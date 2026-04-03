// Command server is the main entry point for the auth service.
// It bootstraps configuration, dependencies, and dual-port HTTP servers,
// then runs until it receives SIGTERM or SIGINT and shuts down gracefully.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/auth"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/httpserver"
	"github.com/qf-studio/auth-service/internal/logger"
	"github.com/qf-studio/auth-service/internal/middleware"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/token"
)

func main() {
	log := logger.MustNew("info")

	if err := run(log); err != nil {
		log.Fatal("service failed", zap.Error(err))
	}
}

func run(log *zap.Logger) error {
	defer func() { _ = log.Sync() }()

	// ── Config ────────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config load failed: %w", err)
	}

	// Reinitialise logger at the configured log level.
	log, err = logger.New(cfg.App.LogLevel)
	if err != nil {
		return fmt.Errorf("logger reinit failed: %w", err)
	}

	if cfg.App.Env != "development" {
		gin.SetMode(gin.ReleaseMode)
	}

	// ── Redis ─────────────────────────────────────────────────────────────
	redisClient, err := storage.NewRedisClient(cfg.Redis.Addr(), cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}
	defer func() { _ = redisClient.Close() }()

	// ── Services ─────────────────────────────────────────────────────────
	// Auth dependencies (UserRepository, RefreshTokenRepository, TokenProvider,
	// PasswordVerifier) are wired in GH-112 once PostgreSQL repositories and
	// token signing are implemented. Passing nil is safe because the HTTP
	// handlers that call Login/Logout are not yet routed through real backends.
	authSvc := auth.NewService(redisClient, log, nil, nil, nil, nil)
	tokenSvc := token.NewService(log)

	services := &api.Services{
		Auth:  authSvc,
		Token: tokenSvc,
	}

	// ── Middleware ─────────────────────────────────────────────────────────
	rateLimiter := middleware.NewRateLimiter(cfg.Rate)

	mw := &api.MiddlewareStack{
		CORS:            middleware.CORS(cfg.CORS),
		CorrelationID:   middleware.CorrelationID(),
		SecurityHeaders: middleware.SecurityHeaders(),
		RateLimit:       rateLimiter.Handler(),
		RequestSize:     middleware.RequestSize(cfg.RequestLimit),
	}

	// ── HTTP servers ──────────────────────────────────────────────────────
	publicRouter := api.NewPublicRouter(services, mw)
	adminRouter := adminGinEngine()

	publicSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.App.PublicPort),
		Handler:           publicRouter,
		ReadHeaderTimeout: 10 * time.Second,
	}
	adminSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.App.AdminPort),
		Handler:           adminRouter,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Closers are released in order after HTTP drains: Redis first.
	// Decision: Redis is listed before any future DB closer so that
	// token-revocation lookups during drain can still reach the cache.
	closers := []httpserver.Closer{
		&redisCloser{client: redisClient},
	}

	srv := httpserver.New(log, []*http.Server{publicSrv, adminSrv}, closers)
	if _, err := srv.Start(); err != nil {
		return fmt.Errorf("server start failed: %w", err)
	}

	log.Info("auth service started",
		zap.Int("public_port", cfg.App.PublicPort),
		zap.Int("admin_port", cfg.App.AdminPort),
		zap.String("env", cfg.App.Env),
	)

	// ── Block until OS signal ─────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	sig := <-quit
	log.Info("shutdown signal received", zap.String("signal", sig.String()))

	ctx, cancel := context.WithTimeout(context.Background(), httpserver.ShutdownTimeout)
	defer cancel()

	// Shutdown drains HTTP then calls redisCloser.Close().
	srv.Shutdown(ctx)

	log.Info("auth service stopped")
	return nil
}

// adminGinEngine returns a minimal Gin engine for the admin port.
// Full admin routes will be wired up in a later issue.
func adminGinEngine() *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	return r
}

// redisCloser adapts *redis.Client to the httpserver.Closer interface.
type redisCloser struct {
	client *redis.Client
}

func (r *redisCloser) Name() string { return "redis" }
func (r *redisCloser) Close() error { return r.client.Close() }
