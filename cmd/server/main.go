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

	"github.com/gin-gonic/gin"
	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/httpserver"
	"github.com/qf-studio/auth-service/internal/logger"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func main() {
	// ── Logger — always first so subsequent errors are structured ──────────
	log := logger.MustNew("info")
	defer func() { _ = log.Sync() }()

	// ── Config ────────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("config load failed", zap.Error(err))
	}

	// Reinitialise logger at the configured log level.
	log, err = logger.New(cfg.App.LogLevel)
	if err != nil {
		log.Fatal("logger reinit failed", zap.Error(err))
	}

	if cfg.App.Env != "development" {
		gin.SetMode(gin.ReleaseMode)
	}

	// ── Redis ─────────────────────────────────────────────────────────────
	redisClient, err := storage.NewRedisClient(cfg.Redis.Addr(), cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		log.Fatal("redis connection failed", zap.Error(err))
	}
	defer func() { _ = redisClient.Close() }()

	// ── HTTP servers ──────────────────────────────────────────────────────
	publicRouter := api.NewPublicRouter(&api.Services{}, nil)
	adminRouter := adminGinEngine()

	publicSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.App.PublicPort),
		Handler: publicRouter,
	}
	adminSrv := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.App.AdminPort),
		Handler: adminRouter,
	}

	// Closers are released in order after HTTP drains: Redis first.
	// Decision: Redis is listed before any future DB closer so that
	// token-revocation lookups during drain can still reach the cache.
	closers := []httpserver.Closer{
		&redisCloser{client: redisClient},
	}

	srv := httpserver.New(log, []*http.Server{publicSrv, adminSrv}, closers)
	if _, err := srv.Start(); err != nil {
		log.Fatal("server start failed", zap.Error(err))
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
	// defer redisClient.Close() above runs last (logger.Sync already deferred).
	srv.Shutdown(ctx)

	log.Info("auth service stopped")
	// Deferred logger.Sync() and redisClient.Close() execute here.
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

func (r *redisCloser) Name() string  { return "redis" }
func (r *redisCloser) Close() error  { return r.client.Close() }
