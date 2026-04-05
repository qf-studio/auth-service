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

	"github.com/qf-studio/auth-service/internal/admin"
	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/auth"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/dpop"
	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/hibp"
	"github.com/qf-studio/auth-service/internal/httpserver"
	"github.com/qf-studio/auth-service/internal/logger"
	"github.com/qf-studio/auth-service/internal/metrics"
	"github.com/qf-studio/auth-service/internal/middleware"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/session"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/token"
)

func main() {
	// Load config first so we can initialize the logger at the correct level.
	cfg, err := config.Load()
	if err != nil {
		panic(fmt.Sprintf("config load failed: %v", err))
	}

	if err := logger.Init(cfg.App.Env); err != nil {
		panic(fmt.Sprintf("logger init failed: %v", err))
	}
	log := logger.GetLogger()

	if err := run(log, cfg); err != nil {
		log.Fatal("service failed", zap.Error(err))
	}
}

func run(log *zap.Logger, cfg *config.Config) error {
	defer func() { _ = log.Sync() }()

	if cfg.App.Env != "development" {
		gin.SetMode(gin.ReleaseMode)
	}

	// ── Redis ─────────────────────────────────────────────────────────────
	redisClient, err := storage.NewRedisClient(cfg.Redis.Addr(), cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		return fmt.Errorf("redis connection failed: %w", err)
	}
	defer func() { _ = redisClient.Close() }()

	// ── PostgreSQL ────────────────────────────────────────────────────────
	pgPool, err := storage.NewPostgresPool(cfg.Postgres.DSN(), cfg.Postgres.MaxConns)
	if err != nil {
		return fmt.Errorf("postgres connection failed: %w", err)
	}
	defer pgPool.Close()

	// ── Repositories ─────────────────────────────────────────────────────
	userRepo := storage.NewPostgresUserRepository(pgPool)
	refreshTokenRepo := storage.NewPostgresRefreshTokenRepository(pgPool)

	// ── Audit ─────────────────────────────────────────────────────────────
	auditSvc := audit.NewService(log, 1024)

	// ── Services ─────────────────────────────────────────────────────────
	hasher := password.New([]byte(cfg.Argon2.Pepper))
	tokenSvc, err := token.NewService(cfg.JWT, redisClient, log, auditSvc)
	if err != nil {
		return fmt.Errorf("token service init failed: %w", err)
	}
	hibpClient := hibp.NewClient(http.DefaultClient)
	authSvc := auth.NewService(redisClient, log, auditSvc, userRepo, refreshTokenRepo, tokenSvc, hasher, hibpClient)

	// ── Session ──────────────────────────────────────────────────────────
	sessionStore := session.NewMemoryStore()
	sessionSvc := session.NewService(sessionStore)

	// ── DPoP ─────────────────────────────────────────────────────────────
	dpopSvc := dpop.NewService(cfg.DPoP, redisClient, log)
	var dpopAPISvc api.DPoPService
	if cfg.DPoP.Enabled {
		dpopAPISvc = dpop.NewAPIAdapter(dpopSvc)
		log.Info("DPoP proof-of-possession enabled",
			zap.Duration("nonce_ttl", cfg.DPoP.NonceTTL),
			zap.Duration("jti_window", cfg.DPoP.JTIWindow),
		)
	}

	services := &api.Services{
		Auth:    authSvc,
		Token:   tokenSvc,
		Session: sessionSvc,
		DPoP:    dpopAPISvc,
	}

	// ── Health ─────────────────────────────────────────────────────────────
	healthCheckers := []health.Checker{
		health.NewRedisChecker(redisClient),
	}
	healthSvc := health.NewService(healthCheckers...)

	// ── Metrics ───────────────────────────────────────────────────────────
	metricsCollector := metrics.New()

	// ── Repositories (admin) ─────────────────────────────────────────────
	adminUserRepo := storage.NewPostgresAdminUserRepository(pgPool)
	clientRepo := storage.NewPostgresClientRepository(pgPool)
	apiKeyRepo := storage.NewPostgresAPIKeyRepository(pgPool)

	// ── Admin services ────────────────────────────────────────────────────
	adminUserSvc := admin.NewUserService(adminUserRepo, hasher, log, auditSvc)
	adminClientSvc := admin.NewClientService(clientRepo, hasher, log, auditSvc)
	adminTokenSvc := admin.NewTokenService(tokenSvc, refreshTokenRepo, "auth-service", log, auditSvc)
	adminAPIKeySvc := admin.NewAPIKeyService(apiKeyRepo, hasher, log, auditSvc)

	// ── Middleware ─────────────────────────────────────────────────────────
	rateLimiter := middleware.NewRateLimiter(cfg.Rate)

	var dpopMW gin.HandlerFunc
	if cfg.DPoP.Enabled {
		dpopMW = middleware.DPoPMiddleware(dpop.NewMiddlewareValidator(dpopSvc))
	}

	mw := &api.MiddlewareStack{
		CORS:            middleware.CORS(cfg.CORS),
		CorrelationID:   middleware.CorrelationID(log),
		SecurityHeaders: middleware.SecurityHeaders(),
		RateLimit:       rateLimiter.Handler(),
		RequestSize:     middleware.RequestSize(cfg.RequestLimit),
		APIKey:          middleware.APIKeyMiddleware(adminAPIKeySvc),
		Auth:            middleware.AuthMiddleware(tokenSvc),
		DPoP:            dpopMW,
		Metrics:         metricsCollector.Middleware(),
	}

	adminServices := &api.AdminServices{
		Users:   adminUserSvc,
		Clients: adminClientSvc,
		Tokens:  adminTokenSvc,
		APIKeys: adminAPIKeySvc,
	}

	adminDeps := &api.AdminDeps{
		Health:  healthSvc,
		Metrics: metricsCollector,
	}

	// ── HTTP servers ──────────────────────────────────────────────────────
	publicRouter := api.NewPublicRouter(services, mw, healthSvc)
	adminRouter := api.NewAdminRouter(adminServices, adminDeps)

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
		auditSvc,
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

// redisCloser adapts *redis.Client to the httpserver.Closer interface.
type redisCloser struct {
	client *redis.Client
}

func (r *redisCloser) Name() string { return "redis" }
func (r *redisCloser) Close() error { return r.client.Close() }
