//go:build integration

package testutil

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/api"
)

// Default fixture values aligned with NIST password policy (15-char minimum).
const (
	DefaultTestEmail    = "testuser@example.com"
	DefaultTestPassword = "securepassword!12345" // 20 chars, meets NIST minimum
	DefaultTestName     = "Test User"
	DefaultTestUserID   = "usr_test_00000001"

	DefaultClientID     = "client_test_00000001"
	DefaultClientSecret = "qf_cs_test_secret_value"
	DefaultClientName   = "Test Client"

	DefaultAccessToken  = "qf_at_test_access_token"
	DefaultRefreshToken = "qf_rt_test_refresh_token"
)

// FixtureOption allows customising fixture values.
type FixtureOption func(*fixtureConfig)

type fixtureConfig struct {
	email    string
	name     string
	password string
	userID   string
}

func defaultFixtureConfig() *fixtureConfig {
	return &fixtureConfig{
		email:    DefaultTestEmail,
		name:     DefaultTestName,
		password: DefaultTestPassword,
		userID:   DefaultTestUserID,
	}
}

// WithEmail overrides the default test email.
func WithEmail(email string) FixtureOption {
	return func(c *fixtureConfig) { c.email = email }
}

// WithName overrides the default test name.
func WithName(name string) FixtureOption {
	return func(c *fixtureConfig) { c.name = name }
}

// WithUserID overrides the default test user ID.
func WithUserID(id string) FixtureOption {
	return func(c *fixtureConfig) { c.userID = id }
}

// CreateTestUser inserts a user row directly via SQL and returns a UserInfo.
// If the users table does not exist yet (upstream migrations not merged), it returns
// a synthetic UserInfo without touching the database.
func CreateTestUser(ctx context.Context, pool *pgxpool.Pool, opts ...FixtureOption) (*api.UserInfo, error) {
	cfg := defaultFixtureConfig()
	for _, o := range opts {
		o(cfg)
	}

	if !tableExists(ctx, pool, "users") {
		// Upstream schema not available — return synthetic fixture.
		return &api.UserInfo{
			ID:    cfg.userID,
			Email: cfg.email,
			Name:  cfg.name,
		}, nil
	}

	var id string
	err := pool.QueryRow(ctx,
		`INSERT INTO users (id, email, password_hash, name)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name
		 RETURNING id`,
		cfg.userID, cfg.email, "placeholder_hash", cfg.name,
	).Scan(&id)
	if err != nil {
		return nil, fmt.Errorf("create test user: %w", err)
	}

	return &api.UserInfo{
		ID:    id,
		Email: cfg.email,
		Name:  cfg.name,
	}, nil
}

// ClientFixture holds test OAuth2 client data.
type ClientFixture struct {
	ID     string
	Secret string
	Name   string
}

// CreateTestClient inserts a client row and returns fixture data.
// Falls back to a synthetic fixture if the clients table doesn't exist.
func CreateTestClient(ctx context.Context, pool *pgxpool.Pool) (*ClientFixture, error) {
	if !tableExists(ctx, pool, "clients") {
		return &ClientFixture{
			ID:     DefaultClientID,
			Secret: DefaultClientSecret,
			Name:   DefaultClientName,
		}, nil
	}

	_, err := pool.Exec(ctx,
		`INSERT INTO clients (id, secret_hash, name, grant_types)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (id) DO NOTHING`,
		DefaultClientID, "placeholder_hash", DefaultClientName, "client_credentials",
	)
	if err != nil {
		return nil, fmt.Errorf("create test client: %w", err)
	}

	return &ClientFixture{
		ID:     DefaultClientID,
		Secret: DefaultClientSecret,
		Name:   DefaultClientName,
	}, nil
}

// TokenPairFixture holds a test access/refresh token pair.
type TokenPairFixture struct {
	AccessToken  string
	RefreshToken string
	UserID       string
}

// CreateTestTokenPair returns a synthetic token pair fixture.
// When token storage tables exist upstream, this will insert real rows.
func CreateTestTokenPair(ctx context.Context, pool *pgxpool.Pool, userID string) (*TokenPairFixture, error) {
	if userID == "" {
		userID = DefaultTestUserID
	}

	return &TokenPairFixture{
		AccessToken:  DefaultAccessToken,
		RefreshToken: DefaultRefreshToken,
		UserID:       userID,
	}, nil
}

// NewTestAuthResult creates an api.AuthResult with default test values.
func NewTestAuthResult() *api.AuthResult {
	return &api.AuthResult{
		AccessToken:  DefaultAccessToken,
		RefreshToken: DefaultRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}
}

// NewTestUserInfo creates an api.UserInfo with default test values, overridable via options.
func NewTestUserInfo(opts ...FixtureOption) *api.UserInfo {
	cfg := defaultFixtureConfig()
	for _, o := range opts {
		o(cfg)
	}
	return &api.UserInfo{
		ID:    cfg.userID,
		Email: cfg.email,
		Name:  cfg.name,
	}
}

// tableExists checks if a table exists in the public schema.
func tableExists(ctx context.Context, pool *pgxpool.Pool, table string) bool {
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tablename = $1
		)`, table,
	).Scan(&exists)
	return err == nil && exists
}
