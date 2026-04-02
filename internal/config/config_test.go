package config

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// requiredEnv returns a map of all required env vars with valid values.
func requiredEnv() map[string]string {
	return map[string]string{
		"APP_ENV":              "production",
		"POSTGRES_HOST":        "localhost",
		"POSTGRES_DB":          "auth_test",
		"POSTGRES_USER":        "testuser",
		"POSTGRES_PASSWORD":    "testpass",
		"REDIS_HOST":           "localhost",
		"JWT_PRIVATE_KEY_PATH": "/tmp/key.pem",
		"SYSTEM_SECRETS":       "secret1,secret2",
		"PASSWORD_PEPPER":      "peppercorn",
		"CORS_ALLOWED_ORIGINS": "https://example.com",
	}
}

// setEnv sets all given env vars and returns a cleanup function.
func setEnv(t *testing.T, vars map[string]string) {
	t.Helper()
	for k, v := range vars {
		t.Setenv(k, v)
	}
}

func TestLoad_AllDefaults(t *testing.T) {
	setEnv(t, requiredEnv())

	cfg, err := Load()
	require.NoError(t, err)

	// App defaults
	assert.Equal(t, "production", cfg.App.Env)
	assert.Equal(t, 4000, cfg.App.PublicPort)
	assert.Equal(t, 4001, cfg.App.AdminPort)
	assert.Equal(t, "info", cfg.App.LogLevel)

	// Postgres defaults
	assert.Equal(t, "localhost", cfg.Postgres.Host)
	assert.Equal(t, 5432, cfg.Postgres.Port)
	assert.Equal(t, "auth_test", cfg.Postgres.DB)
	assert.Equal(t, "testuser", cfg.Postgres.User)
	assert.Equal(t, "testpass", cfg.Postgres.Password)
	assert.Equal(t, "disable", cfg.Postgres.SSLMode)
	assert.Equal(t, 10, cfg.Postgres.MaxConns)

	// Redis defaults
	assert.Equal(t, "localhost", cfg.Redis.Host)
	assert.Equal(t, 6379, cfg.Redis.Port)
	assert.Equal(t, "", cfg.Redis.Password)
	assert.Equal(t, 0, cfg.Redis.DB)

	// JWT defaults
	assert.Equal(t, "/tmp/key.pem", cfg.JWT.PrivateKeyPath)
	assert.Equal(t, "ES256", cfg.JWT.Algorithm)
	assert.Equal(t, 15*time.Minute, cfg.JWT.AccessTokenTTL)
	assert.Equal(t, 7*24*time.Hour, cfg.JWT.RefreshTokenTTL)
	assert.Equal(t, []string{"secret1", "secret2"}, cfg.JWT.SystemSecrets)

	// Argon2 defaults
	assert.Equal(t, uint32(19456), cfg.Argon2.Memory)
	assert.Equal(t, uint32(2), cfg.Argon2.Time)
	assert.Equal(t, uint8(1), cfg.Argon2.Parallelism)
	assert.Equal(t, "peppercorn", cfg.Argon2.Pepper)

	// Rate limit defaults
	assert.Equal(t, 50, cfg.Rate.RPS)
	assert.Equal(t, 100, cfg.Rate.Burst)

	// TLS default
	assert.False(t, cfg.TLS.Enabled)

	// CORS
	assert.Equal(t, []string{"https://example.com"}, cfg.CORS.AllowedOrigins)
}

func TestLoad_CustomValues(t *testing.T) {
	env := requiredEnv()
	env["PUBLIC_PORT"] = "8080"
	env["ADMIN_PORT"] = "8081"
	env["LOG_LEVEL"] = "debug"
	env["POSTGRES_PORT"] = "5433"
	env["POSTGRES_SSLMODE"] = "require"
	env["POSTGRES_MAX_CONNS"] = "25"
	env["REDIS_PORT"] = "6380"
	env["REDIS_PASSWORD"] = "redispass"
	env["REDIS_DB"] = "2"
	env["JWT_ALGORITHM"] = "EdDSA"
	env["ACCESS_TOKEN_TTL"] = "30m"
	env["REFRESH_TOKEN_TTL"] = "14d"
	env["ARGON2_MEMORY"] = "32768"
	env["ARGON2_TIME"] = "3"
	env["ARGON2_PARALLELISM"] = "2"
	env["RATE_LIMIT_RPS"] = "100"
	env["RATE_LIMIT_BURST"] = "200"
	env["TLS_ENABLED"] = "true"
	env["CORS_ALLOWED_ORIGINS"] = "https://a.com, https://b.com"
	env["APP_ENV"] = "staging"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "staging", cfg.App.Env)
	assert.Equal(t, 8080, cfg.App.PublicPort)
	assert.Equal(t, 8081, cfg.App.AdminPort)
	assert.Equal(t, "debug", cfg.App.LogLevel)

	assert.Equal(t, 5433, cfg.Postgres.Port)
	assert.Equal(t, "require", cfg.Postgres.SSLMode)
	assert.Equal(t, 25, cfg.Postgres.MaxConns)

	assert.Equal(t, 6380, cfg.Redis.Port)
	assert.Equal(t, "redispass", cfg.Redis.Password)
	assert.Equal(t, 2, cfg.Redis.DB)

	assert.Equal(t, "EdDSA", cfg.JWT.Algorithm)
	assert.Equal(t, 30*time.Minute, cfg.JWT.AccessTokenTTL)
	assert.Equal(t, 14*24*time.Hour, cfg.JWT.RefreshTokenTTL)

	assert.Equal(t, uint32(32768), cfg.Argon2.Memory)
	assert.Equal(t, uint32(3), cfg.Argon2.Time)
	assert.Equal(t, uint8(2), cfg.Argon2.Parallelism)

	assert.Equal(t, 100, cfg.Rate.RPS)
	assert.Equal(t, 200, cfg.Rate.Burst)

	assert.True(t, cfg.TLS.Enabled)
	assert.Equal(t, []string{"https://a.com", "https://b.com"}, cfg.CORS.AllowedOrigins)
}

func TestLoad_MissingRequired(t *testing.T) {
	// Set nothing — all required vars missing.
	// Clear any env that might leak from the test runner.
	for k := range requiredEnv() {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing required environment variables")
	assert.Contains(t, err.Error(), "APP_ENV")
	assert.Contains(t, err.Error(), "POSTGRES_HOST")
	assert.Contains(t, err.Error(), "REDIS_HOST")
	assert.Contains(t, err.Error(), "JWT_PRIVATE_KEY_PATH")
	assert.Contains(t, err.Error(), "SYSTEM_SECRETS")
	assert.Contains(t, err.Error(), "PASSWORD_PEPPER")
	assert.Contains(t, err.Error(), "CORS_ALLOWED_ORIGINS")
}

func TestLoad_InvalidInteger(t *testing.T) {
	env := requiredEnv()
	env["PUBLIC_PORT"] = "not_a_number"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PUBLIC_PORT")
	assert.Contains(t, err.Error(), "invalid integer")
}

func TestLoad_InvalidBoolean(t *testing.T) {
	env := requiredEnv()
	env["TLS_ENABLED"] = "maybe"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TLS_ENABLED")
	assert.Contains(t, err.Error(), "invalid boolean")
}

func TestLoad_InvalidJWTAlgorithm(t *testing.T) {
	env := requiredEnv()
	env["JWT_ALGORITHM"] = "HS256"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
	assert.Contains(t, err.Error(), "HS256")
}

func TestLoad_InvalidAppEnv(t *testing.T) {
	env := requiredEnv()
	env["APP_ENV"] = "test"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "APP_ENV")
	assert.Contains(t, err.Error(), "unsupported value")
}

func TestLoad_InvalidDuration(t *testing.T) {
	env := requiredEnv()
	env["ACCESS_TOKEN_TTL"] = "forever"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ACCESS_TOKEN_TTL")
}

func TestLoad_InvalidDaysDuration(t *testing.T) {
	env := requiredEnv()
	env["REFRESH_TOKEN_TTL"] = "abcd"
	setEnv(t, env)

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REFRESH_TOKEN_TTL")
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"15m", 15 * time.Minute, false},
		{"1h", time.Hour, false},
		{"7d", 7 * 24 * time.Hour, false},
		{"30d", 30 * 24 * time.Hour, false},
		{"500ms", 500 * time.Millisecond, false},
		{"bad", 0, true},
		{"xd", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			d, err := parseDuration(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, d)
			}
		})
	}
}

func TestPostgresConfig_DSN(t *testing.T) {
	c := PostgresConfig{
		Host:     "db.example.com",
		Port:     5432,
		DB:       "mydb",
		User:     "myuser",
		Password: "mypass",
		SSLMode:  "require",
	}
	expected := "host=db.example.com port=5432 dbname=mydb user=myuser password=mypass sslmode=require"
	assert.Equal(t, expected, c.DSN())
}

func TestRedisConfig_Addr(t *testing.T) {
	c := RedisConfig{Host: "redis.example.com", Port: 6380}
	assert.Equal(t, "redis.example.com:6380", c.Addr())
}

func TestLoad_SystemSecretsTrimsWhitespace(t *testing.T) {
	env := requiredEnv()
	env["SYSTEM_SECRETS"] = " secret1 , secret2 , secret3 "
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"secret1", "secret2", "secret3"}, cfg.JWT.SystemSecrets)
}

func TestLoad_CORSMultipleOrigins(t *testing.T) {
	env := requiredEnv()
	env["CORS_ALLOWED_ORIGINS"] = "https://a.com,https://b.com,https://c.com"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, []string{"https://a.com", "https://b.com", "https://c.com"}, cfg.CORS.AllowedOrigins)
}

func TestLoad_DevelopmentEnv(t *testing.T) {
	env := requiredEnv()
	env["APP_ENV"] = "development"
	setEnv(t, env)

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "development", cfg.App.Env)
}
