package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Obviously fake values; long enough to satisfy MinSecretBytes.
const (
	fakeSecretA = "0123456789abcdef0123456789abcdef"
	fakeSecretB = "fedcba9876543210fedcba9876543210"
)

// compliantConfig returns a production Config that violates no guardrail.
func compliantConfig() *Config {
	return &Config{
		App:      AppConfig{Env: "production"},
		Postgres: PostgresConfig{SSLMode: "require"},
		Redis:    RedisConfig{Password: "fake-redis-password", TLS: true},
		JWT:      JWTConfig{SystemSecrets: []string{fakeSecretA, fakeSecretB}},
		Argon2:   Argon2Config{Pepper: fakeSecretA},
		Email:    EmailConfig{Enabled: true},
	}
}

func TestValidate_Compliant(t *testing.T) {
	for _, strict := range []bool{false, true} {
		cfg := compliantConfig()
		cfg.App.Strict = strict
		warnings, err := cfg.Validate()
		require.NoError(t, err)
		assert.Empty(t, warnings)
	}
}

func TestValidate_Rules(t *testing.T) {
	rules := []struct {
		name   string
		mutate func(*Config)
		want   string // substring of the violation message
	}{
		{"sslmode disable", func(c *Config) { c.Postgres.SSLMode = "disable" }, "POSTGRES_SSLMODE"},
		{"sslmode prefer", func(c *Config) { c.Postgres.SSLMode = "prefer" }, "POSTGRES_SSLMODE"},
		{"sslmode empty", func(c *Config) { c.Postgres.SSLMode = "" }, "POSTGRES_SSLMODE"},
		{"redis password unset", func(c *Config) { c.Redis.Password = "" }, "REDIS_PASSWORD"},
		{"redis tls off", func(c *Config) { c.Redis.TLS = false }, "REDIS_TLS"},
		{"short pepper", func(c *Config) { c.Argon2.Pepper = "peppercorn" }, "PASSWORD_PEPPER: shorter than 32"},
		{"placeholder pepper", func(c *Config) { c.Argon2.Pepper = "change-me-" + fakeSecretA }, "PASSWORD_PEPPER: is a placeholder"},
		{"placeholder pepper upper/underscore", func(c *Config) { c.Argon2.Pepper = "CHANGE_ME_" + fakeSecretA }, "PASSWORD_PEPPER: is a placeholder"},
		{"short system secret", func(c *Config) { c.JWT.SystemSecrets = []string{fakeSecretA, "short"} }, "SYSTEM_SECRETS: entry 2: shorter than 32"},
		{"placeholder system secret", func(c *Config) { c.JWT.SystemSecrets = []string{"change-me-" + fakeSecretA} }, "SYSTEM_SECRETS: entry 1: is a placeholder"},
		{"email disabled", func(c *Config) { c.Email.Enabled = false }, "EMAIL_ENABLED"},
	}

	for _, r := range rules {
		t.Run(r.name+"/strict production errors", func(t *testing.T) {
			cfg := compliantConfig()
			cfg.App.Strict = true
			r.mutate(cfg)

			warnings, err := cfg.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), r.want)
			assert.Empty(t, warnings)
		})

		t.Run(r.name+"/non-strict production warns", func(t *testing.T) {
			cfg := compliantConfig()
			r.mutate(cfg)

			warnings, err := cfg.Validate()
			require.NoError(t, err)
			require.Len(t, warnings, 1, "exactly one warning per violated rule")
			assert.Contains(t, warnings[0], r.want)
		})

		for _, env := range []string{"development", "staging"} {
			for _, strict := range []bool{false, true} {
				name := r.name + "/" + env + "/warns"
				if strict {
					name += " even when strict"
				}
				t.Run(name, func(t *testing.T) {
					cfg := compliantConfig()
					cfg.App.Env = env
					cfg.App.Strict = strict
					r.mutate(cfg)

					warnings, err := cfg.Validate()
					require.NoError(t, err)
					require.Len(t, warnings, 1)
					assert.Contains(t, warnings[0], r.want)
				})
			}
		}
	}
}

func TestValidate_AcceptsAllSecureSSLModes(t *testing.T) {
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		cfg := compliantConfig()
		cfg.App.Strict = true
		cfg.Postgres.SSLMode = mode
		_, err := cfg.Validate()
		require.NoError(t, err, mode)
	}
}

func TestValidate_ReportsEveryViolation(t *testing.T) {
	cfg := &Config{
		App:      AppConfig{Env: "production", Strict: true},
		Postgres: PostgresConfig{SSLMode: "disable"},
		JWT:      JWTConfig{SystemSecrets: []string{"short"}},
		Argon2:   Argon2Config{Pepper: "short"},
	}
	_, err := cfg.Validate()
	require.Error(t, err)
	for _, want := range []string{"POSTGRES_SSLMODE", "REDIS_PASSWORD", "REDIS_TLS", "PASSWORD_PEPPER", "SYSTEM_SECRETS", "EMAIL_ENABLED"} {
		assert.Contains(t, err.Error(), want)
	}

	cfg.App.Strict = false
	warnings, err := cfg.Validate()
	require.NoError(t, err)
	assert.Len(t, warnings, 6)
}

func TestValidate_NeverEchoesSecretValues(t *testing.T) {
	cfg := compliantConfig()
	cfg.App.Strict = true
	cfg.Argon2.Pepper = "change-me-super-secret-pepper-value"
	cfg.JWT.SystemSecrets = []string{"change-me-super-secret-system-value"}
	cfg.Redis.Password = ""

	_, err := cfg.Validate()
	require.Error(t, err)
	assert.False(t, strings.Contains(err.Error(), "super-secret"))
}
