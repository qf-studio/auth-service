package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the auth service, parsed from environment variables.
type Config struct {
	App      AppConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Argon2   Argon2Config
	Rate     RateLimitConfig
	TLS      TLSConfig
	CORS     CORSConfig
}

// AppConfig holds server-level settings.
type AppConfig struct {
	Env        string // "development", "staging", "production"
	PublicPort int
	AdminPort  int
	LogLevel   string
}

// PostgresConfig holds PostgreSQL connection parameters.
type PostgresConfig struct {
	Host     string
	Port     int
	DB       string
	User     string
	Password string
	SSLMode  string
	MaxConns int
}

// DSN returns a PostgreSQL connection string.
func (c PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		c.Host, c.Port, c.DB, c.User, c.Password, c.SSLMode,
	)
}

// RedisConfig holds Redis connection parameters.
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

// Addr returns the host:port string expected by go-redis.
func (c RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// JWTConfig holds JWT signing and token lifetime settings.
type JWTConfig struct {
	PrivateKeyPath  string
	Algorithm       string // "ES256" or "EdDSA"
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	SystemSecrets   []string // Comma-separated in env; newest first for rotation.
}

// Argon2Config holds Argon2id password hashing parameters.
type Argon2Config struct {
	Memory      uint32 // KiB
	Time        uint32 // iterations
	Parallelism uint8
	Pepper      string
}

// RateLimitConfig holds rate limiting parameters.
type RateLimitConfig struct {
	RPS   int
	Burst int
}

// TLSConfig holds TLS settings.
type TLSConfig struct {
	Enabled bool
}

// CORSConfig holds CORS settings.
type CORSConfig struct {
	AllowedOrigins []string
}

// Load parses all required environment variables into a Config struct.
// It fails fast with a descriptive error listing every missing required variable.
func Load() (*Config, error) {
	var missing []string

	requireStr := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			missing = append(missing, key)
		}
		return v
	}

	optStr := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return fallback
	}

	optInt := func(key string, fallback int) (int, error) {
		v := os.Getenv(key)
		if v == "" {
			return fallback, nil
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, fmt.Errorf("%s: invalid integer %q: %w", key, v, err)
		}
		return n, nil
	}

	optBool := func(key string, fallback bool) (bool, error) {
		v := os.Getenv(key)
		if v == "" {
			return fallback, nil
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			return false, fmt.Errorf("%s: invalid boolean %q: %w", key, v, err)
		}
		return b, nil
	}

	// ── App ──
	appEnv := requireStr("APP_ENV")
	logLevel := optStr("LOG_LEVEL", "info")

	publicPort, err := optInt("PUBLIC_PORT", 4000)
	if err != nil {
		return nil, err
	}
	adminPort, err := optInt("ADMIN_PORT", 4001)
	if err != nil {
		return nil, err
	}

	// ── Postgres ──
	pgHost := requireStr("POSTGRES_HOST")
	pgDB := requireStr("POSTGRES_DB")
	pgUser := requireStr("POSTGRES_USER")
	pgPassword := requireStr("POSTGRES_PASSWORD")
	pgSSLMode := optStr("POSTGRES_SSLMODE", "disable")

	pgPort, err := optInt("POSTGRES_PORT", 5432)
	if err != nil {
		return nil, err
	}
	pgMaxConns, err := optInt("POSTGRES_MAX_CONNS", 10)
	if err != nil {
		return nil, err
	}

	// ── Redis ──
	redisHost := requireStr("REDIS_HOST")
	redisPassword := optStr("REDIS_PASSWORD", "")

	redisPort, err := optInt("REDIS_PORT", 6379)
	if err != nil {
		return nil, err
	}
	redisDB, err := optInt("REDIS_DB", 0)
	if err != nil {
		return nil, err
	}

	// ── JWT ──
	jwtKeyPath := requireStr("JWT_PRIVATE_KEY_PATH")
	jwtAlg := optStr("JWT_ALGORITHM", "ES256")

	accessTTLStr := optStr("ACCESS_TOKEN_TTL", "15m")
	accessTTL, err := parseDuration(accessTTLStr)
	if err != nil {
		return nil, fmt.Errorf("ACCESS_TOKEN_TTL: %w", err)
	}

	refreshTTLStr := optStr("REFRESH_TOKEN_TTL", "7d")
	refreshTTL, err := parseDuration(refreshTTLStr)
	if err != nil {
		return nil, fmt.Errorf("REFRESH_TOKEN_TTL: %w", err)
	}

	secretsRaw := requireStr("SYSTEM_SECRETS")
	var secrets []string
	if secretsRaw != "" {
		for _, s := range strings.Split(secretsRaw, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				secrets = append(secrets, s)
			}
		}
	}

	// ── Argon2 ──
	pepper := requireStr("PASSWORD_PEPPER")

	argonMem, err := optInt("ARGON2_MEMORY", 19456)
	if err != nil {
		return nil, err
	}
	argonTime, err := optInt("ARGON2_TIME", 2)
	if err != nil {
		return nil, err
	}
	argonPar, err := optInt("ARGON2_PARALLELISM", 1)
	if err != nil {
		return nil, err
	}

	// ── Rate Limiting ──
	rps, err := optInt("RATE_LIMIT_RPS", 50)
	if err != nil {
		return nil, err
	}
	burst, err := optInt("RATE_LIMIT_BURST", 100)
	if err != nil {
		return nil, err
	}

	// ── TLS ──
	tlsEnabled, err := optBool("TLS_ENABLED", false)
	if err != nil {
		return nil, err
	}

	// ── CORS ──
	corsRaw := requireStr("CORS_ALLOWED_ORIGINS")
	var origins []string
	if corsRaw != "" {
		for _, o := range strings.Split(corsRaw, ",") {
			o = strings.TrimSpace(o)
			if o != "" {
				origins = append(origins, o)
			}
		}
	}

	// ── Fail fast on missing required vars ──
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	// ── Validate JWT algorithm ──
	if jwtAlg != "ES256" && jwtAlg != "EdDSA" {
		return nil, fmt.Errorf("JWT_ALGORITHM: unsupported algorithm %q (must be ES256 or EdDSA)", jwtAlg)
	}

	// ── Validate APP_ENV ──
	switch appEnv {
	case "development", "staging", "production":
	default:
		return nil, fmt.Errorf("APP_ENV: unsupported value %q (must be development, staging, or production)", appEnv)
	}

	return &Config{
		App: AppConfig{
			Env:        appEnv,
			PublicPort: publicPort,
			AdminPort:  adminPort,
			LogLevel:   logLevel,
		},
		Postgres: PostgresConfig{
			Host:     pgHost,
			Port:     pgPort,
			DB:       pgDB,
			User:     pgUser,
			Password: pgPassword,
			SSLMode:  pgSSLMode,
			MaxConns: pgMaxConns,
		},
		Redis: RedisConfig{
			Host:     redisHost,
			Port:     redisPort,
			Password: redisPassword,
			DB:       redisDB,
		},
		JWT: JWTConfig{
			PrivateKeyPath:  jwtKeyPath,
			Algorithm:       jwtAlg,
			AccessTokenTTL:  accessTTL,
			RefreshTokenTTL: refreshTTL,
			SystemSecrets:   secrets,
		},
		Argon2: Argon2Config{
			Memory:      uint32(argonMem),
			Time:        uint32(argonTime),
			Parallelism: uint8(argonPar),
			Pepper:      pepper,
		},
		Rate: RateLimitConfig{
			RPS:   rps,
			Burst: burst,
		},
		TLS: TLSConfig{
			Enabled: tlsEnabled,
		},
		CORS: CORSConfig{
			AllowedOrigins: origins,
		},
	}, nil
}

// parseDuration extends time.ParseDuration to support "d" (days) suffix.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		daysStr := strings.TrimSuffix(s, "d")
		days, err := strconv.Atoi(daysStr)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q: %w", s, err)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
