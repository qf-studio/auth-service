package config

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Config holds all configuration for the auth service, parsed from environment variables.
type Config struct {
	App          AppConfig
	Postgres     PostgresConfig
	Redis        RedisConfig
	JWT          JWTConfig
	Argon2       Argon2Config
	Rate         RateLimitConfig
	CORS         CORSConfig
	RequestLimit RequestLimitConfig
	Email        EmailConfig
	DPoP         DPoPConfig
	MFA          MFAConfig
	OAuth        OAuthConfig
	OIDC         OIDCConfig
	SAML         SAMLConfig
	Tenant       TenantConfig
	HIBP         HIBPConfig
	Proxy        ProxyConfig
	Admin        AdminConfig
	Audit        AuditConfig
	GRPC         GRPCConfig
}

// gRPC caller-authentication modes (GRPC_AUTH_MODE).
const (
	GRPCAuthOff     = "off"
	GRPCAuthWarn    = "warn"
	GRPCAuthEnforce = "enforce"

	// minGRPCClientTokenBytes is the minimum length of each GRPC_CLIENT_TOKENS entry.
	minGRPCClientTokenBytes = 32
)

// GRPCConfig holds gRPC caller-authentication settings.
type GRPCConfig struct {
	AuthMode     string   // GRPC_AUTH_MODE: "off", "warn" (default), or "enforce"
	ClientTokens []string // GRPC_CLIENT_TOKENS: comma-separated bearer tokens, each >= 32 bytes; required for enforce
}

// TenantConfig holds multi-tenancy resolution settings.
type TenantConfig struct {
	DefaultID      string        // TENANT_DEFAULT_ID: fallback tenant when none resolved
	ResolutionMode string        // TENANT_RESOLUTION_MODE: "subdomain", "header", or "both" (default "both")
	BaseDomain     string        // TENANT_BASE_DOMAIN: base domain for subdomain parsing (e.g. "auth.quantflow.studio")
	CacheTTL       time.Duration // TENANT_CACHE_TTL: how long to cache tenant lookups
}

// SAMLConfig holds SAML Service Provider settings.
type SAMLConfig struct {
	Enabled  bool   // SAML_ENABLED: whether SAML SSO is active
	EntityID string // SAML_ENTITY_ID: the SP entity identifier
	ACSURL   string // SAML_ACS_URL: Assertion Consumer Service URL
	KeyPath  string // SAML_KEY_PATH: path to SP private key file
	CertPath string // SAML_CERT_PATH: path to SP certificate file
}

// OIDCConfig holds OpenID Connect provider settings.
type OIDCConfig struct {
	IssuerURL       string        // OIDC_ISSUER_URL: the issuer identifier (e.g. https://auth.example.com)
	IDTokenTTL      time.Duration // OIDC_ID_TOKEN_TTL: lifetime of ID tokens
	SupportedScopes []string      // OIDC_SUPPORTED_SCOPES: comma-separated OIDC scopes
	LoginUIURL      string        // OIDC_LOGIN_UI_URL: base URL of the external login UI (login_challenge is appended as a query param)
	ConsentUIURL    string        // OIDC_CONSENT_UI_URL: base URL of the external consent UI; defaults to LoginUIURL when unset
}

// OAuthProviderConfig holds credentials and settings for a single OAuth provider.
type OAuthProviderConfig struct {
	ClientID     string // OAUTH_<PROVIDER>_CLIENT_ID
	ClientSecret string // OAUTH_<PROVIDER>_CLIENT_SECRET (Apple: path to .p8 private key)
	RedirectURI  string // OAUTH_<PROVIDER>_REDIRECT_URI
	Enabled      bool   // OAUTH_<PROVIDER>_ENABLED
	TeamID       string // OAUTH_<PROVIDER>_TEAM_ID (Apple only)
	KeyID        string // OAUTH_<PROVIDER>_KEY_ID (Apple only)
}

// OAuthConfig holds OAuth provider configurations.
type OAuthConfig struct {
	Google      OAuthProviderConfig
	GitHub      OAuthProviderConfig
	Apple       OAuthProviderConfig
	StateSecret string // OAUTH_STATE_SECRET: HMAC key for signing state parameters
}

// MFAConfig holds multi-factor authentication settings.
type MFAConfig struct {
	Issuer          string // MFA_ISSUER: issuer name shown in authenticator apps
	Digits          int    // MFA_DIGITS: number of TOTP digits (6 or 8)
	Period          int    // MFA_PERIOD: TOTP period in seconds
	BackupCodeCount int    // MFA_BACKUP_CODE_COUNT: number of backup codes to generate
}

// DPoPConfig holds DPoP (Demonstrating Proof-of-Possession) settings.
type DPoPConfig struct {
	Enabled   bool          // DPOP_ENABLED: whether DPoP proof binding is active
	NonceTTL  time.Duration // DPOP_NONCE_TTL: lifetime of server-issued nonces
	JTIWindow time.Duration // DPOP_JTI_WINDOW: replay window for proof JTI deduplication
}

// HIBPConfig holds HaveIBeenPwned Pwned Passwords API settings.
type HIBPConfig struct {
	APIURL string // HIBP_API_URL: base range-endpoint URL; empty uses internal/hibp's built-in pwnedpasswords.com default
}

// MinAdminTokenBytes is the minimum length of each ADMIN_API_TOKENS value.
const MinAdminTokenBytes = 32

// DefaultAuditRetentionDays is the audit_logs retention when AUDIT_RETENTION_DAYS is unset.
const DefaultAuditRetentionDays = 365

// AuditConfig holds audit log persistence settings.
type AuditConfig struct {
	// RetentionDays: AUDIT_RETENTION_DAYS, audit_logs rows older than this are
	// deleted daily (default 365). 0 keeps rows forever.
	RetentionDays int
}

// AdminConfig holds admin API (:4001) authentication settings.
type AdminConfig struct {
	// APITokens: ADMIN_API_TOKENS, comma-separated static bearer tokens, each
	// at least MinAdminTokenBytes long. Any one of them authenticates a
	// request, so two can be configured at once to rotate. Empty disables
	// every /admin/* route (503 admin_api_disabled) without failing startup.
	APITokens []string
}

// ProxyConfig holds trusted reverse-proxy settings.
type ProxyConfig struct {
	// TrustedCIDRs: TRUSTED_PROXY_CIDRS, comma-separated CIDRs of the reverse
	// proxies / load balancers in front of the service. For requests whose
	// immediate peer address falls within one of these ranges the server:
	//   - derives the client IP (rate limiting, session records) from
	//     X-Forwarded-For, taking the rightmost address outside these ranges;
	//   - honors X-Forwarded-Proto when reconstructing the externally-visible
	//     request URL (DPoP htu matching behind a TLS-terminating AWS ALB).
	// The host is always taken from Request.Host. Empty (the default) trusts
	// nothing — the client IP is the TCP peer and the scheme comes from
	// Request.TLS.
	TrustedCIDRs []*net.IPNet
}

// EmailConfig holds outbound email delivery settings.
type EmailConfig struct {
	ServiceURL           string // EMAIL_SERVICE_URL: base URL of the email-service
	APIKey               string // EMAIL_API_KEY: bearer token for the email-service API
	SenderAddress        string // EMAIL_SENDER_ADDRESS: the From address on outgoing mail
	Enabled              bool   // EMAIL_ENABLED: false → skip delivery (useful in dev/test)
	PasswordResetURLBase string // PASSWORD_RESET_URL_BASE: base URL the reset token is appended to (?token=<token>); required when Enabled
	EmailVerifyURLBase   string // EMAIL_VERIFY_URL_BASE: base URL the verify token is appended to (?token=<token>); required when Enabled

	// EmailChangeConfirmURLBase and EmailChangeRevertURLBase back the
	// email-change confirm/revert links (GH-518). Unlike the fields above,
	// these are optional even when Enabled: leaving them unset lets existing
	// deployments keep booting, but POST /auth/me/email answers 503 until
	// both are configured. A startup warning is logged in that case.
	EmailChangeConfirmURLBase string // EMAIL_CHANGE_CONFIRM_URL_BASE
	EmailChangeRevertURLBase  string // EMAIL_CHANGE_REVERT_URL_BASE
}

// AppConfig holds server-level settings.
type AppConfig struct {
	Env        string // "development", "staging", "production"
	PublicPort int
	AdminPort  int
	GRPCPort   int
	LogLevel   string

	// Strict (CONFIG_STRICT, default false) turns the production guardrails
	// checked by Config.Validate from startup warnings into a startup error.
	Strict bool

	// HTTP server timeouts (HTTP_READ_TIMEOUT, HTTP_WRITE_TIMEOUT,
	// HTTP_IDLE_TIMEOUT) applied to both the public and admin listeners.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
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

// DSN returns a PostgreSQL connection URL. Built with net/url so credentials
// containing spaces, quotes or other reserved characters are escaped instead
// of corrupting (or injecting into) the connection string.
func (c PostgresConfig) DSN() string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(c.User, c.Password),
		Host:     net.JoinHostPort(c.Host, strconv.Itoa(c.Port)),
		Path:     "/" + c.DB,
		RawQuery: url.Values{"sslmode": {c.SSLMode}}.Encode(),
	}
	return u.String()
}

// RedisConfig holds Redis connection parameters.
type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
	TLS      bool // REDIS_TLS: connect over TLS, verifying the server against system roots
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
	Audience        []string // JWT_AUDIENCE: comma-separated aud values for access tokens; empty means no aud claim.
	// AudienceEnforce gates aud validation in ValidateToken (JWT_AUDIENCE_ENFORCE,
	// GH-506). Default false: existing consumers (e.g. Pointer, integrated
	// before per-app audiences existed) keep validating tokens regardless of
	// aud until they confirm their expected audience and flip this on.
	AudienceEnforce bool
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
	RPS                   int
	Burst                 int
	ProgressiveDelayAfter int           // number of failed attempts before progressive delay kicks in
	LockoutDuration       time.Duration // duration to lock out after MaxFailedAttempts
	MaxFailedAttempts     int           // failed attempts before lockout
}

// CORSConfig holds CORS settings.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposeHeaders    []string
	AllowCredentials bool
	MaxAge           time.Duration
}

// RequestLimitConfig holds request size and timeout limits.
type RequestLimitConfig struct {
	MaxBodySize    int64 // bytes
	RequestTimeout time.Duration
}

// loader collects parsing state while reading environment variables.
type loader struct {
	missing []string
}

func (l *loader) requireStr(key string) string {
	v := os.Getenv(key)
	if v == "" {
		l.missing = append(l.missing, key)
	}
	return v
}

func (*loader) optStr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (*loader) optInt(key string, fallback int) (int, error) {
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

// optDuration parses a positive duration (supports the "d" suffix).
func (*loader) optDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := parseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: must be positive, got %q", key, v)
	}
	return d, nil
}

func (*loader) optBool(key string, fallback bool) (bool, error) {
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

// Load parses all required environment variables into a Config struct.
// It fails fast with a descriptive error listing every missing required variable.
func Load() (*Config, error) {
	l := &loader{}

	app, err := loadApp(l)
	if err != nil {
		return nil, err
	}
	pg, err := loadPostgres(l)
	if err != nil {
		return nil, err
	}
	rds, err := loadRedis(l)
	if err != nil {
		return nil, err
	}
	jwt, err := loadJWT(l)
	if err != nil {
		return nil, err
	}
	argon, err := loadArgon2(l)
	if err != nil {
		return nil, err
	}
	rate, err := loadRateLimit(l)
	if err != nil {
		return nil, err
	}
	cors, err := loadCORS(l)
	if err != nil {
		return nil, err
	}
	reqLimit, err := loadRequestLimit(l)
	if err != nil {
		return nil, err
	}
	email, err := loadEmail(l)
	if err != nil {
		return nil, err
	}
	dpop, err := loadDPoP(l)
	if err != nil {
		return nil, err
	}
	mfaCfg, err := loadMFA(l)
	if err != nil {
		return nil, err
	}
	oauthCfg, err := loadOAuth(l)
	if err != nil {
		return nil, err
	}
	oidcCfg, err := loadOIDC(l)
	if err != nil {
		return nil, err
	}
	samlCfg, err := loadSAML(l)
	if err != nil {
		return nil, err
	}
	tenantCfg, err := loadTenant(l)
	if err != nil {
		return nil, err
	}
	hibpCfg := loadHIBP(l)
	proxyCfg, err := loadProxy(l)
	if err != nil {
		return nil, err
	}

	adminCfg, err := loadAdmin(l)
	if err != nil {
		return nil, err
	}

	auditCfg, err := loadAudit(l)
	if err != nil {
		return nil, err
	}

	grpcCfg, err := loadGRPC(l)
	if err != nil {
		return nil, err
	}

	if len(l.missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(l.missing, ", "))
	}

	if app.Env != "development" && app.Env != "staging" && app.Env != "production" {
		return nil, fmt.Errorf("APP_ENV: unsupported value %q (must be development, staging, or production)", app.Env)
	}

	return &Config{
		App:          app,
		Postgres:     pg,
		Redis:        rds,
		JWT:          jwt,
		Argon2:       argon,
		Rate:         rate,
		CORS:         cors,
		RequestLimit: reqLimit,
		Email:        email,
		DPoP:         dpop,
		MFA:          mfaCfg,
		OAuth:        oauthCfg,
		OIDC:         oidcCfg,
		SAML:         samlCfg,
		Tenant:       tenantCfg,
		HIBP:         hibpCfg,
		Proxy:        proxyCfg,
		Admin:        adminCfg,
		Audit:        auditCfg,
		GRPC:         grpcCfg,
	}, nil
}

// loadGRPC reads GRPC_AUTH_MODE and GRPC_CLIENT_TOKENS. It has no required
// fields, so it never contributes to l.missing. Enforce mode without tokens is
// rejected because it would lock out every caller.
func loadGRPC(l *loader) (GRPCConfig, error) {
	mode := strings.ToLower(l.optStr("GRPC_AUTH_MODE", GRPCAuthWarn))
	switch mode {
	case GRPCAuthOff, GRPCAuthWarn, GRPCAuthEnforce:
	default:
		return GRPCConfig{}, fmt.Errorf("GRPC_AUTH_MODE: unsupported value %q (must be off, warn, or enforce)", mode)
	}

	tokens := splitCSV(os.Getenv("GRPC_CLIENT_TOKENS"))
	for i, t := range tokens {
		if len(t) < minGRPCClientTokenBytes {
			return GRPCConfig{}, fmt.Errorf("GRPC_CLIENT_TOKENS: entry %d is shorter than %d bytes", i+1, minGRPCClientTokenBytes)
		}
	}
	if mode == GRPCAuthEnforce && len(tokens) == 0 {
		return GRPCConfig{}, fmt.Errorf("GRPC_CLIENT_TOKENS: at least one token is required when GRPC_AUTH_MODE=enforce")
	}

	return GRPCConfig{AuthMode: mode, ClientTokens: tokens}, nil
}

// loadHIBP reads the optional HIBP range-endpoint override used to redirect
// internal/hibp.Client at a fake server in tests; it has no required fields
// so it never contributes to l.missing.
func loadHIBP(l *loader) HIBPConfig {
	return HIBPConfig{APIURL: l.optStr("HIBP_API_URL", "")}
}

// adminTokenPlaceholderPrefix marks the example values in the .env*.example
// files. Those files are public, so a copied placeholder must not work as a
// credential (compared case-insensitively).
const adminTokenPlaceholderPrefix = "change_me"

// loadAdmin reads ADMIN_API_TOKENS. Errors name the token by position only,
// never by value.
func loadAdmin(l *loader) (AdminConfig, error) {
	tokens := splitCSV(l.optStr("ADMIN_API_TOKENS", ""))
	for i, tok := range tokens {
		if len(tok) < MinAdminTokenBytes {
			return AdminConfig{}, fmt.Errorf("ADMIN_API_TOKENS: token %d is shorter than %d bytes", i+1, MinAdminTokenBytes)
		}
		if strings.HasPrefix(strings.ToLower(tok), adminTokenPlaceholderPrefix) {
			return AdminConfig{}, fmt.Errorf("ADMIN_API_TOKENS: token %d is a placeholder value; generate a random token", i+1)
		}
	}
	return AdminConfig{APITokens: tokens}, nil
}

// loadAudit reads AUDIT_RETENTION_DAYS (0 disables pruning).
func loadAudit(l *loader) (AuditConfig, error) {
	days, err := l.optInt("AUDIT_RETENTION_DAYS", DefaultAuditRetentionDays)
	if err != nil {
		return AuditConfig{}, err
	}
	if days < 0 {
		return AuditConfig{}, fmt.Errorf("AUDIT_RETENTION_DAYS: must be >= 0, got %d", days)
	}
	return AuditConfig{RetentionDays: days}, nil
}

// loadProxy reads TRUSTED_PROXY_CIDRS and parses each entry as a CIDR. It has
// no required fields, so it never contributes to l.missing.
func loadProxy(l *loader) (ProxyConfig, error) {
	raw := l.optStr("TRUSTED_PROXY_CIDRS", "")
	entries := splitCSV(raw)

	cidrs := make([]*net.IPNet, 0, len(entries))
	for _, entry := range entries {
		_, ipNet, err := net.ParseCIDR(entry)
		if err != nil {
			return ProxyConfig{}, fmt.Errorf("TRUSTED_PROXY_CIDRS: invalid CIDR %q: %w", entry, err)
		}
		cidrs = append(cidrs, ipNet)
	}

	return ProxyConfig{TrustedCIDRs: cidrs}, nil
}

func loadApp(l *loader) (AppConfig, error) {
	appEnv := l.requireStr("APP_ENV")
	logLevel := l.optStr("LOG_LEVEL", "info")

	publicPort, err := l.optInt("PUBLIC_PORT", 4000)
	if err != nil {
		return AppConfig{}, err
	}
	adminPort, err := l.optInt("ADMIN_PORT", 4001)
	if err != nil {
		return AppConfig{}, err
	}
	grpcPort, err := l.optInt("GRPC_PORT", 4002)
	if err != nil {
		return AppConfig{}, err
	}

	strict, err := l.optBool("CONFIG_STRICT", false)
	if err != nil {
		return AppConfig{}, err
	}

	readTimeout, err := l.optDuration("HTTP_READ_TIMEOUT", DefaultHTTPReadTimeout)
	if err != nil {
		return AppConfig{}, err
	}
	writeTimeout, err := l.optDuration("HTTP_WRITE_TIMEOUT", DefaultHTTPWriteTimeout)
	if err != nil {
		return AppConfig{}, err
	}
	idleTimeout, err := l.optDuration("HTTP_IDLE_TIMEOUT", DefaultHTTPIdleTimeout)
	if err != nil {
		return AppConfig{}, err
	}

	return AppConfig{
		Env:          appEnv,
		PublicPort:   publicPort,
		AdminPort:    adminPort,
		GRPCPort:     grpcPort,
		LogLevel:     logLevel,
		Strict:       strict,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}, nil
}

func loadPostgres(l *loader) (PostgresConfig, error) {
	pgHost := l.requireStr("POSTGRES_HOST")
	pgDB := l.requireStr("POSTGRES_DB")
	pgUser := l.requireStr("POSTGRES_USER")
	pgPassword := l.requireStr("POSTGRES_PASSWORD")
	pgSSLMode := l.optStr("POSTGRES_SSLMODE", "disable")

	pgPort, err := l.optInt("POSTGRES_PORT", 5432)
	if err != nil {
		return PostgresConfig{}, err
	}
	pgMaxConns, err := l.optInt("POSTGRES_MAX_CONNS", 10)
	if err != nil {
		return PostgresConfig{}, err
	}

	return PostgresConfig{
		Host:     pgHost,
		Port:     pgPort,
		DB:       pgDB,
		User:     pgUser,
		Password: pgPassword,
		SSLMode:  pgSSLMode,
		MaxConns: pgMaxConns,
	}, nil
}

func loadRedis(l *loader) (RedisConfig, error) {
	redisHost := l.requireStr("REDIS_HOST")
	redisPassword := l.optStr("REDIS_PASSWORD", "")

	redisPort, err := l.optInt("REDIS_PORT", 6379)
	if err != nil {
		return RedisConfig{}, err
	}
	redisDB, err := l.optInt("REDIS_DB", 0)
	if err != nil {
		return RedisConfig{}, err
	}
	redisTLS, err := l.optBool("REDIS_TLS", false)
	if err != nil {
		return RedisConfig{}, err
	}

	return RedisConfig{
		Host:     redisHost,
		Port:     redisPort,
		Password: redisPassword,
		DB:       redisDB,
		TLS:      redisTLS,
	}, nil
}

func loadJWT(l *loader) (JWTConfig, error) {
	jwtKeyPath := l.requireStr("JWT_PRIVATE_KEY_PATH")
	jwtAlg := l.optStr("JWT_ALGORITHM", "ES256")

	accessTTLStr := l.optStr("ACCESS_TOKEN_TTL", "15m")
	accessTTL, err := parseDuration(accessTTLStr)
	if err != nil {
		return JWTConfig{}, fmt.Errorf("ACCESS_TOKEN_TTL: %w", err)
	}

	refreshTTLStr := l.optStr("REFRESH_TOKEN_TTL", "7d")
	refreshTTL, err := parseDuration(refreshTTLStr)
	if err != nil {
		return JWTConfig{}, fmt.Errorf("REFRESH_TOKEN_TTL: %w", err)
	}

	secretsRaw := l.requireStr("SYSTEM_SECRETS")
	secrets := splitCSV(secretsRaw)

	audienceRaw := l.optStr("JWT_AUDIENCE", "")
	audience := splitCSV(audienceRaw)

	audienceEnforce, err := l.optBool("JWT_AUDIENCE_ENFORCE", false)
	if err != nil {
		return JWTConfig{}, err
	}

	if jwtAlg != "ES256" && jwtAlg != "EdDSA" {
		return JWTConfig{}, fmt.Errorf("JWT_ALGORITHM: unsupported algorithm %q (must be ES256 or EdDSA)", jwtAlg)
	}

	return JWTConfig{
		PrivateKeyPath:  jwtKeyPath,
		Algorithm:       jwtAlg,
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: refreshTTL,
		SystemSecrets:   secrets,
		Audience:        audience,
		AudienceEnforce: audienceEnforce,
	}, nil
}

func loadArgon2(l *loader) (Argon2Config, error) {
	pepper := l.requireStr("PASSWORD_PEPPER")

	argonMem, err := l.optInt("ARGON2_MEMORY", 19456)
	if err != nil {
		return Argon2Config{}, err
	}
	argonTime, err := l.optInt("ARGON2_TIME", 2)
	if err != nil {
		return Argon2Config{}, err
	}
	argonPar, err := l.optInt("ARGON2_PARALLELISM", 1)
	if err != nil {
		return Argon2Config{}, err
	}

	if argonMem < 0 || argonMem > math.MaxUint32 {
		return Argon2Config{}, fmt.Errorf("ARGON2_MEMORY: value %d out of uint32 range", argonMem)
	}
	if argonTime < 0 || argonTime > math.MaxUint32 {
		return Argon2Config{}, fmt.Errorf("ARGON2_TIME: value %d out of uint32 range", argonTime)
	}
	if argonPar < 0 || argonPar > math.MaxUint8 {
		return Argon2Config{}, fmt.Errorf("ARGON2_PARALLELISM: value %d out of uint8 range", argonPar)
	}

	return Argon2Config{
		Memory:      uint32(argonMem),  //nolint:gosec // bounds checked above
		Time:        uint32(argonTime), //nolint:gosec // bounds checked above
		Parallelism: uint8(argonPar),   //nolint:gosec // bounds checked above
		Pepper:      pepper,
	}, nil
}

func loadRateLimit(l *loader) (RateLimitConfig, error) {
	rps, err := l.optInt("RATE_LIMIT_RPS", 50)
	if err != nil {
		return RateLimitConfig{}, err
	}
	burst, err := l.optInt("RATE_LIMIT_BURST", 100)
	if err != nil {
		return RateLimitConfig{}, err
	}
	progressiveDelayAfter, err := l.optInt("RATE_LIMIT_PROGRESSIVE_DELAY_AFTER", 5)
	if err != nil {
		return RateLimitConfig{}, err
	}
	maxFailedAttempts, err := l.optInt("RATE_LIMIT_MAX_FAILED_ATTEMPTS", 10)
	if err != nil {
		return RateLimitConfig{}, err
	}

	lockoutDurStr := l.optStr("RATE_LIMIT_LOCKOUT_DURATION", "15m")
	lockoutDur, err := parseDuration(lockoutDurStr)
	if err != nil {
		return RateLimitConfig{}, fmt.Errorf("RATE_LIMIT_LOCKOUT_DURATION: %w", err)
	}

	return RateLimitConfig{
		RPS:                   rps,
		Burst:                 burst,
		ProgressiveDelayAfter: progressiveDelayAfter,
		LockoutDuration:       lockoutDur,
		MaxFailedAttempts:     maxFailedAttempts,
	}, nil
}

func loadCORS(l *loader) (CORSConfig, error) {
	corsRaw := l.requireStr("CORS_ALLOWED_ORIGINS")
	allowedMethods := l.optStr("CORS_ALLOWED_METHODS", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
	allowedHeaders := l.optStr("CORS_ALLOWED_HEADERS", "Authorization,Content-Type,X-Request-ID")
	exposeHeaders := l.optStr("CORS_EXPOSE_HEADERS", "X-Request-ID")

	allowCredentials, err := l.optBool("CORS_ALLOW_CREDENTIALS", false)
	if err != nil {
		return CORSConfig{}, err
	}

	maxAgeStr := l.optStr("CORS_MAX_AGE", "12h")
	maxAge, err := parseDuration(maxAgeStr)
	if err != nil {
		return CORSConfig{}, fmt.Errorf("CORS_MAX_AGE: %w", err)
	}

	origins := splitCSV(corsRaw)
	// The CORS middleware reflects the request Origin, so a wildcard plus
	// credentials would let any site make credentialed cross-origin calls.
	if allowCredentials && slices.Contains(origins, "*") {
		return CORSConfig{}, errors.New("CORS_ALLOW_CREDENTIALS=true cannot be combined with CORS_ALLOWED_ORIGINS=*; list explicit origins")
	}

	return CORSConfig{
		AllowedOrigins:   origins,
		AllowedMethods:   splitCSV(allowedMethods),
		AllowedHeaders:   splitCSV(allowedHeaders),
		ExposeHeaders:    splitCSV(exposeHeaders),
		AllowCredentials: allowCredentials,
		MaxAge:           maxAge,
	}, nil
}

func loadRequestLimit(l *loader) (RequestLimitConfig, error) {
	maxBodySize, err := l.optInt("REQUEST_MAX_BODY_SIZE", 1<<20) // 1 MiB default
	if err != nil {
		return RequestLimitConfig{}, err
	}

	requestTimeoutStr := l.optStr("REQUEST_TIMEOUT", "30s")
	requestTimeout, err := parseDuration(requestTimeoutStr)
	if err != nil {
		return RequestLimitConfig{}, fmt.Errorf("REQUEST_TIMEOUT: %w", err)
	}

	return RequestLimitConfig{
		MaxBodySize:    int64(maxBodySize), //nolint:gosec // non-negative validated by optInt
		RequestTimeout: requestTimeout,
	}, nil
}

func loadEmail(l *loader) (EmailConfig, error) {
	enabled, err := l.optBool("EMAIL_ENABLED", false)
	if err != nil {
		return EmailConfig{}, err
	}

	// When email delivery is enabled, every downstream field is required so
	// startup fails fast instead of silently dropping password-reset or
	// verification emails.
	var serviceURL, apiKey, senderAddress, resetURLBase, verifyURLBase string
	if enabled {
		serviceURL = l.requireStr("EMAIL_SERVICE_URL")
		apiKey = l.requireStr("EMAIL_API_KEY")
		senderAddress = l.requireStr("EMAIL_SENDER_ADDRESS")
		resetURLBase = l.requireStr("PASSWORD_RESET_URL_BASE")
		verifyURLBase = l.requireStr("EMAIL_VERIFY_URL_BASE")
	} else {
		serviceURL = l.optStr("EMAIL_SERVICE_URL", "")
		apiKey = l.optStr("EMAIL_API_KEY", "")
		senderAddress = l.optStr("EMAIL_SENDER_ADDRESS", "")
		resetURLBase = l.optStr("PASSWORD_RESET_URL_BASE", "")
		verifyURLBase = l.optStr("EMAIL_VERIFY_URL_BASE", "")
	}

	// EmailChangeConfirmURLBase/EmailChangeRevertURLBase are optional even
	// when Enabled, unlike the fields above — see EmailConfig's doc comment.
	changeConfirmURLBase := l.optStr("EMAIL_CHANGE_CONFIRM_URL_BASE", "")
	changeRevertURLBase := l.optStr("EMAIL_CHANGE_REVERT_URL_BASE", "")

	return EmailConfig{
		ServiceURL:                serviceURL,
		APIKey:                    apiKey,
		SenderAddress:             senderAddress,
		Enabled:                   enabled,
		PasswordResetURLBase:      resetURLBase,
		EmailVerifyURLBase:        verifyURLBase,
		EmailChangeConfirmURLBase: changeConfirmURLBase,
		EmailChangeRevertURLBase:  changeRevertURLBase,
	}, nil
}

func loadDPoP(l *loader) (DPoPConfig, error) {
	enabled, err := l.optBool("DPOP_ENABLED", false)
	if err != nil {
		return DPoPConfig{}, err
	}

	nonceTTLStr := l.optStr("DPOP_NONCE_TTL", "5m")
	nonceTTL, err := parseDuration(nonceTTLStr)
	if err != nil {
		return DPoPConfig{}, fmt.Errorf("DPOP_NONCE_TTL: %w", err)
	}

	jtiWindowStr := l.optStr("DPOP_JTI_WINDOW", "1m")
	jtiWindow, err := parseDuration(jtiWindowStr)
	if err != nil {
		return DPoPConfig{}, fmt.Errorf("DPOP_JTI_WINDOW: %w", err)
	}

	return DPoPConfig{
		Enabled:   enabled,
		NonceTTL:  nonceTTL,
		JTIWindow: jtiWindow,
	}, nil
}

func loadMFA(l *loader) (MFAConfig, error) {
	issuer := l.optStr("MFA_ISSUER", "QuantFlow Studio")

	digits, err := l.optInt("MFA_DIGITS", 6)
	if err != nil {
		return MFAConfig{}, err
	}
	if digits != 6 && digits != 8 {
		return MFAConfig{}, fmt.Errorf("MFA_DIGITS: must be 6 or 8, got %d", digits)
	}

	period, err := l.optInt("MFA_PERIOD", 30)
	if err != nil {
		return MFAConfig{}, err
	}

	backupCount, err := l.optInt("MFA_BACKUP_CODE_COUNT", 10)
	if err != nil {
		return MFAConfig{}, err
	}

	return MFAConfig{
		Issuer:          issuer,
		Digits:          digits,
		Period:          period,
		BackupCodeCount: backupCount,
	}, nil
}

func loadOAuth(l *loader) (OAuthConfig, error) {
	google, err := loadOAuthProvider(l, "GOOGLE")
	if err != nil {
		return OAuthConfig{}, err
	}
	github, err := loadOAuthProvider(l, "GITHUB")
	if err != nil {
		return OAuthConfig{}, err
	}
	apple, err := loadOAuthProvider(l, "APPLE")
	if err != nil {
		return OAuthConfig{}, err
	}

	// State secret is required when any provider is enabled.
	var stateSecret string
	if google.Enabled || github.Enabled || apple.Enabled {
		stateSecret = l.requireStr("OAUTH_STATE_SECRET")
	}

	return OAuthConfig{
		Google:      google,
		GitHub:      github,
		Apple:       apple,
		StateSecret: stateSecret,
	}, nil
}

func loadOAuthProvider(l *loader, provider string) (OAuthProviderConfig, error) {
	prefix := "OAUTH_" + provider + "_"

	enabled, err := l.optBool(prefix+"ENABLED", false)
	if err != nil {
		return OAuthProviderConfig{}, err
	}
	if !enabled {
		return OAuthProviderConfig{Enabled: false}, nil
	}

	clientID := l.requireStr(prefix + "CLIENT_ID")
	clientSecret := l.requireStr(prefix + "CLIENT_SECRET")
	redirectURI := l.requireStr(prefix + "REDIRECT_URI")

	// Apple-specific optional fields (ignored for other providers).
	teamID := l.optStr(prefix+"TEAM_ID", "")
	keyID := l.optStr(prefix+"KEY_ID", "")

	return OAuthProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Enabled:      true,
		TeamID:       teamID,
		KeyID:        keyID,
	}, nil
}

func loadOIDC(l *loader) (OIDCConfig, error) {
	issuerURL := l.optStr("OIDC_ISSUER_URL", "https://auth.qf.studio")

	idTokenTTLStr := l.optStr("OIDC_ID_TOKEN_TTL", "1h")
	idTokenTTL, err := parseDuration(idTokenTTLStr)
	if err != nil {
		return OIDCConfig{}, fmt.Errorf("OIDC_ID_TOKEN_TTL: %w", err)
	}

	scopesRaw := l.optStr("OIDC_SUPPORTED_SCOPES", "openid,profile,email,offline_access")
	scopes := splitCSV(scopesRaw)

	loginUIURL := l.optStr("OIDC_LOGIN_UI_URL", "")
	consentUIURL := l.optStr("OIDC_CONSENT_UI_URL", loginUIURL)

	return OIDCConfig{
		IssuerURL:       issuerURL,
		IDTokenTTL:      idTokenTTL,
		SupportedScopes: scopes,
		LoginUIURL:      loginUIURL,
		ConsentUIURL:    consentUIURL,
	}, nil
}

func loadSAML(l *loader) (SAMLConfig, error) {
	enabled, err := l.optBool("SAML_ENABLED", false)
	if err != nil {
		return SAMLConfig{}, err
	}
	if !enabled {
		return SAMLConfig{Enabled: false}, nil
	}

	entityID := l.requireStr("SAML_ENTITY_ID")
	acsURL := l.requireStr("SAML_ACS_URL")
	keyPath := l.requireStr("SAML_KEY_PATH")
	certPath := l.requireStr("SAML_CERT_PATH")

	return SAMLConfig{
		Enabled:  true,
		EntityID: entityID,
		ACSURL:   acsURL,
		KeyPath:  keyPath,
		CertPath: certPath,
	}, nil
}

func loadTenant(l *loader) (TenantConfig, error) {
	defaultID := l.optStr("TENANT_DEFAULT_ID", "")
	mode := l.optStr("TENANT_RESOLUTION_MODE", "both")
	baseDomain := l.optStr("TENANT_BASE_DOMAIN", "")

	if mode != "subdomain" && mode != "header" && mode != "both" {
		return TenantConfig{}, fmt.Errorf("TENANT_RESOLUTION_MODE: unsupported value %q (must be subdomain, header, or both)", mode)
	}

	cacheTTLStr := l.optStr("TENANT_CACHE_TTL", "5m")
	cacheTTL, err := parseDuration(cacheTTLStr)
	if err != nil {
		return TenantConfig{}, fmt.Errorf("TENANT_CACHE_TTL: %w", err)
	}

	return TenantConfig{
		DefaultID:      defaultID,
		ResolutionMode: mode,
		BaseDomain:     baseDomain,
		CacheTTL:       cacheTTL,
	}, nil
}

// splitCSV splits a comma-separated string, trims whitespace, and drops empty entries.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
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
