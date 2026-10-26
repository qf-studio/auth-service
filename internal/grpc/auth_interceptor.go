package grpc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// AuthMode controls how the gRPC caller-authentication interceptor treats
// requests that do not carry a valid service token.
type AuthMode string

const (
	// AuthModeOff disables caller authentication entirely.
	AuthModeOff AuthMode = "off"
	// AuthModeWarn lets unauthenticated calls through but logs a rate-limited
	// WARN per method. It is the rollout default.
	AuthModeWarn AuthMode = "warn"
	// AuthModeEnforce rejects unauthenticated calls with codes.Unauthenticated.
	AuthModeEnforce AuthMode = "enforce"
)

const (
	metadataKeyAuthorization = "authorization"
	bearerScheme             = "bearer"

	// healthServicePrefix is the full-method prefix of the standard gRPC health
	// service. Orchestrator probes cannot carry a service token, so it is
	// exempt in every mode.
	healthServicePrefix = "/grpc.health.v1.Health/"

	// authWarnInterval is the minimum gap between WARN logs for one method.
	authWarnInterval = time.Minute
)

// ParseAuthMode validates s as an AuthMode. An empty string yields AuthModeWarn.
func ParseAuthMode(s string) (AuthMode, error) {
	switch m := AuthMode(strings.ToLower(strings.TrimSpace(s))); m {
	case "":
		return AuthModeWarn, nil
	case AuthModeOff, AuthModeWarn, AuthModeEnforce:
		return m, nil
	default:
		return "", fmt.Errorf("grpc: unsupported auth mode %q (must be off, warn, or enforce)", s)
	}
}

// Authenticator authenticates gRPC callers by a static bearer service token
// carried in the "authorization" metadata key.
type Authenticator struct {
	mode    AuthMode
	digests [][sha256.Size]byte
	logger  *zap.Logger
	now     func() time.Time

	mu       sync.Mutex
	lastWarn map[string]time.Time
}

// NewAuthenticator builds an Authenticator. Only SHA-256 digests of the tokens
// are retained. Enforce mode requires at least one token, otherwise every call
// would be rejected.
func NewAuthenticator(mode AuthMode, tokens []string, logger *zap.Logger) (*Authenticator, error) {
	if logger == nil {
		return nil, fmt.Errorf("grpc: logger is required")
	}
	mode, err := ParseAuthMode(string(mode))
	if err != nil {
		return nil, err
	}
	a := &Authenticator{
		mode:     mode,
		logger:   logger,
		now:      time.Now,
		lastWarn: make(map[string]time.Time),
	}
	for _, t := range tokens {
		if t == "" {
			return nil, fmt.Errorf("grpc: client token must not be empty")
		}
		a.digests = append(a.digests, sha256.Sum256([]byte(t)))
	}
	if mode == AuthModeEnforce && len(a.digests) == 0 {
		return nil, fmt.Errorf("grpc: auth mode enforce requires at least one client token")
	}
	return a, nil
}

// Unary returns the unary server interceptor.
func (a *Authenticator) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if err := a.check(ctx, info.FullMethod); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream returns the stream server interceptor.
func (a *Authenticator) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := a.check(ss.Context(), info.FullMethod); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// check applies the configured mode to one call.
func (a *Authenticator) check(ctx context.Context, method string) error {
	if a.mode == AuthModeOff || strings.HasPrefix(method, healthServicePrefix) {
		return nil
	}

	reason := "missing"
	if presented, ok := bearerToken(ctx); ok {
		if a.valid(presented) {
			return nil
		}
		reason = "invalid"
	}

	if a.mode == AuthModeEnforce {
		return status.Error(codes.Unauthenticated, "missing or invalid service credentials")
	}
	a.warn(ctx, method, reason)
	return nil
}

// valid reports whether presented matches any configured token. It compares
// fixed-size digests and visits every token, so timing reveals neither the
// token length nor which entry matched.
func (a *Authenticator) valid(presented string) bool {
	sum := sha256.Sum256([]byte(presented))
	match := 0
	for i := range a.digests {
		match |= subtle.ConstantTimeCompare(sum[:], a.digests[i][:])
	}
	return match == 1
}

// warn logs at most one WARN per method per authWarnInterval.
func (a *Authenticator) warn(ctx context.Context, method, reason string) {
	now := a.now()
	a.mu.Lock()
	if last, ok := a.lastWarn[method]; ok && now.Sub(last) < authWarnInterval {
		a.mu.Unlock()
		return
	}
	a.lastWarn[method] = now
	a.mu.Unlock()

	logger := LoggerFromContext(ctx)
	if logger == nil {
		logger = a.logger
	}
	peerAddr := "unknown"
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		peerAddr = p.Addr.String()
	}
	logger.Warn("grpc caller not authenticated; allowed because GRPC_AUTH_MODE=warn",
		zap.String("grpc.method", method),
		zap.String("peer", peerAddr),
		zap.String("reason", reason),
	)
}

// bearerToken extracts the token from an "authorization: Bearer <token>" header.
func bearerToken(ctx context.Context) (string, bool) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", false
	}
	vals := md.Get(metadataKeyAuthorization)
	if len(vals) == 0 {
		return "", false
	}
	scheme, tok, found := strings.Cut(vals[0], " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != ""
}
