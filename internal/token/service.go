// Package token implements the token management service including
// JWT issuance, refresh, revocation, and JWKS endpoint.
package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// accessTokenPrefix is prepended to JWT access tokens for leak detection.
	accessTokenPrefix = "qf_at_"

	// refreshTokenPrefix is prepended to refresh tokens for leak detection.
	refreshTokenPrefix = "qf_rt_"

	// revokedKeyPrefix is the Redis key prefix for the revocation blocklist.
	revokedKeyPrefix = "revoked:"

	// refreshKeyPrefix is the Redis key prefix for stored refresh token signatures.
	refreshKeyPrefix = "rt_sig:"

	// jtiBytes is the number of random bytes for JWT ID generation (16 bytes = 128 bits).
	jtiBytes = 16

	// refreshKeyBytes is the number of random bytes for the refresh token key part.
	refreshKeyBytes = 32
)

// UserLookup abstracts user retrieval for refresh-token role enrichment.
// This is a narrow interface satisfied by storage.UserRepository.
type UserLookup interface {
	FindByID(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error)
}

// ClientLookup abstracts OAuth2 client retrieval for refresh-token audience
// preservation (GH-512). This is a narrow interface satisfied by
// storage.ClientRepository.
type ClientLookup interface {
	FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.Client, error)
}

// RefreshTokenStore abstracts the Postgres bookkeeping for refresh token
// signatures performed during rotation. This is a narrow interface satisfied
// by storage.RefreshTokenRepository.
type RefreshTokenStore interface {
	Store(ctx context.Context, tenantID uuid.UUID, signature, userID string, expiresAt time.Time) error
	Revoke(ctx context.Context, tenantID uuid.UUID, signature string) error
}

// Service implements api.TokenService and middleware.TokenValidator.
type Service struct {
	logger        *zap.Logger
	audit         audit.EventLogger
	redis         *redis.Client
	cfg           config.JWTConfig
	oidc          config.OIDCConfig
	privateKey    crypto.Signer
	publicKey     crypto.PublicKey
	signingMethod jwt.SigningMethod
	users         UserLookup
	clients       ClientLookup
	refreshTokens RefreshTokenStore
	kid           string
}

// NewService creates a new token Service, loading the private key from the
// path specified in cfg.PrivateKeyPath. oidcCfg.IssuerURL is used as the JWT
// `iss` claim for both access tokens and ID tokens; oidcCfg.IDTokenTTL is the
// lifetime of tokens minted by IssueIDToken.
func NewService(cfg config.JWTConfig, oidcCfg config.OIDCConfig, redisClient *redis.Client, logger *zap.Logger, auditor audit.EventLogger) (*Service, error) {
	keyData, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	signer, pub, method, err := parsePrivateKey(keyData, cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	kid, err := jwkThumbprint(pub)
	if err != nil {
		return nil, fmt.Errorf("compute key thumbprint: %w", err)
	}

	return &Service{
		logger:        logger,
		audit:         auditor,
		redis:         redisClient,
		cfg:           cfg,
		oidc:          oidcCfg,
		privateKey:    signer,
		publicKey:     pub,
		signingMethod: method,
		kid:           kid,
	}, nil
}

// NewServiceFromKey creates a token Service from an already-parsed private key.
// Useful for testing without filesystem access.
func NewServiceFromKey(cfg config.JWTConfig, oidcCfg config.OIDCConfig, privateKey crypto.Signer, redisClient *redis.Client, logger *zap.Logger, auditor audit.EventLogger) (*Service, error) {
	pub := privateKey.Public()
	method, err := signingMethodForKey(privateKey, cfg.Algorithm)
	if err != nil {
		return nil, err
	}

	kid, err := jwkThumbprint(pub)
	if err != nil {
		return nil, fmt.Errorf("compute key thumbprint: %w", err)
	}

	return &Service{
		logger:        logger,
		audit:         auditor,
		redis:         redisClient,
		cfg:           cfg,
		oidc:          oidcCfg,
		privateKey:    privateKey,
		publicKey:     pub,
		signingMethod: method,
		kid:           kid,
	}, nil
}

// SetUserLookup injects the user repository used to enrich refresh-minted
// access tokens with the user's current roles (GH-432). Optional: if unset,
// refreshed access tokens carry no roles claim. Injected post-construction
// so callers that don't need role enrichment (e.g. tests) can skip it,
// mirroring auth.Service.SetMFAChecker.
func (s *Service) SetUserLookup(users UserLookup) {
	s.users = users
}

// SetClientLookup injects the client repository used to re-resolve a
// refresh token's originating client at refresh time, so the reissued
// access token carries that client's current Audience instead of silently
// falling back to the global JWT_AUDIENCE (GH-512). Optional: if unset,
// refreshed access tokens always fall back to the global JWT_AUDIENCE, the
// pre-GH-512 behavior. Injected post-construction, mirroring SetUserLookup.
func (s *Service) SetClientLookup(clients ClientLookup) {
	s.clients = clients
}

// SetRefreshTokenStore injects the Postgres refresh-token repository used to
// keep introspection state truthful across rotation: on refresh, the old
// signature's row is marked revoked and the new signature's row is inserted
// (GH-486). Optional: if unset, rotation stays Redis-only and Postgres
// introspection state goes stale until the old row's original TTL expires.
// Injected post-construction, mirroring SetUserLookup.
func (s *Service) SetRefreshTokenStore(store RefreshTokenStore) {
	s.refreshTokens = store
}

// IssueTokenPair generates an access/refresh token pair for the given subject.
// audience, if given, overrides JWT_AUDIENCE on the issued access token —
// callers pass the requesting client's Client.Audience (GH-506) when known;
// omitting it (or passing an empty client audience) falls back to the
// service-wide JWT_AUDIENCE.
func (s *Service) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, audience ...string) (*api.AuthResult, error) {
	return s.issueTokenPair(ctx, subject, roles, scopes, clientType, "", "", audience)
}

// IssueTokenPairWithDPoP generates a DPoP-bound access/refresh token pair.
// The jktThumbprint is embedded as the cnf.jkt claim in the access token.
// audience behaves as documented on IssueTokenPair.
func (s *Service) IssueTokenPairWithDPoP(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, jktThumbprint string, audience ...string) (*api.AuthResult, error) {
	return s.issueTokenPair(ctx, subject, roles, scopes, clientType, jktThumbprint, "", audience)
}

// IssueTokenPairForClient generates an access/refresh token pair for a
// request made on behalf of a known OAuth2 client (e.g. the OIDC
// code-exchange grant). clientID is persisted alongside the refresh token so
// that a later refresh (GH-512) can re-resolve the client and reapply its
// current Audience, rather than silently falling back to the global
// JWT_AUDIENCE the way a refresh with no client context does. audience
// behaves as documented on IssueTokenPair.
func (s *Service) IssueTokenPairForClient(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, clientID string, audience ...string) (*api.AuthResult, error) {
	return s.issueTokenPair(ctx, subject, roles, scopes, clientType, "", clientID, audience)
}

// IssueAccessTokenForClient generates an access token only, with no refresh
// token, for a request made on behalf of a known OAuth2 client. The OIDC
// code-exchange grant uses it when offline_access was not granted (OIDC Core
// §11). audience behaves as documented on IssueTokenPair.
func (s *Service) IssueAccessTokenForClient(_ context.Context, subject string, roles, scopes []string, clientType domain.ClientType, clientID string, audience ...string) (*api.AuthResult, error) {
	accessToken, err := s.issueAccessToken(subject, roles, scopes, clientType, "", audience)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	return &api.AuthResult{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.cfg.AccessTokenTTL.Seconds()),
	}, nil
}

func (s *Service) issueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, jktThumbprint, clientID string, audience []string) (*api.AuthResult, error) {
	accessToken, err := s.issueAccessToken(subject, roles, scopes, clientType, jktThumbprint, audience)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	refreshToken, err := s.issueRefreshToken(ctx, subject, clientID, jktThumbprint)
	if err != nil {
		return nil, fmt.Errorf("issue refresh token: %w", err)
	}

	tokenType := "Bearer"
	if jktThumbprint != "" {
		tokenType = "DPoP"
	}

	return &api.AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
	}, nil
}

// Refresh exchanges a refresh token for a new access/refresh token pair.
func (s *Service) Refresh(ctx context.Context, rawRefreshToken string) (*api.AuthResult, error) {
	return s.refreshInternal(ctx, rawRefreshToken, "")
}

// RefreshWithDPoP exchanges a refresh token for a DPoP-bound access/refresh token pair.
func (s *Service) RefreshWithDPoP(ctx context.Context, rawRefreshToken, jktThumbprint string) (*api.AuthResult, error) {
	return s.refreshInternal(ctx, rawRefreshToken, jktThumbprint)
}

func (s *Service) refreshInternal(ctx context.Context, rawRefreshToken, jktThumbprint string) (*api.AuthResult, error) {
	keyEncoded, record, err := s.lookupRefreshToken(ctx, rawRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", api.ErrUnauthorized)
	}
	subject, clientID := record.Subject, record.ClientID

	// DPoP binding (GH-539): a refresh token issued with a DPoP key stays
	// bound to it. The stored thumbprint is the source of truth; the caller's
	// proof must match it. Checked before anything is consumed or deleted so a
	// failed attempt cannot burn the legitimate client's token, and the error
	// is identical to an invalid token so the binding is not disclosed.
	// Decision: unbound records (empty JKT) keep the pre-existing behavior,
	// and with a proof the rotated pair becomes bound.
	if record.JKT != "" {
		if subtle.ConstantTimeCompare([]byte(record.JKT), []byte(jktThumbprint)) != 1 {
			return nil, fmt.Errorf("invalid refresh token: %w", api.ErrUnauthorized)
		}
	}

	tenantID := domain.TenantIDFromContext(ctx)

	// The user must still exist and be active: a locked or deleted account
	// gets no new tokens. Refresh tokens carry no roles/scopes of their own,
	// so the same lookup supplies the user's current roles, mirroring what
	// the login path does (GH-432). A lookup failure fails the refresh
	// without consuming the token, so the client can retry.
	var roles []string
	if s.users != nil {
		user, lookupErr := s.users.FindByID(ctx, tenantID, subject)
		if lookupErr != nil && !errors.Is(lookupErr, storage.ErrNotFound) {
			s.logger.Error("failed to look up user for refresh",
				zap.String("subject", subject), zap.Error(lookupErr))
			return nil, fmt.Errorf("refresh: user lookup: %w", api.ErrInternalError)
		}
		if lookupErr != nil || !user.IsActive() {
			s.deleteRefreshKey(ctx, keyEncoded)
			return nil, fmt.Errorf("invalid refresh token: %w", api.ErrUnauthorized)
		}
		roles = user.Roles
	}

	// Rotate: consume the old record atomically. A concurrent refresh with
	// the same token loses here and gets no tokens.
	if err := s.consumeRefreshToken(ctx, keyEncoded, subject); err != nil {
		if errors.Is(err, errRefreshReused) {
			return nil, fmt.Errorf("invalid refresh token: %w", api.ErrUnauthorized)
		}
		return nil, fmt.Errorf("refresh: %w", api.ErrInternalError)
	}

	// Mark the old signature's Postgres row revoked so introspection reflects
	// the rotation immediately rather than waiting out the row's original
	// TTL (GH-486). Best-effort: Postgres bookkeeping must not fail the
	// refresh — Redis (above) is the authoritative revocation signal.
	if s.refreshTokens != nil {
		if oldSig, ok := domain.RefreshTokenSignature(rawRefreshToken); ok {
			if revokeErr := s.refreshTokens.Revoke(ctx, tenantID, oldSig); revokeErr != nil {
				s.logger.Warn("failed to revoke old refresh token signature in db",
					zap.String("subject", subject), zap.Error(revokeErr))
			}
		}
	}

	// Re-resolve the originating client's current Audience (GH-512): a
	// refresh token minted via IssueTokenPairForClient carries its client_id
	// (see issueRefreshToken), so a refreshed access token can inherit that
	// client's Audience instead of silently falling back to the global
	// JWT_AUDIENCE like tokens minted with no client context. Re-fetching
	// rather than freezing the audience at login time also picks up admin
	// changes to the client's Audience made since the original login.
	// clientID is empty for refresh tokens minted with no client context
	// (password/MFA login — see IssueTokenPair callers in auth/mfa), and a
	// lookup failure is non-fatal (best-effort, same rationale as roles
	// enrichment above): both fall back to the global audience, matching
	// issuance's existing empty-audience->global rule.
	var audience []string
	if clientID != "" && s.clients != nil {
		if cid, parseErr := uuid.Parse(clientID); parseErr != nil {
			s.logger.Warn("refresh token has malformed client id, falling back to global audience",
				zap.String("client_id", clientID), zap.Error(parseErr))
		} else if client, lookupErr := s.clients.FindByID(ctx, tenantID, cid); lookupErr != nil {
			s.logger.Warn("failed to look up client for refresh audience preservation",
				zap.String("client_id", clientID), zap.Error(lookupErr))
		} else {
			audience = client.Audience
		}
	}

	result, err := s.issueTokenPair(ctx, subject, roles, nil, domain.ClientTypeUser, jktThumbprint, clientID, audience)
	if err != nil {
		return nil, err
	}

	// Insert the new signature's Postgres row (best-effort, same rationale
	// as above — mirrors the login-time store in auth.Service.Login).
	if s.refreshTokens != nil {
		if newSig, ok := domain.RefreshTokenSignature(result.RefreshToken); ok {
			if storeErr := s.refreshTokens.Store(ctx, tenantID, newSig, subject, time.Now().Add(s.cfg.RefreshTokenTTL)); storeErr != nil {
				s.logger.Warn("failed to store new refresh token signature in db",
					zap.String("subject", subject), zap.Error(storeErr))
			}
		}
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventTokenRefresh,
		ActorID:  subject,
		TargetID: subject,
	})

	return result, nil
}

// ClientCredentials issues an access token for service-to-service authentication.
// Stub: client verification depends on client repository (future issue).
func (s *Service) ClientCredentials(_ context.Context, _, _ string) (*api.AuthResult, error) {
	// TODO(GH-XX): implement client credentials grant with client repository lookup.
	return nil, fmt.Errorf("client credentials not yet implemented: %w", api.ErrInternalError)
}

// ClientCredentialsWithDPoP issues a DPoP-bound access token for service-to-service auth.
// Stub: client verification depends on client repository (future issue).
func (s *Service) ClientCredentialsWithDPoP(_ context.Context, _, _, _ string) (*api.AuthResult, error) {
	return nil, fmt.Errorf("client credentials not yet implemented: %w", api.ErrInternalError)
}

// Revoke invalidates a token: an access token by adding its JTI to the
// Redis blocklist, a refresh token (qf_rt_) by deleting its record.
func (s *Service) Revoke(ctx context.Context, rawToken string) error {
	if strings.HasPrefix(rawToken, refreshTokenPrefix) {
		return s.revokeRefreshToken(ctx, rawToken)
	}

	// Access token.
	token := strings.TrimPrefix(rawToken, accessTokenPrefix)

	claims, err := s.parseJWT(token)
	if err != nil {
		// If not a valid JWT, just return success (RFC 7009: revoke is best-effort).
		s.logger.Debug("revoke: token is not a valid JWT, ignoring", zap.Error(err))
		return nil
	}

	jti, err := claims.GetJTI()
	if err != nil || jti == "" {
		return nil
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil
	}

	ttl := time.Until(exp.Time)
	if ttl <= 0 {
		// Already expired, no need to blocklist.
		return nil
	}

	key := revokedKeyPrefix + jti
	if err := s.redis.Set(ctx, key, "1", ttl).Err(); err != nil {
		s.logger.Error("failed to add token to revocation blocklist",
			zap.String("jti", jti),
			zap.Error(err),
		)
		return fmt.Errorf("revoke token: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventTokenRevoke,
		Metadata: map[string]string{"jti": jti},
	})

	s.logger.Info("token revoked", zap.String("jti", jti), zap.Duration("ttl", ttl))
	return nil
}

// JWKS returns the JSON Web Key Set containing the public key for token verification.
func (s *Service) JWKS(_ context.Context) (*api.JWKSResponse, error) {
	jwk, err := publicKeyToJWK(s.publicKey, s.cfg.Algorithm, s.kid)
	if err != nil {
		return nil, fmt.Errorf("build JWK: %w", err)
	}
	return &api.JWKSResponse{Keys: []interface{}{jwk}}, nil
}

// ValidateToken parses and cryptographically validates the raw JWT (qf_at_ prefix
// already stripped), returning its claims. Implements middleware.TokenValidator.
//
// Only access tokens are accepted: every access token carries a client_type
// claim, while OIDC ID tokens (IssueIDToken) never do, so a token lacking it
// is rejected with domain.ErrNotAccessToken even if its signature is valid
// (GH-473 defense-in-depth against token-type confusion).
func (s *Service) ValidateToken(_ context.Context, rawToken string) (*domain.TokenClaims, error) {
	claims, err := s.parseAndVerifyJWT(rawToken)
	if err != nil {
		return nil, err
	}

	if claims.ClientType == "" {
		return nil, fmt.Errorf("validate token: %w", domain.ErrNotAccessToken)
	}

	// GH-506: audience enforcement is opt-in via JWT_AUDIENCE_ENFORCE so
	// existing consumers (e.g. Pointer, integrated before per-app audiences
	// existed) keep validating tokens regardless of aud until they confirm
	// their expected audience and flip the flag. With it unset, this check
	// never runs — byte-identical to pre-GH-506 behavior. When set but this
	// validator has no configured Audience, there is nothing to check
	// against, so the token is accepted (misconfiguration should not lock
	// out all traffic).
	if s.cfg.AudienceEnforce && len(s.cfg.Audience) > 0 && !audienceContainsAny(claims.Audience, s.cfg.Audience) {
		return nil, fmt.Errorf("validate token: %w", domain.ErrInvalidAudience)
	}

	return claimsToDomain(claims)
}

// audienceContainsAny reports whether tokenAud contains at least one of the
// values in expected. A validator may be configured with more than one
// acceptable audience value (aliases); per RFC 7519 §4.1.3 the token is
// valid for that validator as soon as any one of them appears in aud, not
// only when every configured value is present.
func audienceContainsAny(tokenAud jwt.ClaimStrings, expected []string) bool {
	for _, want := range expected {
		for _, got := range tokenAud {
			if got == want {
				return true
			}
		}
	}
	return false
}

// IsRevoked reports whether the token with the given JTI is present in the
// Redis revocation blocklist. Implements middleware.TokenValidator.
func (s *Service) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	key := revokedKeyPrefix + tokenID
	n, err := s.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("check revocation: %w", err)
	}
	return n > 0, nil
}

// ── Internal: Access Token ───────────────────────────────────────────────────

// Confirmation represents the cnf (confirmation) claim for DPoP-bound tokens (RFC 9449 §6).
type Confirmation struct {
	JKT string `json:"jkt"`
}

// customClaims extends jwt.RegisteredClaims with our application-specific fields.
type customClaims struct {
	jwt.RegisteredClaims
	Roles        []string      `json:"roles,omitempty"`
	Scopes       []string      `json:"scopes,omitempty"`
	ClientType   string        `json:"client_type"`
	Confirmation *Confirmation `json:"cnf,omitempty"`
}

// GetJTI is a helper to extract the JTI from RegisteredClaims.
func (c *customClaims) GetJTI() (string, error) {
	return c.ID, nil
}

func (s *Service) issueAccessToken(subject string, roles, scopes []string, clientType domain.ClientType, jktThumbprint string, audience []string) (string, error) {
	jti, err := generateRandomID(jtiBytes)
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	now := time.Now()
	claims := &customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    s.oidc.IssuerURL,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenTTL)),
			ID:        jti,
		},
		Roles:      roles,
		Scopes:     scopes,
		ClientType: string(clientType),
	}

	// GH-506: a per-client audience (from the requesting OAuth client's
	// Client.Audience) takes priority over the service-wide JWT_AUDIENCE, so
	// a token minted for one product does not validate at another once
	// audience enforcement is turned on for that product.
	aud := audience
	if len(aud) == 0 {
		aud = s.cfg.Audience
	}
	if len(aud) > 0 {
		claims.Audience = jwt.ClaimStrings(aud)
	}

	if jktThumbprint != "" {
		claims.Confirmation = &Confirmation{JKT: jktThumbprint}
	}

	token := jwt.NewWithClaims(s.signingMethod, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return accessTokenPrefix + signed, nil
}

// ── Internal: ID Token (OIDC) ────────────────────────────────────────────────

// idTokenClaims represents an OpenID Connect ID Token (OIDC Core 1.0 §2).
// Unlike access tokens, ID tokens carry no roles/scopes/client_type: they
// identify the authenticated end-user to the relying party (the OIDC client),
// not authorize resource access.
type idTokenClaims struct {
	jwt.RegisteredClaims
	AuthTime int64  `json:"auth_time,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

// IssueIDToken mints an OpenID Connect ID Token (OIDC Core 1.0 §2) for the
// given subject, identifying the relying party as the sole audience via
// clientID (§2: "aud... MUST contain the OAuth 2.0 client_id of the Relying
// Party"). nonce is echoed back verbatim if the authorization request
// included one (§3.1.3.6, mitigates replay attacks); pass "" if absent.
// authTime records when the end-user authenticated (§2, auth_time claim).
// The token is signed with the same key/kid as access tokens and expires
// after cfg.OIDC.IDTokenTTL (OIDC_ID_TOKEN_TTL).
func (s *Service) IssueIDToken(_ context.Context, subject, clientID, nonce string, authTime time.Time) (string, error) {
	jti, err := generateRandomID(jtiBytes)
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	now := time.Now()
	claims := &idTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    s.oidc.IssuerURL,
			Audience:  jwt.ClaimStrings{clientID},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.oidc.IDTokenTTL)),
			ID:        jti,
		},
		AuthTime: authTime.Unix(),
		Nonce:    nonce,
	}

	token := jwt.NewWithClaims(s.signingMethod, claims)
	token.Header["kid"] = s.kid
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign id token: %w", err)
	}

	return signed, nil
}

func (s *Service) parseAndVerifyJWT(rawToken string) (*customClaims, error) {
	claims := &customClaims{}

	token, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != s.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return s.publicKey, nil
	}, jwt.WithValidMethods([]string{s.signingMethod.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// parseJWT parses claims without strict validation (used for revocation to read jti/exp).
func (s *Service) parseJWT(rawToken string) (*customClaims, error) {
	claims := &customClaims{}

	_, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	return claims, nil
}

func claimsToDomain(c *customClaims) (*domain.TokenClaims, error) {
	if c.Subject == "" {
		return nil, fmt.Errorf("missing subject claim")
	}

	claims := &domain.TokenClaims{
		Subject:    c.Subject,
		Roles:      c.Roles,
		Scopes:     c.Scopes,
		ClientType: domain.ClientType(c.ClientType),
		TokenID:    c.ID,
		Audience:   c.Audience,
	}

	if c.ExpiresAt != nil {
		claims.ExpiresAt = c.ExpiresAt.Time
	}
	if c.IssuedAt != nil {
		claims.IssuedAt = c.IssuedAt.Time
	}
	if c.Confirmation != nil {
		claims.JKTThumbprint = c.Confirmation.JKT
	}

	return claims, nil
}

// ── Internal: Refresh Token ──────────────────────────────────────────────────

// refreshTokenData is the JSON value stored in Redis for a refresh token
// key. ClientID is empty for tokens minted with no client context (e.g.
// password/MFA login); when set (via IssueTokenPairForClient), refresh uses
// it to re-resolve the client's current Audience (GH-512).
type refreshTokenData struct {
	Subject  string `json:"sub"`
	ClientID string `json:"cid,omitempty"`
	// IssuedAt is the issue time in unix nanoseconds, compared against the
	// subject's revocation epoch (see refresh_lifecycle.go). Zero for
	// records written before it existed.
	IssuedAt int64 `json:"iat,omitempty"`
	// JKT is the DPoP key thumbprint the token was issued with (GH-539).
	// Empty for unbound tokens and for records written before it existed.
	JKT string `json:"jkt,omitempty"`
}

func (s *Service) issueRefreshToken(ctx context.Context, subject, clientID, jktThumbprint string) (string, error) {
	if len(s.cfg.SystemSecrets) == 0 {
		return "", fmt.Errorf("no system secrets configured")
	}

	keyMaterial, err := generateRandomBytes(refreshKeyBytes)
	if err != nil {
		return "", fmt.Errorf("generate refresh key: %w", err)
	}

	keyEncoded := base64.RawURLEncoding.EncodeToString(keyMaterial)
	signature := hmacSign(keyMaterial, s.cfg.SystemSecrets[0])
	sigEncoded := base64.RawURLEncoding.EncodeToString(signature)

	refreshToken := refreshTokenPrefix + keyEncoded + "." + sigEncoded

	// Store the signature in Redis keyed by encoded key, value is the JSON
	// encoding of refreshTokenData (subject + originating client, if any).
	encoded, err := json.Marshal(refreshTokenData{Subject: subject, ClientID: clientID, IssuedAt: time.Now().UnixNano(), JKT: jktThumbprint})
	if err != nil {
		return "", fmt.Errorf("encode refresh token data: %w", err)
	}
	redisKey := refreshKeyPrefix + keyEncoded
	if err := s.redis.Set(ctx, redisKey, encoded, s.cfg.RefreshTokenTTL).Err(); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}

	return refreshToken, nil
}

// deleteRefreshKey removes the live record for an encoded refresh key.
func (s *Service) deleteRefreshKey(ctx context.Context, keyEncoded string) {
	if err := s.redis.Del(ctx, refreshKeyPrefix+keyEncoded).Err(); err != nil {
		s.logger.Warn("failed to delete refresh token", zap.Error(err))
	}
}

// ── Internal: Key Parsing ────────────────────────────────────────────────────

func parsePrivateKey(data []byte, algorithm string) (crypto.Signer, crypto.PublicKey, jwt.SigningMethod, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try EC-specific parse as fallback.
		ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
		if ecErr != nil {
			return nil, nil, nil, fmt.Errorf("parse private key (PKCS8: %w, EC: %w)", err, ecErr)
		}
		key = ecKey
	}

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if algorithm != "ES256" {
			return nil, nil, nil, fmt.Errorf("key is ECDSA but algorithm is %s", algorithm)
		}
		if k.Curve != elliptic.P256() {
			return nil, nil, nil, fmt.Errorf("ECDSA key must use P-256 curve for ES256")
		}
		return k, &k.PublicKey, jwt.SigningMethodES256, nil

	case ed25519.PrivateKey:
		if algorithm != "EdDSA" {
			return nil, nil, nil, fmt.Errorf("key is Ed25519 but algorithm is %s", algorithm)
		}
		return k, k.Public(), jwt.SigningMethodEdDSA, nil

	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

func signingMethodForKey(key crypto.Signer, algorithm string) (jwt.SigningMethod, error) {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		if algorithm != "ES256" {
			return nil, fmt.Errorf("key is ECDSA but algorithm is %s", algorithm)
		}
		return jwt.SigningMethodES256, nil
	case ed25519.PrivateKey:
		if algorithm != "EdDSA" {
			return nil, fmt.Errorf("key is Ed25519 but algorithm is %s", algorithm)
		}
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ── Internal: JWKS ───────────────────────────────────────────────────────────

// publicKeyToJWK converts a public key to a JWK map (RFC 7517).
func publicKeyToJWK(pub crypto.PublicKey, algorithm, kid string) (map[string]interface{}, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported ECDSA curve")
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()

		// Pad to fixed length.
		xPadded := make([]byte, byteLen)
		yPadded := make([]byte, byteLen)
		copy(xPadded[byteLen-len(xBytes):], xBytes)
		copy(yPadded[byteLen-len(yBytes):], yBytes)

		return map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"alg": algorithm,
			"use": "sig",
			"kid": kid,
			"x":   base64.RawURLEncoding.EncodeToString(xPadded),
			"y":   base64.RawURLEncoding.EncodeToString(yPadded),
		}, nil

	case ed25519.PublicKey:
		return map[string]interface{}{
			"kty": "OKP",
			"crv": "Ed25519",
			"alg": algorithm,
			"use": "sig",
			"kid": kid,
			"x":   base64.RawURLEncoding.EncodeToString([]byte(k)),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// jwkThumbprint computes the RFC 7638 JWK thumbprint of a public key, used as
// the stable `kid` for both the JWKS entry and the JOSE header of tokens
// signed with the corresponding private key. Being a deterministic hash of
// the key material, it is stable across restarts without requiring any
// additional state, and changes automatically if the key is rotated.
func jwkThumbprint(pub crypto.PublicKey) (string, error) {
	// RFC 7638 §3.2: the JSON object must contain only the required members
	// for the key type, with member names in lexicographic order and no
	// whitespace, so the hash input is unambiguous.
	var canonical string

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("unsupported ECDSA curve")
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()

		xPadded := make([]byte, byteLen)
		yPadded := make([]byte, byteLen)
		copy(xPadded[byteLen-len(xBytes):], xBytes)
		copy(yPadded[byteLen-len(yBytes):], yBytes)

		canonical = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`,
			base64.RawURLEncoding.EncodeToString(xPadded),
			base64.RawURLEncoding.EncodeToString(yPadded),
		)

	case ed25519.PublicKey:
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":%q}`,
			base64.RawURLEncoding.EncodeToString([]byte(k)),
		)

	default:
		return "", fmt.Errorf("unsupported public key type: %T", pub)
	}

	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// ── Internal: Crypto Helpers ─────────────────────────────────────────────────

func hmacSign(data []byte, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return h.Sum(nil)
}

func generateRandomID(n int) (string, error) {
	b, err := generateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	return b, nil
}

// Ensure Service implements the required interfaces at compile time.
var _ api.TokenService = (*Service)(nil)
