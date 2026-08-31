package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/admin"
	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/oauth"
	"github.com/qf-studio/auth-service/internal/oidc"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/token"
	"github.com/qf-studio/auth-service/migrations"
)

// oidcStack wires together real (testcontainers-backed) Postgres and Redis
// instances plus the concrete OIDC services under test (ProviderService,
// ConsentService, ApprovalService) and their supporting dependencies
// (admin.ClientService, token.Service). This exercises the full stack wired
// in cmd/server/main.go (GH-470), rather than the narrow fakes used by
// provider_service_test.go / consent_service_test.go.
type oidcStack struct {
	provider *oidc.ProviderService
	consent  *oidc.ConsentService
	approval *oidc.ApprovalService
	admin    *admin.ClientService
	users    storage.UserRepository
	oidcCfg  config.OIDCConfig
	pubKey   *ecdsa.PublicKey
}

func setupOIDCStack(t *testing.T) *oidcStack {
	t.Helper()
	ctx := context.Background()

	pgContainer, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("auth_test"),
		tcpostgres.WithUsername("auth_test"),
		tcpostgres.WithPassword("auth_test"),
		tcpostgres.BasicWaitStrategies(),
	)
	require.NoError(t, err, "start postgres testcontainer")
	t.Cleanup(func() {
		require.NoError(t, testcontainers.TerminateContainer(pgContainer))
	})

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	src, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err, "open embedded migrations")
	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	require.NoError(t, err, "create migrate instance")
	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		require.NoError(t, err, "run migrations up")
	}

	pool, err := storage.NewPostgresPool(dsn, 5)
	require.NoError(t, err, "open postgres pool")
	t.Cleanup(pool.Close)

	redisContainer, err := tcredis.Run(ctx, "redis:7.4-alpine")
	require.NoError(t, err, "start redis testcontainer")
	t.Cleanup(func() {
		require.NoError(t, testcontainers.TerminateContainer(redisContainer))
	})

	redisConnStr, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err)
	redisOpts, err := goredis.ParseURL(redisConnStr)
	require.NoError(t, err)
	redisClient := goredis.NewClient(redisOpts)
	t.Cleanup(func() { _ = redisClient.Close() })

	logger := zap.NewNop()
	auditor := audit.NopLogger{}
	hasher := password.New([]byte("test-pepper"))

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "generate ES256 test key")

	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret-1"},
	}
	oidcCfg := config.OIDCConfig{
		IssuerURL:       "https://auth.test.local",
		IDTokenTTL:      10 * time.Minute,
		SupportedScopes: []string{"openid", "profile", "email"},
		LoginUIURL:      "https://login.test.local/login",
		ConsentUIURL:    "https://login.test.local/consent",
	}

	tokenSvc, err := token.NewServiceFromKey(jwtCfg, oidcCfg, privKey, redisClient, logger, auditor)
	require.NoError(t, err, "create token service")

	clientRepo := storage.NewPostgresClientRepository(pool)
	userRepo := storage.NewPostgresUserRepository(pool)
	consentRepo := storage.NewPostgresConsentGrantRepository(pool)
	oidcStore := oidc.NewRedisStore(redisClient)

	return &oidcStack{
		provider: oidc.NewProviderService(oidcCfg, jwtCfg.Algorithm, oidcStore, clientRepo, userRepo, tokenSvc, hasher, logger, auditor),
		consent:  oidc.NewConsentService(oidcCfg, oidcStore, clientRepo, consentRepo, logger, auditor),
		approval: oidc.NewApprovalService(clientRepo, hasher, logger, auditor),
		admin:    admin.NewClientService(clientRepo, hasher, logger, auditor),
		users:    userRepo,
		oidcCfg:  oidcCfg,
		pubKey:   &privKey.PublicKey,
	}
}

// createTestUser inserts a user directly via the repository (bypassing the
// registration flow, which is out of scope for this OIDC-focused test).
func (s *oidcStack) createTestUser(t *testing.T, email string) *domain.User {
	t.Helper()
	ctx := context.Background()

	hash, err := password.New([]byte("test-pepper")).Hash("correct horse battery staple 1")
	require.NoError(t, err)

	created, err := s.users.Create(ctx, &domain.User{
		ID:            uuid.NewString(),
		TenantID:      domain.DefaultTenantID,
		Email:         email,
		PasswordHash:  hash,
		Name:          "Test User",
		Roles:         []string{"user"},
		EmailVerified: true,
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	})
	require.NoError(t, err, "create test user")
	return created
}

// createThirdPartyClient creates and approves a third-party public client
// (requires explicit consent, PKCE-only per ProviderService.Authorize).
func (s *oidcStack) createThirdPartyClient(t *testing.T, redirectURI string) *api.AdminClientWithSecret {
	t.Helper()
	ctx := context.Background()

	created, err := s.approval.CreateThirdPartyClient(ctx, &api.CreateClientRequest{
		Name:         "Third Party App " + uuid.NewString(),
		ClientType:   "public",
		Scopes:       []string{"openid", "profile", "email"},
		RedirectURIs: []string{redirectURI},
	})
	require.NoError(t, err, "create third-party client")

	_, err = s.approval.ApproveClient(ctx, created.ID)
	require.NoError(t, err, "approve third-party client")

	return created
}

// createFirstPartyClient creates a confidential (secret-bearing) first-party
// client, which skips the consent screen (Owner: "admin" in the DB).
func (s *oidcStack) createFirstPartyClient(t *testing.T, redirectURI string) *api.AdminClientWithSecret {
	t.Helper()
	ctx := context.Background()

	created, err := s.admin.CreateClient(ctx, &api.CreateClientRequest{
		Name:         "Confidential Service " + uuid.NewString(),
		ClientType:   "service",
		Scopes:       []string{"openid", "profile", "email"},
		RedirectURIs: []string{redirectURI},
	})
	require.NoError(t, err, "create first-party client")

	return created
}

// parseRedirect parses a redirect URL and returns its query values.
func parseRedirect(t *testing.T, redirectTo string) url.Values {
	t.Helper()
	u, err := url.Parse(redirectTo)
	require.NoError(t, err, "parse redirect URL %q", redirectTo)
	return u.Query()
}

// idTokenIssuer parses idToken (without re-verifying business claims) and
// returns its "iss" claim, verifying the signature against the stack's test
// key in the process.
func (s *oidcStack) idTokenIssuer(t *testing.T, idToken string) string {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(idToken, claims, func(*jwt.Token) (interface{}, error) {
		return s.pubKey, nil
	}, jwt.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err, "parse/verify ID token")
	iss, _ := claims["iss"].(string)
	return iss
}

// TestOIDCFlow_Integration exercises the full OIDC authorization code flow
// (authorize -> login accept -> consent accept -> code -> token -> userinfo)
// against real Postgres and Redis instances, plus the negative/variant
// cases called out in GH-470: reused code, wrong PKCE verifier, plain
// challenge method, unregistered redirect_uri, and the confidential client
// secret path.
func TestOIDCFlow_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testcontainers-backed OIDC integration test in short mode (requires Docker)")
	}

	stack := setupOIDCStack(t)
	ctx := context.Background()

	t.Run("happy path: authorize to userinfo via third-party client with PKCE", func(t *testing.T) {
		user := stack.createTestUser(t, fmt.Sprintf("happy-%s@example.com", uuid.NewString()))
		redirectURI := "https://client.example.com/callback"
		client := stack.createThirdPartyClient(t, redirectURI)

		verifier := oauth.GenerateVerifier()
		challenge := oauth.S256Challenge(verifier)

		authResp, err := stack.provider.Authorize(ctx, &api.AuthorizeRequest{
			ClientID:            client.ID,
			RedirectURI:         redirectURI,
			ResponseType:        "code",
			Scope:               "openid profile email",
			State:               "state-abc",
			Nonce:               "nonce-abc",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
		})
		require.NoError(t, err)
		loginQuery := parseRedirect(t, authResp.RedirectTo)
		loginChallenge := loginQuery.Get("login_challenge")
		require.NotEmpty(t, loginChallenge)

		loginResp, err := stack.consent.AcceptLogin(ctx, loginChallenge, &api.AcceptLoginRequest{Subject: user.ID})
		require.NoError(t, err)
		consentQuery := parseRedirect(t, loginResp.RedirectTo)
		consentChallenge := consentQuery.Get("consent_challenge")
		require.NotEmpty(t, consentChallenge, "third-party client should require explicit consent")

		consentResp, err := stack.consent.AcceptConsent(ctx, consentChallenge, &api.AcceptConsentRequest{
			GrantedScopes: []string{"openid", "profile", "email"},
		})
		require.NoError(t, err)
		codeQuery := parseRedirect(t, consentResp.RedirectTo)
		code := codeQuery.Get("code")
		require.NotEmpty(t, code)
		require.Equal(t, "state-abc", codeQuery.Get("state"))

		tokenResp, err := stack.provider.ExchangeCode(ctx, &api.CodeExchangeRequest{
			GrantType:    "authorization_code",
			Code:         code,
			RedirectURI:  redirectURI,
			ClientID:     client.ID,
			CodeVerifier: verifier,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenResp.AccessToken)
		require.NotEmpty(t, tokenResp.IDToken, "openid scope was granted, ID token expected")

		discovery, err := stack.provider.GetDiscovery(ctx)
		require.NoError(t, err)
		require.Equal(t, discovery.Issuer, stack.idTokenIssuer(t, tokenResp.IDToken),
			"discovery issuer must match iss claim in issued ID tokens")

		userInfo, err := stack.provider.GetUserInfo(ctx, user.ID)
		require.NoError(t, err)
		require.Equal(t, user.ID, userInfo.Sub)
		require.Equal(t, user.Email, userInfo.Email)
		require.True(t, userInfo.EmailVerified)
	})

	t.Run("reused authorization code is rejected", func(t *testing.T) {
		user := stack.createTestUser(t, fmt.Sprintf("reuse-%s@example.com", uuid.NewString()))
		redirectURI := "https://client.example.com/callback"
		client := stack.createThirdPartyClient(t, redirectURI)

		verifier := oauth.GenerateVerifier()
		challenge := oauth.S256Challenge(verifier)

		authResp, err := stack.provider.Authorize(ctx, &api.AuthorizeRequest{
			ClientID: client.ID, RedirectURI: redirectURI, ResponseType: "code",
			Scope: "openid", CodeChallenge: challenge, CodeChallengeMethod: "S256",
		})
		require.NoError(t, err)
		loginChallenge := parseRedirect(t, authResp.RedirectTo).Get("login_challenge")

		loginResp, err := stack.consent.AcceptLogin(ctx, loginChallenge, &api.AcceptLoginRequest{Subject: user.ID})
		require.NoError(t, err)
		consentChallenge := parseRedirect(t, loginResp.RedirectTo).Get("consent_challenge")

		consentResp, err := stack.consent.AcceptConsent(ctx, consentChallenge, &api.AcceptConsentRequest{GrantedScopes: []string{"openid"}})
		require.NoError(t, err)
		code := parseRedirect(t, consentResp.RedirectTo).Get("code")

		exchangeReq := &api.CodeExchangeRequest{
			GrantType: "authorization_code", Code: code, RedirectURI: redirectURI,
			ClientID: client.ID, CodeVerifier: verifier,
		}

		_, err = stack.provider.ExchangeCode(ctx, exchangeReq)
		require.NoError(t, err, "first exchange should succeed")

		_, err = stack.provider.ExchangeCode(ctx, exchangeReq)
		require.Error(t, err, "reused code must be rejected")
		require.True(t, errors.Is(err, api.ErrUnauthorized), "got %v", err)
	})

	t.Run("wrong PKCE verifier is rejected", func(t *testing.T) {
		user := stack.createTestUser(t, fmt.Sprintf("wrongverifier-%s@example.com", uuid.NewString()))
		redirectURI := "https://client.example.com/callback"
		client := stack.createThirdPartyClient(t, redirectURI)

		verifier := oauth.GenerateVerifier()
		challenge := oauth.S256Challenge(verifier)

		authResp, err := stack.provider.Authorize(ctx, &api.AuthorizeRequest{
			ClientID: client.ID, RedirectURI: redirectURI, ResponseType: "code",
			Scope: "openid", CodeChallenge: challenge, CodeChallengeMethod: "S256",
		})
		require.NoError(t, err)
		loginChallenge := parseRedirect(t, authResp.RedirectTo).Get("login_challenge")

		loginResp, err := stack.consent.AcceptLogin(ctx, loginChallenge, &api.AcceptLoginRequest{Subject: user.ID})
		require.NoError(t, err)
		consentChallenge := parseRedirect(t, loginResp.RedirectTo).Get("consent_challenge")

		consentResp, err := stack.consent.AcceptConsent(ctx, consentChallenge, &api.AcceptConsentRequest{GrantedScopes: []string{"openid"}})
		require.NoError(t, err)
		code := parseRedirect(t, consentResp.RedirectTo).Get("code")

		_, err = stack.provider.ExchangeCode(ctx, &api.CodeExchangeRequest{
			GrantType: "authorization_code", Code: code, RedirectURI: redirectURI,
			ClientID: client.ID, CodeVerifier: oauth.GenerateVerifier(), // wrong verifier
		})
		require.Error(t, err)
		require.True(t, errors.Is(err, api.ErrUnauthorized), "got %v", err)
	})

	t.Run("plain code_challenge_method is rejected at authorize via redirect error", func(t *testing.T) {
		redirectURI := "https://client.example.com/callback"
		client := stack.createThirdPartyClient(t, redirectURI)

		authResp, err := stack.provider.Authorize(ctx, &api.AuthorizeRequest{
			ClientID: client.ID, RedirectURI: redirectURI, ResponseType: "code",
			Scope: "openid", State: "plain-state",
			CodeChallenge:       "some-challenge-value",
			CodeChallengeMethod: "plain",
		})
		require.NoError(t, err, "invalid PKCE method is reported via redirect, not a Go error")
		q := parseRedirect(t, authResp.RedirectTo)
		require.Equal(t, "invalid_request", q.Get("error"))
		require.Equal(t, "plain-state", q.Get("state"))
	})

	t.Run("unregistered redirect_uri returns an error, not a redirect", func(t *testing.T) {
		client := stack.createThirdPartyClient(t, "https://client.example.com/callback")

		authResp, err := stack.provider.Authorize(ctx, &api.AuthorizeRequest{
			ClientID: client.ID, RedirectURI: "https://evil.example.com/callback",
			ResponseType: "code", Scope: "openid",
		})
		require.Error(t, err)
		require.Nil(t, authResp)
		require.True(t, errors.Is(err, api.ErrNotFound), "got %v", err)
	})

	t.Run("confidential client secret path works, skipping consent", func(t *testing.T) {
		user := stack.createTestUser(t, fmt.Sprintf("confidential-%s@example.com", uuid.NewString()))
		redirectURI := "https://service.example.com/callback"
		client := stack.createFirstPartyClient(t, redirectURI)
		require.NotEmpty(t, client.ClientSecret)

		authResp, err := stack.provider.Authorize(ctx, &api.AuthorizeRequest{
			ClientID: client.ID, RedirectURI: redirectURI, ResponseType: "code",
			Scope: "openid profile", State: "confidential-state",
		})
		require.NoError(t, err)
		loginChallenge := parseRedirect(t, authResp.RedirectTo).Get("login_challenge")
		require.NotEmpty(t, loginChallenge)

		// First-party clients are auto-consented: AcceptLogin issues the code
		// directly, redirecting to the client's own redirect_uri rather than
		// the consent UI.
		loginResp, err := stack.consent.AcceptLogin(ctx, loginChallenge, &api.AcceptLoginRequest{Subject: user.ID})
		require.NoError(t, err)
		codeQuery := parseRedirect(t, loginResp.RedirectTo)
		code := codeQuery.Get("code")
		require.NotEmpty(t, code)
		require.Equal(t, "confidential-state", codeQuery.Get("state"))

		// Without a client secret, the exchange must fail.
		_, err = stack.provider.ExchangeCode(ctx, &api.CodeExchangeRequest{
			GrantType: "authorization_code", Code: code, RedirectURI: redirectURI, ClientID: client.ID,
		})
		require.Error(t, err, "confidential client must present its secret")
		require.True(t, errors.Is(err, api.ErrUnauthorized), "got %v", err)

		// Re-issue a fresh code: the failed exchange above did not consume
		// the code (secret check happens before code consumption), so the
		// original code is still redeemable with the correct secret.
		tokenResp, err := stack.provider.ExchangeCode(ctx, &api.CodeExchangeRequest{
			GrantType: "authorization_code", Code: code, RedirectURI: redirectURI,
			ClientID: client.ID, ClientSecret: client.ClientSecret,
		})
		require.NoError(t, err)
		require.NotEmpty(t, tokenResp.AccessToken)
		require.NotEmpty(t, tokenResp.IDToken)
	})
}
