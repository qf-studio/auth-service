package oidc_test

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/oauth"
	"github.com/qf-studio/auth-service/internal/oidc"
	"github.com/qf-studio/auth-service/internal/storage"
)

func testOIDCConfig() config.OIDCConfig {
	return config.OIDCConfig{
		IssuerURL:       "https://auth.example.com",
		IDTokenTTL:      time.Hour,
		SupportedScopes: []string{"openid", "profile", "email"},
		LoginUIURL:      "https://login.example.com/login",
		ConsentUIURL:    "https://login.example.com/consent",
	}
}

func testConfidentialClient() *domain.Client {
	return &domain.Client{
		ID:           uuid.New(),
		Name:         "test-client",
		ClientType:   domain.ClientTypeService,
		SecretHash:   "$argon2id$mock$correct-secret",
		Scopes:       []string{"openid", "profile"},
		RedirectURIs: []string{"https://app.example.com/callback"},
		Owner:        "admin",
		Status:       domain.ClientStatusActive,
	}
}

func testPublicClient() *domain.Client {
	return &domain.Client{
		ID:           uuid.New(),
		Name:         "spa-client",
		ClientType:   domain.ClientTypePublic,
		Scopes:       []string{"openid", "profile"},
		RedirectURIs: []string{"https://spa.example.com/callback"},
		Owner:        "admin",
		Status:       domain.ClientStatusActive,
	}
}

func testUserForOIDC() *domain.User {
	return &domain.User{
		ID:            "user-1",
		Email:         "alice@example.com",
		EmailVerified: true,
		Name:          "Alice",
		Roles:         []string{"user"},
	}
}

func newTestProviderService(t *testing.T, cfg config.OIDCConfig, clients oidc.ClientLookup, users oidc.UserLookup, tokens oidc.TokenIssuer, hasher *fakeHasher) (*oidc.ProviderService, oidc.Store) {
	t.Helper()
	_, redisClient := newTestRedis(t)
	store := oidc.NewRedisStore(redisClient)
	if hasher == nil {
		hasher = &fakeHasher{}
	}
	svc := oidc.NewProviderService(cfg, "ES256", store, clients, users, tokens, hasher, zap.NewNop(), audit.NopLogger{})
	return svc, store
}

// ────────────────────────────────────────────────────────────────────────────
// GetDiscovery
// ────────────────────────────────────────────────────────────────────────────

func TestProviderService_GetDiscovery(t *testing.T) {
	cfg := testOIDCConfig()
	svc, _ := newTestProviderService(t, cfg, nil, nil, nil, nil)

	got, err := svc.GetDiscovery(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "https://auth.example.com", got.Issuer)
	assert.Equal(t, "https://auth.example.com/oauth/authorize", got.AuthorizationEndpoint)
	assert.Equal(t, "https://auth.example.com/oauth/token", got.TokenEndpoint)
	assert.Equal(t, "https://auth.example.com/userinfo", got.UserinfoEndpoint)
	assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", got.JwksURI)
	assert.Equal(t, cfg.SupportedScopes, got.ScopesSupported)
	assert.Equal(t, []string{"code"}, got.ResponseTypesSupported)
	assert.Equal(t, []string{"authorization_code"}, got.GrantTypesSupported)
	assert.Equal(t, []string{"public"}, got.SubjectTypesSupported)
	assert.Equal(t, []string{"ES256"}, got.IDTokenSigningAlgValuesSupported)
	assert.Equal(t, []string{"client_secret_post"}, got.TokenEndpointAuthMethodsSupported)
	assert.Equal(t, []string{"S256"}, got.CodeChallengeMethodsSupported)
}

func TestProviderService_GetDiscovery_TrimsTrailingSlash(t *testing.T) {
	cfg := testOIDCConfig()
	cfg.IssuerURL = "https://auth.example.com/"
	svc, _ := newTestProviderService(t, cfg, nil, nil, nil, nil)

	got, err := svc.GetDiscovery(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com", got.Issuer)
	assert.Equal(t, "https://auth.example.com/oauth/authorize", got.AuthorizationEndpoint)
}

// ────────────────────────────────────────────────────────────────────────────
// Authorize
// ────────────────────────────────────────────────────────────────────────────

func TestProviderService_Authorize_Success(t *testing.T) {
	client := testConfidentialClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, id uuid.UUID) (*domain.Client, error) {
			require.Equal(t, client.ID, id)
			return client, nil
		},
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     client.ID.String(),
		RedirectURI:  client.RedirectURIs[0],
		ResponseType: "code",
		Scope:        "openid profile",
		State:        "state-123",

		CodeChallenge:       oauth.S256Challenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.RedirectTo)

	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "login.example.com", u.Host)
	assert.NotEmpty(t, u.Query().Get("login_challenge"))
}

func TestProviderService_Authorize_MissingLoginUIURL(t *testing.T) {
	cfg := testOIDCConfig()
	cfg.LoginUIURL = ""
	svc, _ := newTestProviderService(t, cfg, nil, nil, nil, nil)

	_, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     uuid.New().String(),
		RedirectURI:  "https://app.example.com/callback",
		ResponseType: "code",
		Scope:        "openid",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

func TestProviderService_Authorize_InvalidClientID(t *testing.T) {
	svc, _ := newTestProviderService(t, testOIDCConfig(), &fakeClientLookup{}, nil, nil, nil)

	_, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     "not-a-uuid",
		RedirectURI:  "https://app.example.com/callback",
		ResponseType: "code",
		Scope:        "openid",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestProviderService_Authorize_UnknownClient_ReturnsJSONError(t *testing.T) {
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     uuid.New().String(),
		RedirectURI:  "https://app.example.com/callback",
		ResponseType: "code",
		Scope:        "openid",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
	assert.Nil(t, resp)
}

func TestProviderService_Authorize_InactiveClient_ReturnsJSONError(t *testing.T) {
	client := testConfidentialClient()
	client.Status = domain.ClientStatusSuspended
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	_, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     client.ID.String(),
		RedirectURI:  client.RedirectURIs[0],
		ResponseType: "code",
		Scope:        "openid",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestProviderService_Authorize_RedirectURIMismatch_ReturnsJSONError(t *testing.T) {
	client := testConfidentialClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     client.ID.String(),
		RedirectURI:  "https://evil.example.com/callback",
		ResponseType: "code",
		Scope:        "openid",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
	assert.Nil(t, resp)
}

func TestProviderService_Authorize_UnsupportedResponseType_ReturnsRedirectError(t *testing.T) {
	client := testConfidentialClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     client.ID.String(),
		RedirectURI:  client.RedirectURIs[0],
		ResponseType: "token",
		Scope:        "openid",
		State:        "xyz",
	})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "unsupported_response_type", u.Query().Get("error"))
	assert.Equal(t, "xyz", u.Query().Get("state"))
}

func TestProviderService_Authorize_PublicClientRequiresPKCE(t *testing.T) {
	client := testPublicClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     client.ID.String(),
		RedirectURI:  client.RedirectURIs[0],
		ResponseType: "code",
		Scope:        "openid",
	})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", u.Query().Get("error"))
}

func TestProviderService_Authorize_PlainPKCERejected(t *testing.T) {
	client := testPublicClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:            client.ID.String(),
		RedirectURI:         client.RedirectURIs[0],
		ResponseType:        "code",
		Scope:               "openid",
		CodeChallenge:       "abc",
		CodeChallengeMethod: "plain",
	})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", u.Query().Get("error"))
}

func TestProviderService_Authorize_S256PKCEAccepted(t *testing.T) {
	client := testPublicClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:            client.ID.String(),
		RedirectURI:         client.RedirectURIs[0],
		ResponseType:        "code",
		Scope:               "openid",
		CodeChallenge:       oauth.S256Challenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "login.example.com", u.Host)
	assert.NotEmpty(t, u.Query().Get("login_challenge"))
}

func TestProviderService_Authorize_ConfidentialClientRequiresPKCE(t *testing.T) {
	client := testConfidentialClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
		ClientID:     client.ID.String(),
		RedirectURI:  client.RedirectURIs[0],
		ResponseType: "code",
		Scope:        "openid",
		State:        "s1",
	})
	require.NoError(t, err)
	u, err := url.Parse(resp.RedirectTo)
	require.NoError(t, err)
	assert.Equal(t, "invalid_request", u.Query().Get("error"))
	assert.Equal(t, "s1", u.Query().Get("state"))
	assert.Empty(t, u.Query().Get("login_challenge"))
}

func TestProviderService_Authorize_ScopeValidation(t *testing.T) {
	tests := []struct {
		name         string
		clientScopes []string
		requested    string
		wantScopes   []string // nil => expect invalid_scope redirect
	}{
		{"unknown and unpermitted scopes dropped", []string{"openid", "email"}, "openid email admin", []string{"openid", "email"}},
		{"client scope outside server set dropped", []string{"openid", "email", "admin"}, "openid email admin", []string{"openid", "email"}},
		{"client permitted subset only", []string{"openid"}, "openid email profile", []string{"openid"}},
		{"empty client scopes limited to supported", nil, "openid email profile admin", []string{"openid", "email", "profile"}},
		{"duplicates collapsed", nil, "openid openid email", []string{"openid", "email"}},
		{"openid missing from request", nil, "email profile", nil},
		{"openid not permitted for client", []string{"email"}, "openid email", nil},
		{"only unknown scopes", nil, "admin", nil},
		{"empty scope", nil, "", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := testConfidentialClient()
			client.Scopes = tc.clientScopes
			clients := &fakeClientLookup{
				findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
			}
			svc, store := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

			resp, err := svc.Authorize(context.Background(), &api.AuthorizeRequest{
				ClientID:            client.ID.String(),
				RedirectURI:         client.RedirectURIs[0],
				ResponseType:        "code",
				Scope:               tc.requested,
				State:               "st",
				CodeChallenge:       oauth.S256Challenge("verifier"),
				CodeChallengeMethod: "S256",
			})
			require.NoError(t, err)
			u, err := url.Parse(resp.RedirectTo)
			require.NoError(t, err)

			if tc.wantScopes == nil {
				assert.Equal(t, "invalid_scope", u.Query().Get("error"))
				assert.Equal(t, "st", u.Query().Get("state"))
				assert.Empty(t, u.Query().Get("login_challenge"))
				return
			}

			require.Empty(t, u.Query().Get("error"))
			lr, err := store.GetLoginRequest(context.Background(), u.Query().Get("login_challenge"))
			require.NoError(t, err)
			assert.Equal(t, tc.wantScopes, lr.Scopes)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// ExchangeCode
// ────────────────────────────────────────────────────────────────────────────

func seedAuthCode(t *testing.T, store oidc.Store, code *oidc.AuthorizationCode) {
	t.Helper()
	require.NoError(t, store.SaveAuthorizationCode(context.Background(), code))
}

func TestProviderService_ExchangeCode_Success_WithOpenIDScope(t *testing.T) {
	client := testConfidentialClient()
	user := testUserForOIDC()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	users := &fakeUserLookup{
		findByIDFn: func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
			require.Equal(t, user.ID, id)
			return user, nil
		},
	}
	var issuedNonce, issuedClientID string
	tokens := &fakeTokenIssuer{
		issueTokenPairFn: func(_ context.Context, subject string, roles, scopes []string, clientType domain.ClientType, _ ...string) (*api.AuthResult, error) {
			assert.Equal(t, user.ID, subject)
			assert.Equal(t, domain.ClientTypeUser, clientType)
			return &api.AuthResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900, RefreshToken: "rt"}, nil
		},
		issueIDTokenFn: func(_ context.Context, subject, clientID, nonce string, _ time.Time) (string, error) {
			issuedNonce = nonce
			issuedClientID = clientID
			return "id-token-abc", nil
		},
	}

	svc, store := newTestProviderService(t, testOIDCConfig(), clients, users, tokens, nil)

	code := &oidc.AuthorizationCode{
		Code:                "auth-code-1",
		Subject:             user.ID,
		ClientID:            client.ID.String(),
		RedirectURI:         client.RedirectURIs[0],
		Scopes:              []string{"openid", "profile", "offline_access"},
		Nonce:               "nonce-xyz",
		CodeChallenge:       oauth.S256Challenge("verifier-1"),
		CodeChallengeMethod: "S256",
		AuthTime:            time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Minute),
	}
	seedAuthCode(t, store, code)

	resp, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
		GrantType:    "authorization_code",
		Code:         "auth-code-1",
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ID.String(),
		ClientSecret: "correct-secret",
		CodeVerifier: "verifier-1",
	})
	require.NoError(t, err)
	assert.Equal(t, "at", resp.AccessToken)
	assert.Equal(t, "rt", resp.RefreshToken)
	assert.Equal(t, "id-token-abc", resp.IDToken)
	assert.Equal(t, "openid profile offline_access", resp.Scope)
	assert.Equal(t, "nonce-xyz", issuedNonce)
	assert.Equal(t, client.ID.String(), issuedClientID)
}

func TestProviderService_ExchangeCode_RequiresVerifier(t *testing.T) {
	client := testConfidentialClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	tests := []struct {
		name      string
		challenge string
		verifier  string
	}{
		{"code stored without challenge", "", "verifier-x"},
		{"verifier omitted", oauth.S256Challenge("verifier-x"), ""},
		{"wrong verifier", oauth.S256Challenge("verifier-x"), "other"},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc, store := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)
			codeValue := fmt.Sprintf("auth-code-verifier-%d", i)
			seedAuthCode(t, store, &oidc.AuthorizationCode{
				Code:          codeValue,
				Subject:       "user-1",
				ClientID:      client.ID.String(),
				RedirectURI:   client.RedirectURIs[0],
				Scopes:        []string{"openid"},
				CodeChallenge: tc.challenge,
				ExpiresAt:     time.Now().UTC().Add(time.Minute),
			})

			_, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
				Code:         codeValue,
				RedirectURI:  client.RedirectURIs[0],
				ClientID:     client.ID.String(),
				ClientSecret: "correct-secret",
				CodeVerifier: tc.verifier,
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrUnauthorized)
		})
	}
}

func TestProviderService_ExchangeCode_UserNoLongerActive(t *testing.T) {
	deletedAt := time.Now().UTC()
	tests := []struct {
		name   string
		mutate func(u *domain.User)
	}{
		{"locked after code issued", func(u *domain.User) { u.Locked = true }},
		{"deleted after code issued", func(u *domain.User) { u.DeletedAt = &deletedAt }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := testConfidentialClient()
			user := testUserForOIDC()
			tt.mutate(user)
			clients := &fakeClientLookup{
				findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
			}
			users := &fakeUserLookup{
				findByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) { return user, nil },
			}
			tokens := &fakeTokenIssuer{
				issueTokenPairFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, _ ...string) (*api.AuthResult, error) {
					t.Fatal("no tokens may be issued for an inactive user")
					return nil, nil
				},
				issueTokenPairForClientFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, _ string, _ ...string) (*api.AuthResult, error) {
					t.Fatal("no tokens may be issued for an inactive user")
					return nil, nil
				},
			}
			svc, store := newTestProviderService(t, testOIDCConfig(), clients, users, tokens, nil)

			seedAuthCode(t, store, &oidc.AuthorizationCode{
				Code:                "auth-code-inactive",
				Subject:             user.ID,
				ClientID:            client.ID.String(),
				RedirectURI:         client.RedirectURIs[0],
				Scopes:              []string{"profile"},
				CodeChallenge:       oauth.S256Challenge("verifier-inactive"),
				CodeChallengeMethod: "S256",
				AuthTime:            time.Now().UTC(),
				ExpiresAt:           time.Now().UTC().Add(time.Minute),
			})

			_, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
				GrantType:    "authorization_code",
				Code:         "auth-code-inactive",
				RedirectURI:  client.RedirectURIs[0],
				ClientID:     client.ID.String(),
				ClientSecret: "correct-secret",
				CodeVerifier: "verifier-inactive",
			})
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrUnauthorized)
		})
	}
}

func TestProviderService_ExchangeCode_PassesClientAudience(t *testing.T) {
	client := testConfidentialClient()
	client.Audience = []string{"https://api.example.com"}
	user := testUserForOIDC()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	users := &fakeUserLookup{
		findByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) { return user, nil },
	}
	var capturedAudience []string
	tokens := &fakeTokenIssuer{
		issueTokenPairFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, audience ...string) (*api.AuthResult, error) {
			capturedAudience = audience
			return &api.AuthResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900}, nil
		},
	}

	svc, store := newTestProviderService(t, testOIDCConfig(), clients, users, tokens, nil)

	code := &oidc.AuthorizationCode{
		Code:                "auth-code-aud",
		Subject:             user.ID,
		ClientID:            client.ID.String(),
		RedirectURI:         client.RedirectURIs[0],
		Scopes:              []string{"profile"},
		CodeChallenge:       oauth.S256Challenge("verifier-aud"),
		CodeChallengeMethod: "S256",
		AuthTime:            time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Minute),
	}
	seedAuthCode(t, store, code)

	_, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
		GrantType:    "authorization_code",
		Code:         "auth-code-aud",
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ID.String(),
		ClientSecret: "correct-secret",
		CodeVerifier: "verifier-aud",
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"https://api.example.com"}, capturedAudience)
}

// TestProviderService_ExchangeCode_PersistsClientIDForRefresh is a
// regression test for GH-512: code exchange must call
// IssueTokenPairForClient (not IssueTokenPair) with the requesting client's
// id, so the token service can persist it alongside the refresh token and
// re-resolve the client's Audience on a later refresh instead of silently
// falling back to the global JWT_AUDIENCE.
func TestProviderService_ExchangeCode_PersistsClientIDForRefresh(t *testing.T) {
	client := testConfidentialClient()
	client.Audience = []string{"https://api.example.com"}
	user := testUserForOIDC()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	users := &fakeUserLookup{
		findByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) { return user, nil },
	}
	var capturedClientID string
	var capturedAudience []string
	tokens := &fakeTokenIssuer{
		issueTokenPairForClientFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, clientID string, audience ...string) (*api.AuthResult, error) {
			capturedClientID = clientID
			capturedAudience = audience
			return &api.AuthResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900}, nil
		},
	}

	svc, store := newTestProviderService(t, testOIDCConfig(), clients, users, tokens, nil)

	code := &oidc.AuthorizationCode{
		Code:                "auth-code-cid",
		Subject:             user.ID,
		ClientID:            client.ID.String(),
		RedirectURI:         client.RedirectURIs[0],
		Scopes:              []string{"profile", "offline_access"},
		CodeChallenge:       oauth.S256Challenge("verifier-cid"),
		CodeChallengeMethod: "S256",
		AuthTime:            time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Minute),
	}
	seedAuthCode(t, store, code)

	_, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
		GrantType:    "authorization_code",
		Code:         "auth-code-cid",
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ID.String(),
		ClientSecret: "correct-secret",
		CodeVerifier: "verifier-cid",
	})
	require.NoError(t, err)
	assert.Equal(t, client.ID.String(), capturedClientID)
	assert.Equal(t, []string{"https://api.example.com"}, capturedAudience)
}

func TestProviderService_ExchangeCode_Success_WithoutOpenIDScope_NoIDToken(t *testing.T) {
	client := testConfidentialClient()
	user := testUserForOIDC()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	users := &fakeUserLookup{
		findByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) { return user, nil },
	}
	tokens := &fakeTokenIssuer{
		issueTokenPairFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, _ ...string) (*api.AuthResult, error) {
			return &api.AuthResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900}, nil
		},
		issueIDTokenFn: func(_ context.Context, _, _, _ string, _ time.Time) (string, error) {
			t.Fatal("IssueIDToken should not be called without openid scope")
			return "", nil
		},
	}

	svc, store := newTestProviderService(t, testOIDCConfig(), clients, users, tokens, nil)

	code := &oidc.AuthorizationCode{
		Code:                "auth-code-2",
		Subject:             user.ID,
		ClientID:            client.ID.String(),
		RedirectURI:         client.RedirectURIs[0],
		Scopes:              []string{"profile"},
		CodeChallenge:       oauth.S256Challenge("verifier-2"),
		CodeChallengeMethod: "S256",
		AuthTime:            time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Minute),
	}
	seedAuthCode(t, store, code)

	resp, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
		Code:         "auth-code-2",
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ID.String(),
		ClientSecret: "correct-secret",
		CodeVerifier: "verifier-2",
	})
	require.NoError(t, err)
	assert.Empty(t, resp.IDToken)
}

func TestProviderService_ExchangeCode_InvalidCode(t *testing.T) {
	client := testConfidentialClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	_, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
		Code:         "nonexistent-code",
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ID.String(),
		ClientSecret: "correct-secret",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestProviderService_ExchangeCode_PKCEMismatch(t *testing.T) {
	client := testConfidentialClient()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	svc, store := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

	code := &oidc.AuthorizationCode{
		Code:                "auth-code-3",
		Subject:             "user-1",
		ClientID:            client.ID.String(),
		RedirectURI:         client.RedirectURIs[0],
		Scopes:              []string{"openid"},
		CodeChallenge:       oauth.S256Challenge("verifier-correct"),
		CodeChallengeMethod: "S256",
		AuthTime:            time.Now().UTC(),
		ExpiresAt:           time.Now().UTC().Add(time.Minute),
	}
	seedAuthCode(t, store, code)

	_, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
		Code:         "auth-code-3",
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ID.String(),
		ClientSecret: "correct-secret",
		CodeVerifier: "verifier-wrong",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestProviderService_ExchangeCode_ClientSecretVerification(t *testing.T) {
	t.Run("wrong secret rejected", func(t *testing.T) {
		client := testConfidentialClient()
		clients := &fakeClientLookup{
			findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
		}
		svc, store := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

		code := &oidc.AuthorizationCode{
			Code:        "auth-code-4",
			Subject:     "user-1",
			ClientID:    client.ID.String(),
			RedirectURI: client.RedirectURIs[0],
			Scopes:      []string{"profile"},
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
		}
		seedAuthCode(t, store, code)

		_, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
			Code:         "auth-code-4",
			RedirectURI:  client.RedirectURIs[0],
			ClientID:     client.ID.String(),
			ClientSecret: "wrong-secret",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, api.ErrUnauthorized)
	})

	t.Run("grace period previous secret accepted", func(t *testing.T) {
		client := testConfidentialClient()
		future := time.Now().UTC().Add(time.Hour)
		client.PreviousSecretHash = "$argon2id$mock$old-secret"
		client.PreviousSecretExpiresAt = &future
		clients := &fakeClientLookup{
			findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
		}
		user := testUserForOIDC()
		users := &fakeUserLookup{
			findByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) { return user, nil },
		}
		tokens := &fakeTokenIssuer{
			issueTokenPairFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, _ ...string) (*api.AuthResult, error) {
				return &api.AuthResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900}, nil
			},
		}
		svc, store := newTestProviderService(t, testOIDCConfig(), clients, users, tokens, nil)

		code := &oidc.AuthorizationCode{
			Code:          "auth-code-5",
			Subject:       user.ID,
			ClientID:      client.ID.String(),
			RedirectURI:   client.RedirectURIs[0],
			Scopes:        []string{"profile"},
			CodeChallenge: oauth.S256Challenge("verifier-5"),
			ExpiresAt:     time.Now().UTC().Add(time.Minute),
		}
		seedAuthCode(t, store, code)

		resp, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
			Code:         "auth-code-5",
			RedirectURI:  client.RedirectURIs[0],
			ClientID:     client.ID.String(),
			ClientSecret: "old-secret",
			CodeVerifier: "verifier-5",
		})
		require.NoError(t, err)
		assert.Equal(t, "at", resp.AccessToken)
	})

	t.Run("expired grace period previous secret rejected", func(t *testing.T) {
		client := testConfidentialClient()
		past := time.Now().UTC().Add(-time.Hour)
		client.PreviousSecretHash = "$argon2id$mock$old-secret"
		client.PreviousSecretExpiresAt = &past
		clients := &fakeClientLookup{
			findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
		}
		svc, store := newTestProviderService(t, testOIDCConfig(), clients, nil, nil, nil)

		code := &oidc.AuthorizationCode{
			Code:        "auth-code-6",
			Subject:     "user-1",
			ClientID:    client.ID.String(),
			RedirectURI: client.RedirectURIs[0],
			Scopes:      []string{"profile"},
			ExpiresAt:   time.Now().UTC().Add(time.Minute),
		}
		seedAuthCode(t, store, code)

		_, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
			Code:         "auth-code-6",
			RedirectURI:  client.RedirectURIs[0],
			ClientID:     client.ID.String(),
			ClientSecret: "old-secret",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, api.ErrUnauthorized)
	})
}

func TestProviderService_ExchangeCode_PublicClient_NoSecretRequired(t *testing.T) {
	client := testPublicClient()
	user := testUserForOIDC()
	clients := &fakeClientLookup{
		findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
	}
	users := &fakeUserLookup{
		findByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) { return user, nil },
	}
	tokens := &fakeTokenIssuer{
		issueTokenPairFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, _ ...string) (*api.AuthResult, error) {
			return &api.AuthResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900}, nil
		},
	}
	svc, store := newTestProviderService(t, testOIDCConfig(), clients, users, tokens, nil)

	code := &oidc.AuthorizationCode{
		Code:                "auth-code-7",
		Subject:             user.ID,
		ClientID:            client.ID.String(),
		RedirectURI:         client.RedirectURIs[0],
		Scopes:              []string{"profile"},
		CodeChallenge:       oauth.S256Challenge("verifier-7"),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().UTC().Add(time.Minute),
	}
	seedAuthCode(t, store, code)

	resp, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
		Code:         "auth-code-7",
		RedirectURI:  client.RedirectURIs[0],
		ClientID:     client.ID.String(),
		CodeVerifier: "verifier-7",
	})
	require.NoError(t, err)
	assert.Equal(t, "at", resp.AccessToken)
}

// ────────────────────────────────────────────────────────────────────────────
// GetUserInfo
// ────────────────────────────────────────────────────────────────────────────

func TestProviderService_GetUserInfo_ScopeProjection(t *testing.T) {
	user := testUserForOIDC()
	users := &fakeUserLookup{
		findByIDFn: func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
			require.Equal(t, user.ID, id)
			return user, nil
		},
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), nil, users, nil, nil)

	tests := []struct {
		name    string
		scopes  []string
		want    api.OIDCUserInfoResponse
		wantErr error
	}{
		{"openid only returns sub only", []string{"openid"}, api.OIDCUserInfoResponse{Sub: user.ID}, nil},
		{"email scope adds email fields", []string{"openid", "email"},
			api.OIDCUserInfoResponse{Sub: user.ID, Email: user.Email, EmailVerified: true}, nil},
		{"profile scope adds name", []string{"openid", "profile"},
			api.OIDCUserInfoResponse{Sub: user.ID, Name: user.Name}, nil},
		{"all scopes", []string{"openid", "email", "profile"},
			api.OIDCUserInfoResponse{Sub: user.ID, Email: user.Email, EmailVerified: true, Name: user.Name}, nil},
		{"no openid is insufficient_scope", []string{"email", "profile"}, api.OIDCUserInfoResponse{}, api.ErrInsufficientScope},
		{"no scopes is insufficient_scope", nil, api.OIDCUserInfoResponse{}, api.ErrInsufficientScope},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.GetUserInfo(context.Background(), user.ID, tc.scopes)
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, *got)
		})
	}
}

func TestProviderService_GetUserInfo_NotFound(t *testing.T) {
	users := &fakeUserLookup{
		findByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc, _ := newTestProviderService(t, testOIDCConfig(), nil, users, nil, nil)

	_, err := svc.GetUserInfo(context.Background(), "missing-user", []string{"openid"})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// TestProviderService_ExchangeCode_RefreshTokenOnlyWithOfflineAccess covers
// GH-541: the code exchange returns a refresh token only when offline_access
// is among the granted scopes (OIDC Core §11).
func TestProviderService_ExchangeCode_RefreshTokenOnlyWithOfflineAccess(t *testing.T) {
	tests := []struct {
		name        string
		scopes      []string
		wantRefresh bool
	}{
		{"openid and offline_access", []string{"openid", "offline_access"}, true},
		{"openid only", []string{"openid"}, false},
		{"openid profile email", []string{"openid", "profile", "email"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := testConfidentialClient()
			user := testUserForOIDC()
			clients := &fakeClientLookup{
				findByIDFn: func(_ context.Context, _, _ uuid.UUID) (*domain.Client, error) { return client, nil },
			}
			users := &fakeUserLookup{
				findByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) { return user, nil },
			}
			var pairCalls, accessOnlyCalls int
			tokens := &fakeTokenIssuer{
				issueTokenPairForClientFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, _ string, _ ...string) (*api.AuthResult, error) {
					pairCalls++
					return &api.AuthResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900, RefreshToken: "rt"}, nil
				},
				issueAccessTokenForClientFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType, _ string, _ ...string) (*api.AuthResult, error) {
					accessOnlyCalls++
					return &api.AuthResult{AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900}, nil
				},
				issueIDTokenFn: func(_ context.Context, _, _, _ string, _ time.Time) (string, error) {
					return "id-token", nil
				},
			}

			svc, store := newTestProviderService(t, testOIDCConfig(), clients, users, tokens, nil)
			seedAuthCode(t, store, &oidc.AuthorizationCode{
				Code:                "auth-code-oa",
				Subject:             user.ID,
				ClientID:            client.ID.String(),
				RedirectURI:         client.RedirectURIs[0],
				Scopes:              tc.scopes,
				CodeChallenge:       oauth.S256Challenge("verifier-oa"),
				CodeChallengeMethod: "S256",
				AuthTime:            time.Now().UTC(),
				ExpiresAt:           time.Now().UTC().Add(time.Minute),
			})

			resp, err := svc.ExchangeCode(context.Background(), &api.CodeExchangeRequest{
				GrantType:    "authorization_code",
				Code:         "auth-code-oa",
				RedirectURI:  client.RedirectURIs[0],
				ClientID:     client.ID.String(),
				ClientSecret: "correct-secret",
				CodeVerifier: "verifier-oa",
			})
			require.NoError(t, err)
			assert.Equal(t, "at", resp.AccessToken)
			assert.Equal(t, "id-token", resp.IDToken)
			if tc.wantRefresh {
				assert.Equal(t, "rt", resp.RefreshToken)
				assert.Equal(t, 1, pairCalls)
				assert.Zero(t, accessOnlyCalls)
			} else {
				assert.Empty(t, resp.RefreshToken)
				assert.Zero(t, pairCalls)
				assert.Equal(t, 1, accessOnlyCalls)
			}
		})
	}
}
