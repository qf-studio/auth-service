package oauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/oauth"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

// ── Mock Provider ──────────────────────────────────────────────────────────

type mockProvider struct {
	name          string
	getAuthURLFn  func(ctx context.Context) (string, error)
	exchangeCodeFn func(ctx context.Context, code string) (*domain.OAuthUser, error)
}

func (m *mockProvider) Name() string { return m.name }
func (m *mockProvider) GetAuthURL(ctx context.Context) (string, error) {
	if m.getAuthURLFn != nil {
		return m.getAuthURLFn(ctx)
	}
	return "https://provider.example.com/auth?state=abc", nil
}
func (m *mockProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error) {
	if m.exchangeCodeFn != nil {
		return m.exchangeCodeFn(ctx, code)
	}
	return &domain.OAuthUser{
		ProviderUserID: "prov-123",
		Email:          "user@example.com",
		Name:           "Test User",
	}, nil
}

// ── Mock Token Issuer ──────────────────────────────────────────────────────

type mockTokenIssuer struct {
	issueTokenPairFn func(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error)
}

func (m *mockTokenIssuer) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error) {
	if m.issueTokenPairFn != nil {
		return m.issueTokenPairFn(ctx, subject, roles, scopes, clientType)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_test_access",
		RefreshToken: "qf_rt_test_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		UserID:       subject,
	}, nil
}

// ── Mock User Finder ───────────────────────────────────────────────────────

type mockUserFinder struct {
	findByEmailFn func(ctx context.Context, email string) (*domain.User, error)
}

func (m *mockUserFinder) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.findByEmailFn != nil {
		return m.findByEmailFn(ctx, email)
	}
	return nil, storage.ErrNotFound
}

// ── Mock State Generator ───────────────────────────────────────────────────

type mockStateGen struct {
	generateFn func() (string, error)
	validateFn func(state string) error
}

func (m *mockStateGen) Generate() (string, error) {
	if m.generateFn != nil {
		return m.generateFn()
	}
	return "valid-state", nil
}

func (m *mockStateGen) Validate(state string) error {
	if m.validateFn != nil {
		return m.validateFn(state)
	}
	return nil
}

// ── Test Helpers ───────────────────────────────────────────────────────────

func newTestService(
	providers []oauth.Provider,
	repo *mocks.MockOAuthAccountRepository,
	issuer *mockTokenIssuer,
	users *mockUserFinder,
	stateGen *mockStateGen,
) *oauth.Service {
	if issuer == nil {
		issuer = &mockTokenIssuer{}
	}
	if users == nil {
		users = &mockUserFinder{}
	}
	if stateGen == nil {
		stateGen = &mockStateGen{}
	}
	return oauth.NewService(
		config.OAuthConfig{},
		repo,
		issuer,
		users,
		stateGen,
		zap.NewNop(),
		providers...,
	)
}

// ── GetAuthURL Tests ───────────────────────────────────────────────────────

func TestGetAuthURL_Success(t *testing.T) {
	prov := &mockProvider{name: "google"}
	svc := newTestService([]oauth.Provider{prov}, nil, nil, nil, nil)

	result, err := svc.GetAuthURL(context.Background(), "google")
	require.NoError(t, err)
	assert.Contains(t, result.AuthURL, "provider.example.com")
}

func TestGetAuthURL_ProviderNotFound(t *testing.T) {
	svc := newTestService(nil, nil, nil, nil, nil)

	_, err := svc.GetAuthURL(context.Background(), "unknown")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrNotFound))
}

func TestGetAuthURL_ProviderError(t *testing.T) {
	prov := &mockProvider{
		name: "google",
		getAuthURLFn: func(_ context.Context) (string, error) {
			return "", errors.New("state generation failed")
		},
	}
	svc := newTestService([]oauth.Provider{prov}, nil, nil, nil, nil)

	_, err := svc.GetAuthURL(context.Background(), "google")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get auth URL")
}

// ── HandleCallback Tests ───────────────────────────────────────────────────

func TestHandleCallback_ExistingLinkedAccount(t *testing.T) {
	prov := &mockProvider{name: "google"}
	repo := &mocks.MockOAuthAccountRepository{
		FindByProviderAndProviderUserIDFn: func(_ context.Context, _, _ string) (*domain.OAuthAccount, error) {
			return &domain.OAuthAccount{
				ID:             "oa-1",
				UserID:         "user-1",
				Provider:       "google",
				ProviderUserID: "prov-123",
			}, nil
		},
	}
	issuer := &mockTokenIssuer{}
	svc := newTestService([]oauth.Provider{prov}, repo, issuer, nil, nil)

	result, err := svc.HandleCallback(context.Background(), "google", "auth_code", "valid-state")
	require.NoError(t, err)
	assert.Equal(t, "user-1", result.UserID)
	assert.Equal(t, "qf_at_test_access", result.AccessToken)
}

func TestHandleCallback_LinkToExistingUser(t *testing.T) {
	prov := &mockProvider{name: "google"}
	repo := &mocks.MockOAuthAccountRepository{
		FindByProviderAndProviderUserIDFn: func(_ context.Context, _, _ string) (*domain.OAuthAccount, error) {
			return nil, storage.ErrNotFound
		},
		CreateFn: func(_ context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
			return account, nil
		},
	}
	users := &mockUserFinder{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{
				ID:    "user-2",
				Email: "user@example.com",
				Roles: []string{"user"},
			}, nil
		},
	}
	svc := newTestService([]oauth.Provider{prov}, repo, nil, users, nil)

	result, err := svc.HandleCallback(context.Background(), "google", "auth_code", "valid-state")
	require.NoError(t, err)
	assert.Equal(t, "user-2", result.UserID)
	assert.Equal(t, "qf_at_test_access", result.AccessToken)
}

func TestHandleCallback_NoLinkedAccountNoUser(t *testing.T) {
	prov := &mockProvider{name: "google"}
	repo := &mocks.MockOAuthAccountRepository{
		FindByProviderAndProviderUserIDFn: func(_ context.Context, _, _ string) (*domain.OAuthAccount, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestService([]oauth.Provider{prov}, repo, nil, nil, nil)

	_, err := svc.HandleCallback(context.Background(), "google", "auth_code", "valid-state")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrNotFound))
}

func TestHandleCallback_ProviderNotFound(t *testing.T) {
	svc := newTestService(nil, nil, nil, nil, nil)

	_, err := svc.HandleCallback(context.Background(), "unknown", "code", "state")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrNotFound))
}

func TestHandleCallback_EmptyState(t *testing.T) {
	prov := &mockProvider{name: "google"}
	svc := newTestService([]oauth.Provider{prov}, nil, nil, nil, nil)

	_, err := svc.HandleCallback(context.Background(), "google", "code", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrUnauthorized))
}

func TestHandleCallback_InvalidState(t *testing.T) {
	prov := &mockProvider{name: "google"}
	stateGen := &mockStateGen{
		validateFn: func(_ string) error {
			return errors.New("invalid state signature")
		},
	}
	svc := newTestService([]oauth.Provider{prov}, nil, nil, nil, stateGen)

	_, err := svc.HandleCallback(context.Background(), "google", "code", "bad-state")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrUnauthorized))
}

func TestHandleCallback_CodeExchangeFailed(t *testing.T) {
	prov := &mockProvider{
		name: "google",
		exchangeCodeFn: func(_ context.Context, _ string) (*domain.OAuthUser, error) {
			return nil, errors.New("exchange failed")
		},
	}
	svc := newTestService([]oauth.Provider{prov}, nil, nil, nil, nil)

	_, err := svc.HandleCallback(context.Background(), "google", "bad_code", "valid-state")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrUnauthorized))
}

func TestHandleCallback_DuplicateAccountLink(t *testing.T) {
	prov := &mockProvider{name: "google"}
	repo := &mocks.MockOAuthAccountRepository{
		FindByProviderAndProviderUserIDFn: func(_ context.Context, _, _ string) (*domain.OAuthAccount, error) {
			return nil, storage.ErrNotFound
		},
		CreateFn: func(_ context.Context, _ *domain.OAuthAccount) (*domain.OAuthAccount, error) {
			return nil, storage.ErrDuplicateOAuthAccount
		},
	}
	users := &mockUserFinder{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: "user-3", Email: "user@example.com"}, nil
		},
	}
	svc := newTestService([]oauth.Provider{prov}, repo, nil, users, nil)

	_, err := svc.HandleCallback(context.Background(), "google", "auth_code", "valid-state")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrConflict))
}

// ── ListLinkedAccounts Tests ───────────────────────────────────────────────

func TestListLinkedAccounts_Success(t *testing.T) {
	repo := &mocks.MockOAuthAccountRepository{
		FindByUserIDFn: func(_ context.Context, _ string) ([]domain.OAuthAccount, error) {
			return []domain.OAuthAccount{
				{ID: "oa-1", Provider: "google", UserID: "user-1"},
				{ID: "oa-2", Provider: "github", UserID: "user-1"},
			}, nil
		},
	}
	svc := newTestService(nil, repo, nil, nil, nil)

	result, err := svc.ListLinkedAccounts(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Len(t, result.Accounts, 2)
}

func TestListLinkedAccounts_Empty(t *testing.T) {
	repo := &mocks.MockOAuthAccountRepository{
		FindByUserIDFn: func(_ context.Context, _ string) ([]domain.OAuthAccount, error) {
			return nil, nil
		},
	}
	svc := newTestService(nil, repo, nil, nil, nil)

	result, err := svc.ListLinkedAccounts(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Empty(t, result.Accounts)
}

// ── UnlinkAccount Tests ────────────────────────────────────────────────────

func TestUnlinkAccount_Success(t *testing.T) {
	repo := &mocks.MockOAuthAccountRepository{
		DeleteFn: func(_ context.Context, _, _ string) error {
			return nil
		},
	}
	svc := newTestService(nil, repo, nil, nil, nil)

	err := svc.UnlinkAccount(context.Background(), "user-1", "google")
	require.NoError(t, err)
}

func TestUnlinkAccount_NotFound(t *testing.T) {
	repo := &mocks.MockOAuthAccountRepository{
		DeleteFn: func(_ context.Context, _, _ string) error {
			return storage.ErrNotFound
		},
	}
	svc := newTestService(nil, repo, nil, nil, nil)

	err := svc.UnlinkAccount(context.Background(), "user-1", "google")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrNotFound))
}

// ── State Generator Tests ──────────────────────────────────────────────────

func TestHMACStateGenerator_GenerateAndValidate(t *testing.T) {
	gen := oauth.NewHMACStateGenerator([]byte("test-secret"), 5*time.Minute)

	state, err := gen.Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, state)

	err = gen.Validate(state)
	require.NoError(t, err)
}

func TestHMACStateGenerator_InvalidSignature(t *testing.T) {
	gen := oauth.NewHMACStateGenerator([]byte("test-secret"), 5*time.Minute)

	err := gen.Validate("aW52YWxpZC1zdGF0ZS10b2tlbi1kYXRh")
	require.Error(t, err)
}

func TestHMACStateGenerator_Expired(t *testing.T) {
	gen := oauth.NewHMACStateGenerator([]byte("test-secret"), 1*time.Nanosecond)

	state, err := gen.Generate()
	require.NoError(t, err)

	// The token is already expired because TTL is 1ns.
	err = gen.Validate(state)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestHMACStateGenerator_DifferentSecrets(t *testing.T) {
	gen1 := oauth.NewHMACStateGenerator([]byte("secret-1"), 5*time.Minute)
	gen2 := oauth.NewHMACStateGenerator([]byte("secret-2"), 5*time.Minute)

	state, err := gen1.Generate()
	require.NoError(t, err)

	err = gen2.Validate(state)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}
