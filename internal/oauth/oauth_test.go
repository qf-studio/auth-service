package oauth

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// mockProvider implements Provider for testing the service layer.
type mockProvider struct {
	name        string
	authURL     string
	authURLErr  error
	oauthUser   *domain.OAuthUser
	exchangeErr error
}

func (m *mockProvider) Name() string                  { return m.name }
func (m *mockProvider) GetAuthURL(context.Context) (string, error) { return m.authURL, m.authURLErr }
func (m *mockProvider) ExchangeCode(_ context.Context, _ string) (*domain.OAuthUser, error) {
	return m.oauthUser, m.exchangeErr
}

// mockOAuthRepo implements storage.OAuthAccountRepository for testing.
type mockOAuthRepo struct {
	findResult *domain.OAuthAccount
	findErr    error
	accounts   []domain.OAuthAccount
	findAllErr error
	deleteErr  error
}

func (m *mockOAuthRepo) Create(_ context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
	return account, nil
}
func (m *mockOAuthRepo) FindByProviderAndProviderUserID(_ context.Context, _ uuid.UUID, _, _ string) (*domain.OAuthAccount, error) {
	return m.findResult, m.findErr
}
func (m *mockOAuthRepo) FindByUserID(_ context.Context, _ uuid.UUID, _ string) ([]domain.OAuthAccount, error) {
	return m.accounts, m.findAllErr
}
func (m *mockOAuthRepo) Delete(_ context.Context, _ uuid.UUID, _, _ string) error {
	return m.deleteErr
}

func newTestService(providers []Provider, repo storage.OAuthAccountRepository, stateMgr *StateManager) *Service {
	log, _ := zap.NewDevelopment()
	return NewService(config.OAuthConfig{}, repo, nil, log, stateMgr, providers...)
}

func TestService_GetAuthURL_UnknownProvider(t *testing.T) {
	svc := newTestService(nil, &mockOAuthRepo{}, nil)

	_, err := svc.GetAuthURL(context.Background(), "unknown")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oauth provider not supported")
}

func TestService_GetAuthURL_Success(t *testing.T) {
	mp := &mockProvider{name: "test", authURL: "https://example.com/auth?state=abc"}
	svc := newTestService([]Provider{mp}, &mockOAuthRepo{}, nil)

	result, err := svc.GetAuthURL(context.Background(), "test")
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/auth?state=abc", result.AuthURL)
}

func TestService_HandleCallback_UnknownProvider(t *testing.T) {
	svc := newTestService(nil, &mockOAuthRepo{}, nil)

	_, err := svc.HandleCallback(context.Background(), "unknown", "code", "state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oauth provider not supported")
}

func TestService_HandleCallback_InvalidState(t *testing.T) {
	mp := &mockProvider{name: "test"}
	stateMgr := NewStateManager(testSecret)
	svc := newTestService([]Provider{mp}, &mockOAuthRepo{}, stateMgr)

	_, err := svc.HandleCallback(context.Background(), "test", "code", "bad-state")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "state mismatch")
}

func TestService_HandleCallback_ValidStatePassesVerifier(t *testing.T) {
	expectedVerifier := "test-verifier-12345"
	stateMgr := NewStateManager(testSecret)

	state, err := stateMgr.Generate(expectedVerifier)
	require.NoError(t, err)

	// The mock provider captures the context to check the verifier.
	var capturedCtx context.Context
	mp := &mockProvider{
		name: "test",
		oauthUser: &domain.OAuthUser{
			ProviderUserID: "user-1",
			Email:          "test@example.com",
		},
	}
	// Override ExchangeCode to capture context.
	origExchange := mp.ExchangeCode
	_ = origExchange
	contextCapturingProvider := &contextCapturingMockProvider{
		mockProvider: mp,
	}

	repo := &mockOAuthRepo{
		findResult: &domain.OAuthAccount{UserID: "local-user-1"},
	}
	svc := newTestService([]Provider{contextCapturingProvider}, repo, stateMgr)

	result, err := svc.HandleCallback(context.Background(), "test", "code", state)
	require.NoError(t, err)
	assert.Equal(t, "local-user-1", result.UserID)

	capturedCtx = contextCapturingProvider.lastCtx
	verifier := CodeVerifierFromContext(capturedCtx)
	assert.Equal(t, expectedVerifier, verifier)
}

func TestService_HandleCallback_ExistingAccount(t *testing.T) {
	stateMgr := NewStateManager(testSecret)
	state, err := stateMgr.Generate("verifier")
	require.NoError(t, err)

	mp := &mockProvider{
		name: "test",
		oauthUser: &domain.OAuthUser{
			ProviderUserID: "provider-user-1",
			Email:          "test@example.com",
		},
	}
	repo := &mockOAuthRepo{
		findResult: &domain.OAuthAccount{
			UserID:         "local-user-1",
			Provider:       "test",
			ProviderUserID: "provider-user-1",
		},
	}
	svc := newTestService([]Provider{mp}, repo, stateMgr)

	result, err := svc.HandleCallback(context.Background(), "test", "code", state)
	require.NoError(t, err)
	assert.Equal(t, "local-user-1", result.UserID)
}

func TestService_HandleCallback_NoLinkedAccount(t *testing.T) {
	stateMgr := NewStateManager(testSecret)
	state, err := stateMgr.Generate("verifier")
	require.NoError(t, err)

	mp := &mockProvider{
		name: "test",
		oauthUser: &domain.OAuthUser{
			ProviderUserID: "new-user",
			Email:          "new@example.com",
		},
	}
	repo := &mockOAuthRepo{
		findResult: nil,
		findErr:    storage.ErrNotFound,
	}
	svc := newTestService([]Provider{mp}, repo, stateMgr)

	_, err = svc.HandleCallback(context.Background(), "test", "code", state)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no linked account")
}

func TestService_ListLinkedAccounts(t *testing.T) {
	repo := &mockOAuthRepo{
		accounts: []domain.OAuthAccount{
			{Provider: "google", ProviderUserID: "g1"},
			{Provider: "github", ProviderUserID: "gh1"},
		},
	}
	svc := newTestService(nil, repo, nil)

	result, err := svc.ListLinkedAccounts(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Len(t, result.Accounts, 2)
}

func TestService_UnlinkAccount_NotFound(t *testing.T) {
	repo := &mockOAuthRepo{deleteErr: storage.ErrNotFound}
	svc := newTestService(nil, repo, nil)

	err := svc.UnlinkAccount(context.Background(), "user-1", "google")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oauth account not found")
}

// contextCapturingMockProvider wraps a mockProvider to capture the context
// passed to ExchangeCode.
type contextCapturingMockProvider struct {
	*mockProvider
	lastCtx context.Context
}

func (c *contextCapturingMockProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error) {
	c.lastCtx = ctx
	return c.mockProvider.ExchangeCode(ctx, code)
}
