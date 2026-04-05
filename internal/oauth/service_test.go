package oauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Test doubles ---

type mockUserFinder struct {
	mu    sync.Mutex
	users map[string]*domain.User
}

func newMockUserFinder() *mockUserFinder {
	return &mockUserFinder{users: make(map[string]*domain.User)}
}

func (m *mockUserFinder) addUser(u *domain.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.Email] = u
}

func (m *mockUserFinder) FindByEmail(_ context.Context, email string) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[email]
	if !ok {
		return nil, fmt.Errorf("email %s: %w", email, storage.ErrNotFound)
	}
	return u, nil
}

type mockUserCreator struct {
	mu      sync.Mutex
	created []*domain.User
	err     error
}

func (m *mockUserCreator) Create(_ context.Context, user *domain.User) (*domain.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return nil, m.err
	}
	m.created = append(m.created, user)
	return user, nil
}

type mockTokenIssuer struct{}

func (m *mockTokenIssuer) IssueTokenPair(_ context.Context, subject string, _, _ []string, _ domain.ClientType) (*api.AuthResult, error) {
	return &api.AuthResult{
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		UserID:       subject,
	}, nil
}

type mockOAuthAccountRepo struct {
	mu       sync.Mutex
	accounts map[string]*domain.OAuthAccount // key: provider:provider_user_id
}

func newMockOAuthAccountRepo() *mockOAuthAccountRepo {
	return &mockOAuthAccountRepo{accounts: make(map[string]*domain.OAuthAccount)}
}

func (m *mockOAuthAccountRepo) key(provider domain.OAuthProviderType, providerUserID string) string {
	return string(provider) + ":" + providerUserID
}

func (m *mockOAuthAccountRepo) Create(_ context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(account.Provider, account.ProviderUserID)
	if _, exists := m.accounts[k]; exists {
		return nil, fmt.Errorf("provider %s user %s: %w", account.Provider, account.ProviderUserID, storage.ErrDuplicateOAuthAccount)
	}
	m.accounts[k] = account
	return account, nil
}

func (m *mockOAuthAccountRepo) FindByProviderAndProviderUserID(_ context.Context, provider domain.OAuthProviderType, providerUserID string) (*domain.OAuthAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := m.key(provider, providerUserID)
	a, ok := m.accounts[k]
	if !ok {
		return nil, fmt.Errorf("provider %s user %s: %w", provider, providerUserID, storage.ErrNotFound)
	}
	return a, nil
}

func (m *mockOAuthAccountRepo) FindByUserID(_ context.Context, userID string) ([]domain.OAuthAccount, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []domain.OAuthAccount
	for _, a := range m.accounts {
		if a.UserID == userID {
			result = append(result, *a)
		}
	}
	return result, nil
}

func (m *mockOAuthAccountRepo) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, a := range m.accounts {
		if a.ID == id {
			delete(m.accounts, k)
			return nil
		}
	}
	return fmt.Errorf("oauth account %s: %w", id, storage.ErrNotFound)
}

// --- Helper to create a test service ---

type testServiceDeps struct {
	registry     *Registry
	stateStore   *memStateStore
	accountRepo  *mockOAuthAccountRepo
	userFinder   *mockUserFinder
	userCreator  *mockUserCreator
	tokenIssuer  *mockTokenIssuer
	mockProvider *MockProvider
}

func newTestService() (*Service, *testServiceDeps) {
	reg := NewRegistry()
	mockProv := &MockProvider{
		ProviderName: domain.OAuthProviderGoogle,
		UserResult: &domain.OAuthUser{
			ProviderUserID: "google-user-123",
			Email:          "test@example.com",
			Name:           "Test User",
		},
	}
	reg.Register(mockProv)

	stateStore := newMemStateStore()
	accountRepo := newMockOAuthAccountRepo()
	userFinder := newMockUserFinder()
	userCreator := &mockUserCreator{}
	tokenIssuer := &mockTokenIssuer{}

	svc := NewService(
		Config{StateSecret: "test-secret-32-bytes-long-enough"},
		reg,
		stateStore,
		accountRepo,
		userFinder,
		userCreator,
		tokenIssuer,
		zap.NewNop(),
		audit.NopLogger{},
	)

	return svc, &testServiceDeps{
		registry:     reg,
		stateStore:   stateStore,
		accountRepo:  accountRepo,
		userFinder:   userFinder,
		userCreator:  userCreator,
		tokenIssuer:  tokenIssuer,
		mockProvider: mockProv,
	}
}

// --- Tests ---

func TestService_InitiateAuth(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	result, err := svc.InitiateAuth(ctx, "google")
	require.NoError(t, err)
	assert.NotEmpty(t, result.AuthURL)
	assert.NotEmpty(t, result.State)
	assert.NotEmpty(t, result.CodeVerifier)
	assert.Contains(t, result.AuthURL, "state=")
	assert.Contains(t, result.AuthURL, "code_challenge=")
}

func TestService_InitiateAuth_UnsupportedProvider(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	_, err := svc.InitiateAuth(ctx, "twitter")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrNotFound))
}

func TestService_HandleCallback_NewUser(t *testing.T) {
	svc, deps := newTestService()
	ctx := context.Background()

	// Initiate to get a valid state token.
	initResult, err := svc.InitiateAuth(ctx, "google")
	require.NoError(t, err)

	// Handle callback — no existing user, should create new.
	result, err := svc.HandleCallback(ctx, initResult.State, "auth-code-123")
	require.NoError(t, err)

	assert.NotEmpty(t, result.AccessToken)
	assert.NotEmpty(t, result.UserID)
	assert.Equal(t, "Bearer", result.TokenType)

	// Verify user was created.
	assert.Len(t, deps.userCreator.created, 1)
	assert.Equal(t, "test@example.com", deps.userCreator.created[0].Email)
	assert.Equal(t, "Test User", deps.userCreator.created[0].Name)
}

func TestService_HandleCallback_AccountLinkingByEmail(t *testing.T) {
	svc, deps := newTestService()
	ctx := context.Background()

	// Pre-existing user with same email.
	existingUser := &domain.User{
		ID:    "existing-user-id",
		Email: "test@example.com",
		Name:  "Existing User",
	}
	deps.userFinder.addUser(existingUser)

	// Initiate and callback.
	initResult, err := svc.InitiateAuth(ctx, "google")
	require.NoError(t, err)

	result, err := svc.HandleCallback(ctx, initResult.State, "auth-code-456")
	require.NoError(t, err)

	// Should link to existing user, not create new.
	assert.Equal(t, "existing-user-id", result.UserID)
	assert.Empty(t, deps.userCreator.created, "should not create a new user")
}

func TestService_HandleCallback_ExistingOAuthAccount(t *testing.T) {
	svc, deps := newTestService()
	ctx := context.Background()

	// Pre-link an OAuth account.
	now := time.Now().UTC()
	_, err := deps.accountRepo.Create(ctx, &domain.OAuthAccount{
		ID:             "existing-oauth-id",
		UserID:         "linked-user-id",
		Provider:       domain.OAuthProviderGoogle,
		ProviderUserID: "google-user-123",
		Email:          "test@example.com",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	require.NoError(t, err)

	// Initiate and callback.
	initResult, err := svc.InitiateAuth(ctx, "google")
	require.NoError(t, err)

	result, err := svc.HandleCallback(ctx, initResult.State, "auth-code-789")
	require.NoError(t, err)

	// Should log in as existing linked user.
	assert.Equal(t, "linked-user-id", result.UserID)
	assert.Empty(t, deps.userCreator.created, "should not create a new user")
}

func TestService_HandleCallback_DuplicateOAuthAccountRace(t *testing.T) {
	svc, deps := newTestService()
	ctx := context.Background()

	// Pre-existing user.
	existingUser := &domain.User{
		ID:    "race-user-id",
		Email: "test@example.com",
		Name:  "Race User",
	}
	deps.userFinder.addUser(existingUser)

	// Pre-link the OAuth account to simulate a race condition.
	now := time.Now().UTC()
	_, err := deps.accountRepo.Create(ctx, &domain.OAuthAccount{
		ID:             "pre-linked-id",
		UserID:         "race-user-id",
		Provider:       domain.OAuthProviderGoogle,
		ProviderUserID: "google-user-123",
		Email:          "test@example.com",
		CreatedAt:      now,
		UpdatedAt:      now,
	})
	require.NoError(t, err)

	// Initiate and callback — the link already exists but we should handle gracefully.
	initResult, err := svc.InitiateAuth(ctx, "google")
	require.NoError(t, err)

	result, err := svc.HandleCallback(ctx, initResult.State, "auth-code-dup")
	require.NoError(t, err)

	// Should still succeed (existing linked account path).
	assert.Equal(t, "race-user-id", result.UserID)
}

func TestService_HandleCallback_InvalidState(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	_, err := svc.HandleCallback(ctx, "invalid.state", "code")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrUnauthorized))
}

func TestService_HandleCallback_ReplayedState(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	initResult, err := svc.InitiateAuth(ctx, "google")
	require.NoError(t, err)

	// First callback succeeds.
	_, err = svc.HandleCallback(ctx, initResult.State, "code-1")
	require.NoError(t, err)

	// Second callback with same state fails (replay).
	_, err = svc.HandleCallback(ctx, initResult.State, "code-2")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrUnauthorized))
}

func TestService_HandleCallback_ProviderExchangeError(t *testing.T) {
	svc, deps := newTestService()
	ctx := context.Background()

	deps.mockProvider.ExchangeErr = fmt.Errorf("provider unavailable")

	initResult, err := svc.InitiateAuth(ctx, "google")
	require.NoError(t, err)

	_, err = svc.HandleCallback(ctx, initResult.State, "bad-code")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exchange code")
}

func TestService_HandleCallback_ProviderGetUserError(t *testing.T) {
	svc, deps := newTestService()
	ctx := context.Background()

	deps.mockProvider.UserErr = fmt.Errorf("user info failed")

	initResult, err := svc.InitiateAuth(ctx, "google")
	require.NoError(t, err)

	_, err = svc.HandleCallback(ctx, initResult.State, "code")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "get oauth user")
}

func TestService_ListProviders(t *testing.T) {
	svc, _ := newTestService()
	providers := svc.ListProviders()
	assert.Contains(t, providers, domain.OAuthProviderGoogle)
}
