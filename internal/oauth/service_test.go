package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ── Mocks ────────────────────────────────────────────────────────────────────

type mockUserRepo struct {
	findByEmailFn func(ctx context.Context, email string) (*domain.User, error)
	createFn      func(ctx context.Context, user *domain.User) (*domain.User, error)
}

func (m *mockUserRepo) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.findByEmailFn != nil {
		return m.findByEmailFn(ctx, email)
	}
	return nil, storage.ErrNotFound
}

func (m *mockUserRepo) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	if m.createFn != nil {
		return m.createFn(ctx, user)
	}
	return user, nil
}

type mockSocialRepo struct {
	findByProviderUserFn func(ctx context.Context, provider domain.OAuthProvider, providerUserID string) (*domain.SocialAccount, error)
	findByUserIDFn       func(ctx context.Context, userID string) ([]domain.SocialAccount, error)
	linkFn               func(ctx context.Context, account *domain.SocialAccount) (*domain.SocialAccount, error)
}

func (m *mockSocialRepo) FindByProviderUser(ctx context.Context, provider domain.OAuthProvider, providerUserID string) (*domain.SocialAccount, error) {
	if m.findByProviderUserFn != nil {
		return m.findByProviderUserFn(ctx, provider, providerUserID)
	}
	return nil, storage.ErrNotFound
}

func (m *mockSocialRepo) FindByUserID(ctx context.Context, userID string) ([]domain.SocialAccount, error) {
	if m.findByUserIDFn != nil {
		return m.findByUserIDFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockSocialRepo) Link(ctx context.Context, account *domain.SocialAccount) (*domain.SocialAccount, error) {
	if m.linkFn != nil {
		return m.linkFn(ctx, account)
	}
	return account, nil
}

// mockProvider implements Provider for service tests with controllable exchange results.
type mockProvider struct {
	name        domain.OAuthProvider
	exchangeFn  func(ctx context.Context, code, codeVerifier string) (*domain.OAuthUserInfo, error)
	authCodeURL string
}

func (m *mockProvider) Name() domain.OAuthProvider { return m.name }
func (m *mockProvider) AuthCodeURL(state, _ string) string {
	if m.authCodeURL != "" {
		return m.authCodeURL + "?state=" + state
	}
	return "https://mock.provider/auth?state=" + state
}
func (m *mockProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*domain.OAuthUserInfo, error) {
	if m.exchangeFn != nil {
		return m.exchangeFn(ctx, code, codeVerifier)
	}
	return &domain.OAuthUserInfo{
		ProviderUserID: "provider-user-123",
		Email:          "user@example.com",
		Name:           "Test User",
		EmailVerified:  true,
	}, nil
}

// ── Test helpers ─────────────────────────────────────────────────────────────

func newTestService(t *testing.T) (*Service, *mockUserRepo, *mockSocialRepo, *mockProvider) {
	t.Helper()

	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	registry := NewRegistry()
	provider := &mockProvider{name: domain.OAuthProviderGoogle}
	registry.Register(provider, true)

	secret := []byte("test-hmac-secret-32-bytes-long!!")
	stateMgr := NewStateManager(rdb, secret, 10*time.Minute)

	userRepo := &mockUserRepo{}
	socialRepo := &mockSocialRepo{}
	logger, _ := zap.NewDevelopment()

	svc := NewService(registry, stateMgr, userRepo, socialRepo, logger, audit.NopLogger{})
	return svc, userRepo, socialRepo, provider
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestService_BeginAuth(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	t.Run("success returns auth URL and code verifier", func(t *testing.T) {
		result, err := svc.BeginAuth(ctx, domain.OAuthProviderGoogle)
		require.NoError(t, err)
		assert.NotEmpty(t, result.AuthURL)
		assert.NotEmpty(t, result.CodeVerifier)
		assert.Contains(t, result.AuthURL, "state=")
	})

	t.Run("unregistered provider returns error", func(t *testing.T) {
		_, err := svc.BeginAuth(ctx, domain.OAuthProviderApple)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})

	t.Run("disabled provider returns error", func(t *testing.T) {
		disabled := &stubProvider{name: domain.OAuthProviderGitHub}
		svc.registry.Register(disabled, false)

		_, err := svc.BeginAuth(ctx, domain.OAuthProviderGitHub)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "disabled")
	})
}

func TestService_CompleteAuth_NewUser(t *testing.T) {
	svc, userRepo, socialRepo, _ := newTestService(t)
	ctx := context.Background()

	userRepo.findByEmailFn = func(_ context.Context, _ string) (*domain.User, error) {
		return nil, storage.ErrNotFound
	}
	userRepo.createFn = func(_ context.Context, user *domain.User) (*domain.User, error) {
		return user, nil
	}
	socialRepo.findByProviderUserFn = func(_ context.Context, _ domain.OAuthProvider, _ string) (*domain.SocialAccount, error) {
		return nil, storage.ErrNotFound
	}
	socialRepo.linkFn = func(_ context.Context, account *domain.SocialAccount) (*domain.SocialAccount, error) {
		return account, nil
	}

	// Start the flow to get a valid state token.
	begin, err := svc.BeginAuth(ctx, domain.OAuthProviderGoogle)
	require.NoError(t, err)

	// Extract state from the URL.
	state := extractState(begin.AuthURL)

	result, err := svc.CompleteAuth(ctx, state, "auth-code-123", begin.CodeVerifier)
	require.NoError(t, err)
	assert.True(t, result.IsNewUser)
	assert.Equal(t, "user@example.com", result.User.Email)
	assert.Equal(t, "Test User", result.User.Name)
	assert.Equal(t, domain.OAuthProviderGoogle, result.SocialAccount.Provider)
}

func TestService_CompleteAuth_ExistingUserByEmail(t *testing.T) {
	svc, userRepo, socialRepo, _ := newTestService(t)
	ctx := context.Background()

	existingUser := &domain.User{
		ID:    "existing-user-id",
		Email: "user@example.com",
		Name:  "Existing User",
	}

	userRepo.findByEmailFn = func(_ context.Context, email string) (*domain.User, error) {
		if email == "user@example.com" {
			return existingUser, nil
		}
		return nil, storage.ErrNotFound
	}
	socialRepo.findByProviderUserFn = func(_ context.Context, _ domain.OAuthProvider, _ string) (*domain.SocialAccount, error) {
		return nil, storage.ErrNotFound
	}
	socialRepo.linkFn = func(_ context.Context, account *domain.SocialAccount) (*domain.SocialAccount, error) {
		return account, nil
	}

	begin, err := svc.BeginAuth(ctx, domain.OAuthProviderGoogle)
	require.NoError(t, err)
	state := extractState(begin.AuthURL)

	result, err := svc.CompleteAuth(ctx, state, "auth-code-456", begin.CodeVerifier)
	require.NoError(t, err)
	assert.False(t, result.IsNewUser)
	assert.Equal(t, "existing-user-id", result.User.ID)
	assert.Equal(t, domain.OAuthProviderGoogle, result.SocialAccount.Provider)
}

func TestService_CompleteAuth_ExistingSocialAccount(t *testing.T) {
	svc, userRepo, socialRepo, _ := newTestService(t)
	ctx := context.Background()

	existingUser := &domain.User{
		ID:    "existing-user-id",
		Email: "user@example.com",
		Name:  "Existing User",
	}
	existingSocial := &domain.SocialAccount{
		ID:             "social-id-1",
		UserID:         "existing-user-id",
		Provider:       domain.OAuthProviderGoogle,
		ProviderUserID: "provider-user-123",
		Email:          "user@example.com",
	}

	socialRepo.findByProviderUserFn = func(_ context.Context, _ domain.OAuthProvider, pid string) (*domain.SocialAccount, error) {
		if pid == "provider-user-123" {
			return existingSocial, nil
		}
		return nil, storage.ErrNotFound
	}
	userRepo.findByEmailFn = func(_ context.Context, email string) (*domain.User, error) {
		if email == "user@example.com" {
			return existingUser, nil
		}
		return nil, storage.ErrNotFound
	}

	begin, err := svc.BeginAuth(ctx, domain.OAuthProviderGoogle)
	require.NoError(t, err)
	state := extractState(begin.AuthURL)

	result, err := svc.CompleteAuth(ctx, state, "auth-code-789", begin.CodeVerifier)
	require.NoError(t, err)
	assert.False(t, result.IsNewUser)
	assert.Equal(t, "existing-user-id", result.User.ID)
	assert.Equal(t, "social-id-1", result.SocialAccount.ID)
}

func TestService_CompleteAuth_InvalidState(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.CompleteAuth(ctx, "bogus-state-token", "code", "verifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "validate state")
}

func TestService_CompleteAuth_DuplicateSocialAccount(t *testing.T) {
	svc, userRepo, socialRepo, _ := newTestService(t)
	ctx := context.Background()

	userRepo.findByEmailFn = func(_ context.Context, _ string) (*domain.User, error) {
		return &domain.User{ID: "user-1", Email: "user@example.com"}, nil
	}
	socialRepo.findByProviderUserFn = func(_ context.Context, _ domain.OAuthProvider, _ string) (*domain.SocialAccount, error) {
		return nil, storage.ErrNotFound
	}
	socialRepo.linkFn = func(_ context.Context, _ *domain.SocialAccount) (*domain.SocialAccount, error) {
		return nil, storage.ErrDuplicateSocialAccount
	}

	begin, err := svc.BeginAuth(ctx, domain.OAuthProviderGoogle)
	require.NoError(t, err)
	state := extractState(begin.AuthURL)

	_, err = svc.CompleteAuth(ctx, state, "code", begin.CodeVerifier)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "link social account")
}

// extractState extracts the state parameter from a URL string.
func extractState(url string) string {
	const marker = "state="
	idx := 0
	for i := 0; i < len(url)-len(marker); i++ {
		if url[i:i+len(marker)] == marker {
			idx = i + len(marker)
			break
		}
	}
	if idx == 0 {
		return ""
	}
	end := idx
	for end < len(url) && url[end] != '&' {
		end++
	}
	return url[idx:end]
}
