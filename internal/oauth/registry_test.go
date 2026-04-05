package oauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

// stubProvider implements Provider for testing.
type stubProvider struct {
	name domain.OAuthProvider
}

func (s *stubProvider) Name() domain.OAuthProvider { return s.name }
func (s *stubProvider) AuthCodeURL(state, codeVerifier string) string {
	return "https://example.com/auth?state=" + state
}
func (s *stubProvider) ExchangeCode(_ context.Context, _, _ string) (*domain.OAuthUserInfo, error) {
	return &domain.OAuthUserInfo{
		ProviderUserID: "stub-id",
		Email:          "stub@example.com",
		Name:           "Stub User",
		EmailVerified:  true,
	}, nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()

	google := &stubProvider{name: domain.OAuthProviderGoogle}
	github := &stubProvider{name: domain.OAuthProviderGitHub}

	t.Run("register and retrieve enabled provider", func(t *testing.T) {
		r.Register(google, true)
		p, err := r.Get(domain.OAuthProviderGoogle)
		require.NoError(t, err)
		assert.Equal(t, domain.OAuthProviderGoogle, p.Name())
	})

	t.Run("register disabled provider returns ErrProviderDisabled", func(t *testing.T) {
		r.Register(github, false)
		_, err := r.Get(domain.OAuthProviderGitHub)
		assert.ErrorIs(t, err, ErrProviderDisabled)
	})

	t.Run("unregistered provider returns ErrProviderNotFound", func(t *testing.T) {
		_, err := r.Get(domain.OAuthProviderApple)
		assert.ErrorIs(t, err, ErrProviderNotFound)
	})
}

func TestRegistry_SetEnabled(t *testing.T) {
	r := NewRegistry()
	p := &stubProvider{name: domain.OAuthProviderGoogle}
	r.Register(p, false)

	t.Run("enable a disabled provider", func(t *testing.T) {
		err := r.SetEnabled(domain.OAuthProviderGoogle, true)
		require.NoError(t, err)

		got, err := r.Get(domain.OAuthProviderGoogle)
		require.NoError(t, err)
		assert.Equal(t, domain.OAuthProviderGoogle, got.Name())
	})

	t.Run("disable an enabled provider", func(t *testing.T) {
		err := r.SetEnabled(domain.OAuthProviderGoogle, false)
		require.NoError(t, err)

		_, err = r.Get(domain.OAuthProviderGoogle)
		assert.ErrorIs(t, err, ErrProviderDisabled)
	})

	t.Run("set enabled on unregistered provider returns error", func(t *testing.T) {
		err := r.SetEnabled(domain.OAuthProviderApple, true)
		assert.ErrorIs(t, err, ErrProviderNotFound)
	})
}

func TestRegistry_ListEnabled(t *testing.T) {
	r := NewRegistry()
	r.Register(&stubProvider{name: domain.OAuthProviderGoogle}, true)
	r.Register(&stubProvider{name: domain.OAuthProviderGitHub}, false)
	r.Register(&stubProvider{name: domain.OAuthProviderApple}, true)

	enabled := r.ListEnabled()
	assert.Len(t, enabled, 2)
	assert.Contains(t, enabled, domain.OAuthProviderGoogle)
	assert.Contains(t, enabled, domain.OAuthProviderApple)
	assert.NotContains(t, enabled, domain.OAuthProviderGitHub)
}
