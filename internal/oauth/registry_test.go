package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := NewRegistry()
	mock := &MockProvider{ProviderName: domain.OAuthProviderGoogle}
	reg.Register(mock)

	p, err := reg.Get(domain.OAuthProviderGoogle)
	require.NoError(t, err)
	assert.Equal(t, domain.OAuthProviderGoogle, p.Name())
}

func TestRegistry_GetUnregistered(t *testing.T) {
	reg := NewRegistry()

	_, err := reg.Get(domain.OAuthProviderGitHub)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not registered")
}

func TestRegistry_DuplicatePanics(t *testing.T) {
	reg := NewRegistry()
	mock := &MockProvider{ProviderName: domain.OAuthProviderApple}
	reg.Register(mock)

	assert.Panics(t, func() {
		reg.Register(&MockProvider{ProviderName: domain.OAuthProviderApple})
	})
}

func TestRegistry_List(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&MockProvider{ProviderName: domain.OAuthProviderGoogle})
	reg.Register(&MockProvider{ProviderName: domain.OAuthProviderGitHub})

	names := reg.List()
	assert.Len(t, names, 2)
	assert.Contains(t, names, domain.OAuthProviderGoogle)
	assert.Contains(t, names, domain.OAuthProviderGitHub)
}
