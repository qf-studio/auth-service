package oauth

import (
	"context"
	"errors"
	"sync"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Provider is the interface that each OAuth/social-login provider must implement.
type Provider interface {
	// Name returns the provider identifier (e.g. "google", "github", "apple").
	Name() domain.OAuthProvider

	// AuthCodeURL returns the URL to redirect the user to for authorization.
	// state is the CSRF token; codeVerifier is the PKCE verifier whose challenge
	// will be included in the authorization request.
	AuthCodeURL(state, codeVerifier string) string

	// ExchangeCode exchanges an authorization code for user info.
	// codeVerifier is the PKCE verifier that was used when generating the auth URL.
	ExchangeCode(ctx context.Context, code, codeVerifier string) (*domain.OAuthUserInfo, error)
}

// Registry holds the set of registered OAuth providers and controls which are enabled.
type Registry struct {
	mu        sync.RWMutex
	providers map[domain.OAuthProvider]Provider
	enabled   map[domain.OAuthProvider]bool
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[domain.OAuthProvider]Provider),
		enabled:   make(map[domain.OAuthProvider]bool),
	}
}

// Register adds a provider to the registry. If enabled is true, the provider
// is immediately available for use.
func (r *Registry) Register(p Provider, enabled bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	r.providers[name] = p
	r.enabled[name] = enabled
}

// ErrProviderNotFound is returned when a requested provider is not registered.
var ErrProviderNotFound = errors.New("oauth provider not found")

// ErrProviderDisabled is returned when a registered provider is not enabled.
var ErrProviderDisabled = errors.New("oauth provider disabled")

// Get returns the provider for the given name, or an error if not found or disabled.
func (r *Registry) Get(name domain.OAuthProvider) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.providers[name]
	if !ok {
		return nil, ErrProviderNotFound
	}
	if !r.enabled[name] {
		return nil, ErrProviderDisabled
	}
	return p, nil
}

// SetEnabled enables or disables a provider by name.
func (r *Registry) SetEnabled(name domain.OAuthProvider, enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.providers[name]; !ok {
		return ErrProviderNotFound
	}
	r.enabled[name] = enabled
	return nil
}

// ListEnabled returns the names of all currently enabled providers.
func (r *Registry) ListEnabled() []domain.OAuthProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []domain.OAuthProvider
	for name, on := range r.enabled {
		if on {
			out = append(out, name)
		}
	}
	return out
}
