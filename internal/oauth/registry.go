package oauth

import (
	"fmt"
	"sync"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Registry holds all registered and enabled OAuth providers, keyed by name.
type Registry struct {
	mu        sync.RWMutex
	providers map[domain.OAuthProviderType]Provider
}

// NewRegistry creates an empty provider registry.
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[domain.OAuthProviderType]Provider),
	}
}

// Register adds a provider to the registry. Panics on duplicate registration.
func (r *Registry) Register(p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if _, exists := r.providers[name]; exists {
		panic(fmt.Sprintf("oauth: duplicate provider registration: %s", name))
	}
	r.providers[name] = p
}

// Get returns the provider for the given name, or an error if not registered.
func (r *Registry) Get(name domain.OAuthProviderType) (Provider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[name]
	if !ok {
		return nil, fmt.Errorf("oauth provider %q not registered or not enabled", name)
	}
	return p, nil
}

// List returns the names of all registered providers.
func (r *Registry) List() []domain.OAuthProviderType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]domain.OAuthProviderType, 0, len(r.providers))
	for name := range r.providers {
		names = append(names, name)
	}
	return names
}
