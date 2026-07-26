package domain_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestConsentGrant_IsActive(t *testing.T) {
	t.Run("active when RevokedAt is nil", func(t *testing.T) {
		g := &domain.ConsentGrant{}
		assert.True(t, g.IsActive())
	})

	t.Run("inactive when RevokedAt is set", func(t *testing.T) {
		revoked := time.Now().UTC()
		g := &domain.ConsentGrant{RevokedAt: &revoked}
		assert.False(t, g.IsActive())
	})
}

func TestConsentGrant_CoversScopes(t *testing.T) {
	tests := []struct {
		name      string
		granted   []string
		requested []string
		want      bool
	}{
		{"exact match", []string{"openid", "profile"}, []string{"openid", "profile"}, true},
		{"superset covers subset", []string{"openid", "profile", "email"}, []string{"openid"}, true},
		{"missing scope not covered", []string{"openid"}, []string{"openid", "email"}, false},
		{"empty requested always covered", []string{"openid"}, nil, true},
		{"empty granted does not cover non-empty request", nil, []string{"openid"}, false},
		{"empty granted covers empty request", nil, nil, true},
		{"disjoint scopes not covered", []string{"openid"}, []string{"email"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &domain.ConsentGrant{Scopes: tt.granted}
			assert.Equal(t, tt.want, g.CoversScopes(tt.requested))
		})
	}
}
