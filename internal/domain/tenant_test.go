package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTenant_IsActive(t *testing.T) {
	tests := []struct {
		name   string
		active bool
		want   bool
	}{
		{"active tenant", true, true},
		{"inactive tenant", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant := &Tenant{Active: tt.active}
			assert.Equal(t, tt.want, tenant.IsActive())
		})
	}
}

func TestTenant_EffectivePasswordPolicy(t *testing.T) {
	defaults := PasswordPolicy{
		MinLength:    15,
		MaxLength:    128,
		MaxAgeDays:   0,
		HistoryCount: 5,
	}

	t.Run("no overrides returns defaults", func(t *testing.T) {
		tenant := &Tenant{}
		got := tenant.EffectivePasswordPolicy(defaults)
		assert.Equal(t, defaults, got)
	})

	t.Run("partial overrides", func(t *testing.T) {
		minLen := 20
		histCount := 10
		tenant := &Tenant{
			PasswordMinLength:    &minLen,
			PasswordHistoryCount: &histCount,
		}
		got := tenant.EffectivePasswordPolicy(defaults)
		assert.Equal(t, 20, got.MinLength)
		assert.Equal(t, 128, got.MaxLength)    // default
		assert.Equal(t, 0, got.MaxAgeDays)     // default
		assert.Equal(t, 10, got.HistoryCount)
	})

	t.Run("all overrides", func(t *testing.T) {
		minLen := 8
		maxLen := 64
		maxAge := 90
		histCount := 3
		tenant := &Tenant{
			PasswordMinLength:    &minLen,
			PasswordMaxLength:    &maxLen,
			PasswordMaxAgeDays:   &maxAge,
			PasswordHistoryCount: &histCount,
		}
		got := tenant.EffectivePasswordPolicy(defaults)
		assert.Equal(t, PasswordPolicy{
			MinLength:    8,
			MaxLength:    64,
			MaxAgeDays:   90,
			HistoryCount: 3,
		}, got)
	})
}
