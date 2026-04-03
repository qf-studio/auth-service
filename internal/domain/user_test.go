package domain_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestUser_IsActive(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name   string
		user   domain.User
		active bool
	}{
		{
			name:   "active user",
			user:   domain.User{Locked: false, DeletedAt: nil},
			active: true,
		},
		{
			name:   "locked user",
			user:   domain.User{Locked: true, LockedAt: &now},
			active: false,
		},
		{
			name:   "soft-deleted user",
			user:   domain.User{Locked: false, DeletedAt: &now},
			active: false,
		},
		{
			name:   "locked and deleted",
			user:   domain.User{Locked: true, LockedAt: &now, DeletedAt: &now},
			active: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.active, tt.user.IsActive())
		})
	}
}

func TestRefreshTokenRecord_IsRevoked(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		rec     domain.RefreshTokenRecord
		revoked bool
	}{
		{
			name:    "not revoked",
			rec:     domain.RefreshTokenRecord{RevokedAt: nil},
			revoked: false,
		},
		{
			name:    "revoked",
			rec:     domain.RefreshTokenRecord{RevokedAt: &now},
			revoked: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.revoked, tt.rec.IsRevoked())
		})
	}
}

func TestRefreshTokenRecord_IsExpired(t *testing.T) {
	tests := []struct {
		name    string
		rec     domain.RefreshTokenRecord
		expired bool
	}{
		{
			name:    "not expired",
			rec:     domain.RefreshTokenRecord{ExpiresAt: time.Now().Add(time.Hour)},
			expired: false,
		},
		{
			name:    "expired",
			rec:     domain.RefreshTokenRecord{ExpiresAt: time.Now().Add(-time.Hour)},
			expired: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expired, tt.rec.IsExpired())
		})
	}
}
