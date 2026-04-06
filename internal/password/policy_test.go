package password_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
)

func TestPolicyValidator_ValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		policy   domain.PasswordPolicy
		password string
		wantErr  error
	}{
		{
			name:     "valid password meets min length",
			policy:   domain.PasswordPolicy{MinLength: 15},
			password: "this-is-a-valid-password",
			wantErr:  nil,
		},
		{
			name:     "too short",
			policy:   domain.PasswordPolicy{MinLength: 15},
			password: "short",
			wantErr:  domain.ErrPasswordTooShort,
		},
		{
			name:     "too long",
			policy:   domain.PasswordPolicy{MinLength: 5, MaxLength: 10},
			password: "this-is-way-too-long",
			wantErr:  domain.ErrPasswordTooLong,
		},
		{
			name:     "exactly min length",
			policy:   domain.PasswordPolicy{MinLength: 5},
			password: "12345",
			wantErr:  nil,
		},
		{
			name:     "exactly max length",
			policy:   domain.PasswordPolicy{MinLength: 5, MaxLength: 10},
			password: "1234567890",
			wantErr:  nil,
		},
		{
			name:     "no max length means unlimited",
			policy:   domain.PasswordPolicy{MinLength: 5, MaxLength: 0},
			password: "a-very-long-password-that-should-be-fine-because-there-is-no-max",
			wantErr:  nil,
		},
		{
			name:     "default min length applied when zero",
			policy:   domain.PasswordPolicy{MinLength: 0},
			password: "short",
			wantErr:  domain.ErrPasswordTooShort,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := password.New(nil)
			pv := password.NewPolicyValidator(tt.policy, h)
			err := pv.ValidatePassword(tt.password)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPolicyValidator_IsExpired(t *testing.T) {
	tests := []struct {
		name              string
		maxAgeDays        int
		passwordChangedAt *time.Time
		want              bool
	}{
		{
			name:              "disabled (0 days)",
			maxAgeDays:        0,
			passwordChangedAt: timePtr(time.Now().Add(-365 * 24 * time.Hour)),
			want:              false,
		},
		{
			name:              "nil passwordChangedAt",
			maxAgeDays:        90,
			passwordChangedAt: nil,
			want:              false,
		},
		{
			name:              "not expired",
			maxAgeDays:        90,
			passwordChangedAt: timePtr(time.Now().Add(-30 * 24 * time.Hour)),
			want:              false,
		},
		{
			name:              "expired",
			maxAgeDays:        90,
			passwordChangedAt: timePtr(time.Now().Add(-100 * 24 * time.Hour)),
			want:              true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := password.New(nil)
			pv := password.NewPolicyValidator(domain.PasswordPolicy{MinLength: 15, MaxAgeDays: tt.maxAgeDays}, h)
			got := pv.IsExpired(tt.passwordChangedAt)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPolicyValidator_CheckHistory(t *testing.T) {
	h := password.New(nil)

	// Create a real hash for the password "old-password-12345".
	oldHash, err := h.Hash("old-password-12345")
	require.NoError(t, err)

	history := []domain.PasswordHistoryEntry{
		{ID: "1", UserID: "u1", PasswordHash: oldHash, CreatedAt: time.Now()},
	}

	t.Run("reused password detected", func(t *testing.T) {
		pv := password.NewPolicyValidator(domain.PasswordPolicy{MinLength: 15, HistoryCount: 5}, h)
		err := pv.CheckHistory("old-password-12345", history)
		assert.ErrorIs(t, err, domain.ErrPasswordReused)
	})

	t.Run("different password passes", func(t *testing.T) {
		pv := password.NewPolicyValidator(domain.PasswordPolicy{MinLength: 15, HistoryCount: 5}, h)
		err := pv.CheckHistory("new-password-67890", history)
		assert.NoError(t, err)
	})

	t.Run("history check disabled", func(t *testing.T) {
		pv := password.NewPolicyValidator(domain.PasswordPolicy{MinLength: 15, HistoryCount: 0}, h)
		err := pv.CheckHistory("old-password-12345", history)
		assert.NoError(t, err)
	})

	t.Run("empty history", func(t *testing.T) {
		pv := password.NewPolicyValidator(domain.PasswordPolicy{MinLength: 15, HistoryCount: 5}, h)
		err := pv.CheckHistory("any-password-12345", nil)
		assert.NoError(t, err)
	})

	t.Run("history count limits entries checked", func(t *testing.T) {
		// Only check 1 entry; the matching hash is second.
		otherHash, hashErr := h.Hash("other-password-12345")
		require.NoError(t, hashErr)
		twoEntryHistory := []domain.PasswordHistoryEntry{
			{ID: "2", UserID: "u1", PasswordHash: otherHash, CreatedAt: time.Now()},
			{ID: "1", UserID: "u1", PasswordHash: oldHash, CreatedAt: time.Now().Add(-time.Hour)},
		}

		pv := password.NewPolicyValidator(domain.PasswordPolicy{MinLength: 15, HistoryCount: 1}, h)
		err := pv.CheckHistory("old-password-12345", twoEntryHistory)
		assert.NoError(t, err, "should only check 1 entry, not find match in entry 2")
	})
}

func TestDefaultPolicy(t *testing.T) {
	p := password.DefaultPolicy()
	assert.Equal(t, domain.NistMinPasswordLength, p.MinLength)
	assert.Equal(t, 0, p.MaxLength)
	assert.Equal(t, 0, p.MaxAgeDays)
	assert.Equal(t, 0, p.HistoryCount)
}

func timePtr(t time.Time) *time.Time {
	return &t
}
