package password

import (
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// DefaultPolicy returns the NIST SP 800-63-4 compliant default policy.
func DefaultPolicy() domain.PasswordPolicy {
	return domain.PasswordPolicy{
		MinLength:    domain.NistMinPasswordLength,
		MaxLength:    0, // no upper limit
		MaxAgeDays:   0, // no expiration
		HistoryCount: 0, // no reuse check
	}
}

// PolicyValidator checks passwords against a configurable PasswordPolicy.
type PolicyValidator struct {
	policy domain.PasswordPolicy
	hasher Hasher
}

// NewPolicyValidator creates a PolicyValidator with the given policy and hasher.
func NewPolicyValidator(policy domain.PasswordPolicy, hasher Hasher) *PolicyValidator {
	if policy.MinLength <= 0 {
		policy.MinLength = domain.NistMinPasswordLength
	}
	return &PolicyValidator{
		policy: policy,
		hasher: hasher,
	}
}

// ValidatePassword checks the password against the policy's length constraints.
func (v *PolicyValidator) ValidatePassword(password string) error {
	if len(password) < v.policy.MinLength {
		return domain.ErrPasswordTooShort
	}
	if v.policy.MaxLength > 0 && len(password) > v.policy.MaxLength {
		return domain.ErrPasswordTooLong
	}
	return nil
}

// IsExpired returns true if the password has exceeded the max age.
// Returns false when max age is disabled (0) or passwordChangedAt is nil.
func (v *PolicyValidator) IsExpired(passwordChangedAt *time.Time) bool {
	if v.policy.MaxAgeDays <= 0 || passwordChangedAt == nil {
		return false
	}
	maxAge := time.Duration(v.policy.MaxAgeDays) * 24 * time.Hour
	return time.Since(*passwordChangedAt) > maxAge
}

// CheckHistory returns domain.ErrPasswordReused if the new password matches any
// of the provided history entries. Returns nil if history checking is disabled
// or no match is found.
func (v *PolicyValidator) CheckHistory(newPassword string, history []domain.PasswordHistoryEntry) error {
	if v.policy.HistoryCount <= 0 || len(history) == 0 {
		return nil
	}

	// Only check up to HistoryCount entries (history should be ordered newest-first).
	limit := v.policy.HistoryCount
	if limit > len(history) {
		limit = len(history)
	}

	for _, entry := range history[:limit] {
		match, err := v.hasher.Verify(newPassword, entry.PasswordHash)
		if err != nil {
			// Skip entries with unparseable hashes (e.g. corrupted data).
			continue
		}
		if match {
			return domain.ErrPasswordReused
		}
	}
	return nil
}

// HistoryCount returns the configured number of history entries to retain.
func (v *PolicyValidator) HistoryCount() int {
	return v.policy.HistoryCount
}

// Policy returns the underlying password policy.
func (v *PolicyValidator) Policy() domain.PasswordPolicy {
	return v.policy
}
