package auth

import (
	"context"
	"unicode/utf8"
)

const (
	// minPasswordLength is the minimum password length per NIST SP 800-63-4.
	// Uses rune count to correctly handle Unicode.
	minPasswordLength = 15

	// maxPasswordLength is the maximum password length to prevent DoS via hashing.
	maxPasswordLength = 128
)

// BreachChecker determines whether a password has appeared in known data breaches.
type BreachChecker interface {
	IsBreached(ctx context.Context, password string) (bool, error)
}

// ValidationError represents a single password policy violation.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// ValidatePasswordPolicy checks a password against NIST SP 800-63-4 policy:
// - Minimum 15 characters (rune count for Unicode)
// - Maximum 128 characters
// - No composition rules (uppercase, symbols, etc.)
// - Rejects passwords found in breach databases
func ValidatePasswordPolicy(ctx context.Context, password string, checker BreachChecker) ([]ValidationError, error) {
	var errs []ValidationError

	runeCount := utf8.RuneCountInString(password)

	if runeCount < minPasswordLength {
		errs = append(errs, ValidationError{
			Field:   "password",
			Message: "must be at least 15 characters",
		})
	}

	if runeCount > maxPasswordLength {
		errs = append(errs, ValidationError{
			Field:   "password",
			Message: "must be at most 128 characters",
		})
	}

	// Only check breach database if length constraints pass.
	if len(errs) == 0 && checker != nil {
		breached, err := checker.IsBreached(ctx, password)
		if err != nil {
			return nil, err
		}
		if breached {
			errs = append(errs, ValidationError{
				Field:   "password",
				Message: "this password has appeared in a data breach and cannot be used",
			})
		}
	}

	return errs, nil
}
