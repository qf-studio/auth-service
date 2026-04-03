package auth

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBreachChecker implements BreachChecker for testing.
type mockBreachChecker struct {
	isBreachedFn func(ctx context.Context, password string) (bool, error)
}

func (m *mockBreachChecker) IsBreached(ctx context.Context, password string) (bool, error) {
	if m.isBreachedFn != nil {
		return m.isBreachedFn(ctx, password)
	}
	return false, nil
}

func TestValidatePasswordPolicy(t *testing.T) {
	safeChecker := &mockBreachChecker{}
	breachedChecker := &mockBreachChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	errorChecker := &mockBreachChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, error) {
			return false, fmt.Errorf("HIBP API unavailable")
		},
	}

	tests := []struct {
		name       string
		password   string
		checker    BreachChecker
		wantErrs   int
		wantMsg    string
		wantGoErr  bool
	}{
		{
			name:     "valid password",
			password: "a-very-secure-password-here",
			checker:  safeChecker,
			wantErrs: 0,
		},
		{
			name:     "exactly 15 characters",
			password: "123456789012345",
			checker:  safeChecker,
			wantErrs: 0,
		},
		{
			name:     "too short - 14 chars",
			password: "12345678901234",
			checker:  safeChecker,
			wantErrs: 1,
			wantMsg:  "at least 15",
		},
		{
			name:     "empty password",
			password: "",
			checker:  safeChecker,
			wantErrs: 1,
			wantMsg:  "at least 15",
		},
		{
			name:     "too long - over 128 chars",
			password: strings.Repeat("a", 129),
			checker:  safeChecker,
			wantErrs: 1,
			wantMsg:  "at most 128",
		},
		{
			name:     "exactly 128 characters",
			password: strings.Repeat("a", 128),
			checker:  safeChecker,
			wantErrs: 0,
		},
		{
			name:     "unicode characters counted as runes",
			password: "пароль-длинный!!", // 16 runes, but more bytes
			checker:  safeChecker,
			wantErrs: 0,
		},
		{
			name:     "unicode too short by rune count",
			password: "пароль-коротки", // 14 runes
			checker:  safeChecker,
			wantErrs: 1,
			wantMsg:  "at least 15",
		},
		{
			name:     "emoji characters counted correctly",
			password: "🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐🔐", // 15 runes
			checker:  safeChecker,
			wantErrs: 0,
		},
		{
			name:     "breached password rejected",
			password: "a-very-secure-password-here",
			checker:  breachedChecker,
			wantErrs: 1,
			wantMsg:  "data breach",
		},
		{
			name:      "breach checker error propagates",
			password:  "a-very-secure-password-here",
			checker:   errorChecker,
			wantGoErr: true,
		},
		{
			name:     "nil checker skips breach check",
			password: "a-very-secure-password-here",
			checker:  nil,
			wantErrs: 0,
		},
		{
			name:     "breach check skipped when too short",
			password: "short",
			checker:  breachedChecker,
			wantErrs: 1,
			wantMsg:  "at least 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errs, err := ValidatePasswordPolicy(context.Background(), tt.password, tt.checker)
			if tt.wantGoErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Len(t, errs, tt.wantErrs)
			if tt.wantMsg != "" && len(errs) > 0 {
				assert.Contains(t, errs[0].Message, tt.wantMsg)
			}
		})
	}
}
