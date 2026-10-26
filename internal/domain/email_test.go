package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"already normalized", "alice@x.com", "alice@x.com"},
		{"mixed case", "Alice@X.com", "alice@x.com"},
		{"upper case", "ALICE@X.COM", "alice@x.com"},
		{"surrounding whitespace", "  alice@x.com\t\n", "alice@x.com"},
		{"whitespace and case", " Alice@X.com ", "alice@x.com"},
		{"empty", "", ""},
		{"only whitespace", "   ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, domain.NormalizeEmail(tt.in))
		})
	}
}
