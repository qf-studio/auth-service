package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestRefreshTokenSignature(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantSig   string
		wantOK    bool
		wantEmpty bool
	}{
		{
			name:    "well-formed",
			token:   "qf_rt_abc123.sig456",
			wantSig: "sig456",
			wantOK:  true,
		},
		{
			name:   "missing dot",
			token:  "qf_rt_abc123sig456",
			wantOK: false,
		},
		{
			name:   "empty signature",
			token:  "qf_rt_abc123.",
			wantOK: false,
		},
		{
			name:   "wrong prefix",
			token:  "qf_at_abc123.sig456",
			wantOK: false,
		},
		{
			name:   "empty token",
			token:  "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, ok := domain.RefreshTokenSignature(tt.token)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantSig, sig)
			} else {
				assert.Empty(t, sig)
			}
		})
	}
}
