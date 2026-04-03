package admin

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
)

// --- Mock TokenValidator ---

type mockTokenValidator struct {
	validateTokenFn func(ctx context.Context, rawToken string) (*domain.TokenClaims, error)
	isRevokedFn     func(ctx context.Context, tokenID string) (bool, error)
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error) {
	if m.validateTokenFn != nil {
		return m.validateTokenFn(ctx, rawToken)
	}
	return &domain.TokenClaims{
		Subject:    "user-42",
		Roles:      []string{"user"},
		Scopes:     []string{"read:users", "write:users"},
		ClientType: domain.ClientTypeUser,
		TokenID:    "jti-123",
	}, nil
}

func (m *mockTokenValidator) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	if m.isRevokedFn != nil {
		return m.isRevokedFn(ctx, tokenID)
	}
	return false, nil
}

func newTestTokenService(validator *mockTokenValidator) *TokenService {
	return NewTokenService(validator, "auth-service", zap.NewNop())
}

// --- Introspect: Active Token ---

func TestTokenService_Introspect_Active(t *testing.T) {
	svc := newTestTokenService(&mockTokenValidator{})

	resp, err := svc.Introspect(context.Background(), "qf_at_valid_token")
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, "user-42", resp.Sub)
	assert.Equal(t, "access_token", resp.TokenType)
	assert.Equal(t, "read:users write:users", resp.Scope)
	assert.Equal(t, "auth-service", resp.Iss)
	assert.Equal(t, "jti-123", resp.Jti)
	assert.Equal(t, "user", resp.ClientType)
}

// --- Introspect: Invalid Token ---

func TestTokenService_Introspect_Invalid(t *testing.T) {
	validator := &mockTokenValidator{
		validateTokenFn: func(_ context.Context, _ string) (*domain.TokenClaims, error) {
			return nil, fmt.Errorf("invalid token")
		},
	}
	svc := newTestTokenService(validator)

	resp, err := svc.Introspect(context.Background(), "qf_at_invalid")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}

// --- Introspect: Revoked Token ---

func TestTokenService_Introspect_Revoked(t *testing.T) {
	validator := &mockTokenValidator{
		isRevokedFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	svc := newTestTokenService(validator)

	resp, err := svc.Introspect(context.Background(), "qf_at_revoked")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}

// --- Introspect: Revocation Check Error ---

func TestTokenService_Introspect_RevocationError(t *testing.T) {
	validator := &mockTokenValidator{
		isRevokedFn: func(_ context.Context, _ string) (bool, error) {
			return false, fmt.Errorf("redis down")
		},
	}
	svc := newTestTokenService(validator)

	_, err := svc.Introspect(context.Background(), "qf_at_some_token")
	require.Error(t, err)
}

// --- Introspect: Refresh Token Type ---

func TestTokenService_Introspect_RefreshToken(t *testing.T) {
	svc := newTestTokenService(&mockTokenValidator{})

	resp, err := svc.Introspect(context.Background(), "qf_rt_refresh_token")
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, "refresh_token", resp.TokenType)
}
