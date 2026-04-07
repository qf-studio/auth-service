package admin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
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
	now := time.Now()
	return &domain.TokenClaims{
		Subject:    "user-42",
		Roles:      []string{"user"},
		Scopes:     []string{"read:users", "write:users"},
		ClientType: domain.ClientTypeUser,
		TokenID:    "jti-123",
		ExpiresAt:  now.Add(15 * time.Minute),
		IssuedAt:   now.Add(-5 * time.Minute),
	}, nil
}

func (m *mockTokenValidator) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	if m.isRevokedFn != nil {
		return m.isRevokedFn(ctx, tokenID)
	}
	return false, nil
}

// --- Mock RefreshTokenLookup ---

type mockRefreshTokenLookup struct {
	findBySignatureFn func(ctx context.Context, tenantID uuid.UUID, signature string) (*domain.RefreshTokenRecord, error)
}

func (m *mockRefreshTokenLookup) FindBySignature(ctx context.Context, tenantID uuid.UUID, signature string) (*domain.RefreshTokenRecord, error) {
	if m.findBySignatureFn != nil {
		return m.findBySignatureFn(ctx, tenantID, signature)
	}
	now := time.Now()
	return &domain.RefreshTokenRecord{
		Signature: signature,
		UserID:    "user-99",
		ExpiresAt: now.Add(7 * 24 * time.Hour),
		CreatedAt: now.Add(-1 * time.Hour),
		RevokedAt: nil,
	}, nil
}

// --- Helpers ---

func newTestTokenService(validator *mockTokenValidator, lookup RefreshTokenLookup) *TokenService {
	return NewTokenService(validator, lookup, "auth-service", zap.NewNop(), audit.NopLogger{})
}

// --- Introspect: Access Token (Active) ---

func TestTokenService_Introspect_Active(t *testing.T) {
	svc := newTestTokenService(&mockTokenValidator{}, nil)

	resp, err := svc.Introspect(context.Background(), "qf_at_valid_token")
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, "user-42", resp.Sub)
	assert.Equal(t, "access_token", resp.TokenType)
	assert.Equal(t, "read:users write:users", resp.Scope)
	assert.Equal(t, "auth-service", resp.Iss)
	assert.Equal(t, "jti-123", resp.Jti)
	assert.Equal(t, "user", resp.ClientType)
	assert.NotZero(t, resp.Exp)
	assert.NotZero(t, resp.Iat)
}

// --- Introspect: Access Token (Invalid) ---

func TestTokenService_Introspect_Invalid(t *testing.T) {
	validator := &mockTokenValidator{
		validateTokenFn: func(_ context.Context, _ string) (*domain.TokenClaims, error) {
			return nil, fmt.Errorf("invalid token")
		},
	}
	svc := newTestTokenService(validator, nil)

	resp, err := svc.Introspect(context.Background(), "qf_at_invalid")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}

// --- Introspect: Access Token (Revoked) ---

func TestTokenService_Introspect_Revoked(t *testing.T) {
	validator := &mockTokenValidator{
		isRevokedFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	svc := newTestTokenService(validator, nil)

	resp, err := svc.Introspect(context.Background(), "qf_at_revoked")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}

// --- Introspect: Access Token (Revocation Check Error) ---

func TestTokenService_Introspect_RevocationError(t *testing.T) {
	validator := &mockTokenValidator{
		isRevokedFn: func(_ context.Context, _ string) (bool, error) {
			return false, fmt.Errorf("redis down")
		},
	}
	svc := newTestTokenService(validator, nil)

	_, err := svc.Introspect(context.Background(), "qf_at_some_token")
	require.Error(t, err)
}

// --- Introspect: Access Token (Real Exp/Iat from Claims) ---

func TestTokenService_Introspect_ExpIatFromClaims(t *testing.T) {
	fixedNow := time.Now().Truncate(time.Second)
	fixedExp := fixedNow.Add(15 * time.Minute)
	fixedIat := fixedNow.Add(-2 * time.Minute)

	validator := &mockTokenValidator{
		validateTokenFn: func(_ context.Context, _ string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{
				Subject:    "user-1",
				TokenID:    "jti-1",
				ClientType: domain.ClientTypeUser,
				ExpiresAt:  fixedExp,
				IssuedAt:   fixedIat,
			}, nil
		},
	}
	svc := newTestTokenService(validator, nil)

	resp, err := svc.Introspect(context.Background(), "qf_at_token")
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, fixedExp.Unix(), resp.Exp)
	assert.Equal(t, fixedIat.Unix(), resp.Iat)
}

// --- Introspect: Refresh Token (Active, DB Lookup) ---

func TestTokenService_Introspect_RefreshToken_Active(t *testing.T) {
	lookup := &mockRefreshTokenLookup{}
	svc := newTestTokenService(&mockTokenValidator{}, lookup)

	// Token format: qf_rt_<keyEncoded>.<sigEncoded>
	resp, err := svc.Introspect(context.Background(), "qf_rt_keypart.sigpart123")
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, "user-99", resp.Sub)
	assert.Equal(t, "refresh_token", resp.TokenType)
	assert.Equal(t, "auth-service", resp.Iss)
	assert.NotZero(t, resp.Exp)
	assert.NotZero(t, resp.Iat)
}

// --- Introspect: Refresh Token (Signature passed to DB lookup) ---

func TestTokenService_Introspect_RefreshToken_SignatureParsing(t *testing.T) {
	var capturedSig string
	lookup := &mockRefreshTokenLookup{
		findBySignatureFn: func(_ context.Context, _ uuid.UUID, sig string) (*domain.RefreshTokenRecord, error) {
			capturedSig = sig
			now := time.Now()
			return &domain.RefreshTokenRecord{
				Signature: sig,
				UserID:    "user-1",
				ExpiresAt: now.Add(time.Hour),
				CreatedAt: now,
			}, nil
		},
	}
	svc := newTestTokenService(&mockTokenValidator{}, lookup)

	_, err := svc.Introspect(context.Background(), "qf_rt_ABCDkeypart.XYZsigpart")
	require.NoError(t, err)
	assert.Equal(t, "XYZsigpart", capturedSig, "DB lookup should use the signature portion after the dot")
}

// --- Introspect: Refresh Token (Revoked) ---

func TestTokenService_Introspect_RefreshToken_Revoked(t *testing.T) {
	revokedAt := time.Now().Add(-1 * time.Hour)
	lookup := &mockRefreshTokenLookup{
		findBySignatureFn: func(_ context.Context, _ uuid.UUID, sig string) (*domain.RefreshTokenRecord, error) {
			return &domain.RefreshTokenRecord{
				Signature: sig,
				UserID:    "user-5",
				ExpiresAt: time.Now().Add(time.Hour),
				CreatedAt: time.Now().Add(-2 * time.Hour),
				RevokedAt: &revokedAt,
			}, nil
		},
	}
	svc := newTestTokenService(&mockTokenValidator{}, lookup)

	resp, err := svc.Introspect(context.Background(), "qf_rt_key.sig")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}

// --- Introspect: Refresh Token (Expired) ---

func TestTokenService_Introspect_RefreshToken_Expired(t *testing.T) {
	lookup := &mockRefreshTokenLookup{
		findBySignatureFn: func(_ context.Context, _ uuid.UUID, sig string) (*domain.RefreshTokenRecord, error) {
			return &domain.RefreshTokenRecord{
				Signature: sig,
				UserID:    "user-6",
				ExpiresAt: time.Now().Add(-1 * time.Hour), // already expired
				CreatedAt: time.Now().Add(-8 * 24 * time.Hour),
			}, nil
		},
	}
	svc := newTestTokenService(&mockTokenValidator{}, lookup)

	resp, err := svc.Introspect(context.Background(), "qf_rt_key.sig")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}

// --- Introspect: Refresh Token (Not Found) ---

func TestTokenService_Introspect_RefreshToken_NotFound(t *testing.T) {
	lookup := &mockRefreshTokenLookup{
		findBySignatureFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.RefreshTokenRecord, error) {
			return nil, fmt.Errorf("sig unknown: %w", storage.ErrNotFound)
		},
	}
	svc := newTestTokenService(&mockTokenValidator{}, lookup)

	resp, err := svc.Introspect(context.Background(), "qf_rt_key.sig")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}

// --- Introspect: Refresh Token (Malformed, No Dot) ---

func TestTokenService_Introspect_RefreshToken_Malformed(t *testing.T) {
	svc := newTestTokenService(&mockTokenValidator{}, &mockRefreshTokenLookup{})

	resp, err := svc.Introspect(context.Background(), "qf_rt_nodothere")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}

// --- Introspect: Refresh Token (No DB Repository) ---

func TestTokenService_Introspect_RefreshToken_NoRepository(t *testing.T) {
	// nil refreshTokens means refresh introspection is not supported.
	svc := newTestTokenService(&mockTokenValidator{}, nil)

	resp, err := svc.Introspect(context.Background(), "qf_rt_key.sig")
	require.NoError(t, err)
	assert.False(t, resp.Active)
}
