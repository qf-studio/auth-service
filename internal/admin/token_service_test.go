package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/admin"
	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Mock TokenValidator ---

type mockTokenValidator struct {
	validateFn func(ctx context.Context, rawToken string) (*domain.TokenClaims, error)
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error) {
	if m.validateFn != nil {
		return m.validateFn(ctx, rawToken)
	}
	return nil, errors.New("token invalid")
}

// --- Mock RefreshTokenFinder ---

type mockRefreshFinder struct {
	findFn func(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error)
}

func (m *mockRefreshFinder) FindBySignature(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error) {
	if m.findFn != nil {
		return m.findFn(ctx, signature)
	}
	return nil, storage.ErrNotFound
}

// --- Helpers ---

func newTokenSvc(validator admin.TokenValidator, finder admin.RefreshTokenFinder) *admin.TokenService {
	return admin.NewTokenService(validator, finder)
}

func validClaims() *domain.TokenClaims {
	return &domain.TokenClaims{
		Subject:    "user-42",
		Roles:      []string{"user"},
		Scopes:     []string{"read:users", "write:users"},
		ClientType: domain.ClientTypeUser,
		TokenID:    "jti-abc-123",
	}
}

// --- Introspect ---

func TestTokenService_Introspect_AccessToken(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		validateFn  func(ctx context.Context, rawToken string) (*domain.TokenClaims, error)
		wantActive  bool
		wantSub     string
		wantJti     string
		wantScope   string
		wantType    string
		wantErr     bool
	}{
		{
			name:  "valid access token returns active with claims",
			token: "qf_at_valid.jwt.here",
			validateFn: func(_ context.Context, rawToken string) (*domain.TokenClaims, error) {
				assert.Equal(t, "valid.jwt.here", rawToken, "prefix must be stripped before calling validator")
				return validClaims(), nil
			},
			wantActive: true,
			wantSub:    "user-42",
			wantJti:    "jti-abc-123",
			wantScope:  "read:users write:users",
			wantType:   "access_token",
		},
		{
			name:  "expired access token returns inactive without error",
			token: "qf_at_expired.jwt",
			validateFn: func(_ context.Context, _ string) (*domain.TokenClaims, error) {
				return nil, errors.New("token is expired")
			},
			wantActive: false,
		},
		{
			name:  "invalid JWT returns inactive without error",
			token: "qf_at_not_a_real_jwt",
			validateFn: func(_ context.Context, _ string) (*domain.TokenClaims, error) {
				return nil, errors.New("invalid token")
			},
			wantActive: false,
		},
		{
			name:  "empty scopes produces empty scope string",
			token: "qf_at_noscope.jwt",
			validateFn: func(_ context.Context, _ string) (*domain.TokenClaims, error) {
				c := validClaims()
				c.Scopes = nil
				return c, nil
			},
			wantActive: true,
			wantSub:    "user-42",
			wantJti:    "jti-abc-123",
			wantScope:  "",
			wantType:   "access_token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &mockTokenValidator{validateFn: tt.validateFn}
			finder := &mockRefreshFinder{}

			result, err := newTokenSvc(validator, finder).Introspect(context.Background(), tt.token)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantActive, result.Active)

			if tt.wantActive {
				assert.Equal(t, tt.wantSub, result.Sub)
				assert.Equal(t, tt.wantJti, result.Jti)
				assert.Equal(t, tt.wantScope, result.Scope)
				assert.Equal(t, tt.wantType, result.TokenType)
			} else {
				assert.Empty(t, result.Sub, "inactive token must not expose claims")
			}
		})
	}
}

func TestTokenService_Introspect_RefreshToken(t *testing.T) {
	futureExpiry := time.Now().Add(24 * time.Hour)
	pastExpiry := time.Now().Add(-1 * time.Hour)
	revokedAt := time.Now().Add(-30 * time.Minute)

	tests := []struct {
		name       string
		token      string
		findFn     func(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error)
		wantActive bool
		wantSub    string
		wantType   string
		wantErr    bool
	}{
		{
			name:  "active refresh token returns active with subject",
			token: "qf_rt_key.sig",
			findFn: func(_ context.Context, sig string) (*domain.RefreshTokenRecord, error) {
				assert.Equal(t, "qf_rt_key.sig", sig, "full token must be passed to finder")
				return &domain.RefreshTokenRecord{
					Signature: sig,
					UserID:    "user-99",
					ExpiresAt: futureExpiry,
					CreatedAt: time.Now().Add(-1 * time.Hour),
				}, nil
			},
			wantActive: true,
			wantSub:    "user-99",
			wantType:   "refresh_token",
		},
		{
			name:  "revoked refresh token returns inactive",
			token: "qf_rt_revoked.sig",
			findFn: func(_ context.Context, _ string) (*domain.RefreshTokenRecord, error) {
				return &domain.RefreshTokenRecord{
					Signature: "qf_rt_revoked.sig",
					UserID:    "user-10",
					ExpiresAt: futureExpiry,
					CreatedAt: time.Now().Add(-2 * time.Hour),
					RevokedAt: &revokedAt,
				}, nil
			},
			wantActive: false,
		},
		{
			name:  "expired refresh token returns inactive",
			token: "qf_rt_expired.sig",
			findFn: func(_ context.Context, _ string) (*domain.RefreshTokenRecord, error) {
				return &domain.RefreshTokenRecord{
					Signature: "qf_rt_expired.sig",
					UserID:    "user-11",
					ExpiresAt: pastExpiry,
					CreatedAt: time.Now().Add(-48 * time.Hour),
				}, nil
			},
			wantActive: false,
		},
		{
			name:  "unknown refresh token returns inactive without error",
			token: "qf_rt_unknown.sig",
			findFn: func(_ context.Context, _ string) (*domain.RefreshTokenRecord, error) {
				return nil, storage.ErrNotFound
			},
			wantActive: false,
		},
		{
			name:  "database error returns error",
			token: "qf_rt_dbfail.sig",
			findFn: func(_ context.Context, _ string) (*domain.RefreshTokenRecord, error) {
				return nil, errors.New("connection lost")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &mockTokenValidator{}
			finder := &mockRefreshFinder{findFn: tt.findFn}

			result, err := newTokenSvc(validator, finder).Introspect(context.Background(), tt.token)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantActive, result.Active)
			assert.Equal(t, "refresh_token", result.TokenType)

			if tt.wantActive {
				assert.Equal(t, tt.wantSub, result.Sub)
				assert.Greater(t, result.Exp, int64(0))
				assert.Greater(t, result.Iat, int64(0))
			} else {
				assert.Empty(t, result.Sub, "inactive token must not expose subject")
			}
		})
	}
}

func TestTokenService_Introspect_UnknownPrefix(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "bare JWT without prefix", token: "eyJhbGciOiJFUzI1NiJ9.payload.sig"},
		{name: "empty string", token: ""},
		{name: "random string", token: "not-a-token-at-all"},
		{name: "partial prefix", token: "qf_raw_data"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := &mockTokenValidator{}
			finder := &mockRefreshFinder{}

			result, err := newTokenSvc(validator, finder).Introspect(context.Background(), tt.token)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.False(t, result.Active)
		})
	}
}

func TestTokenService_Introspect_ActiveRefreshToken_ExposesTimestamps(t *testing.T) {
	issued := time.Now().Add(-30 * time.Minute).UTC().Truncate(time.Second)
	expires := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)

	finder := &mockRefreshFinder{
		findFn: func(_ context.Context, _ string) (*domain.RefreshTokenRecord, error) {
			return &domain.RefreshTokenRecord{
				Signature: "qf_rt_test.sig",
				UserID:    "user-ts",
				ExpiresAt: expires,
				CreatedAt: issued,
			}, nil
		},
	}

	result, err := newTokenSvc(&mockTokenValidator{}, finder).Introspect(context.Background(), "qf_rt_test.sig")

	require.NoError(t, err)
	assert.True(t, result.Active)
	assert.Equal(t, expires.Unix(), result.Exp)
	assert.Equal(t, issued.Unix(), result.Iat)
}

// --- Compile-time interface check ---

func TestTokenService_ImplementsInterface(t *testing.T) {
	var _ api.AdminTokenService = (*admin.TokenService)(nil)
}

func TestUserService_ImplementsInterface(t *testing.T) {
	var _ api.AdminUserService = (*admin.UserService)(nil)
}

func TestClientService_ImplementsInterface(t *testing.T) {
	var _ api.AdminClientService = (*admin.ClientService)(nil)
}
