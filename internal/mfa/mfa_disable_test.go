package mfa

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// fakePasswordVerifier accepts exactly one password.
type fakePasswordVerifier struct {
	password string
}

func (f fakePasswordVerifier) Verify(pwd, _ string) (bool, error) {
	return pwd == f.password, nil
}

func TestDisableWithVerification(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Test", AccountName: "alice@test.com"})
	require.NoError(t, err)
	validCode, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	const (
		goodPassword = "current-password-123"
		backupCode   = "abcd-1234-efgh-5678"
	)

	tests := []struct {
		name         string
		password     string
		code         string
		codeType     string
		noVerifier   bool
		wantErr      error
		wantDeleted  bool
		wantConsumed bool
		wantFailures int
	}{
		{name: "valid totp disables", password: goodPassword, code: validCode, wantDeleted: true},
		{name: "valid totp with explicit type disables", password: goodPassword, code: validCode, codeType: "totp", wantDeleted: true},
		{name: "backup code disables and is consumed", password: goodPassword, code: backupCode, codeType: "backup", wantDeleted: true, wantConsumed: true},
		{name: "missing code rejected", password: goodPassword, code: "", wantErr: api.ErrUnauthorized, wantFailures: 1},
		{name: "wrong totp rejected", password: goodPassword, code: "000000", wantErr: api.ErrUnauthorized, wantFailures: 1},
		{name: "unknown backup code rejected", password: goodPassword, code: "ffff-ffff-ffff-ffff", codeType: "backup", wantErr: api.ErrUnauthorized, wantFailures: 1},
		{name: "wrong password rejected before code check", password: "wrong", code: validCode, wantErr: api.ErrInvalidPassword, wantFailures: 1},
		{name: "unsupported code type rejected", password: goodPassword, code: validCode, codeType: "sms", wantErr: api.ErrUnauthorized},
		{name: "no verifier configured fails closed", password: goodPassword, code: validCode, noVerifier: true, wantErr: api.ErrInternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var deleted, consumed bool
			var failures int
			repo := &mockMFARepository{
				getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
					return &domain.MFASecret{Secret: key.Secret(), Confirmed: true}, nil
				},
				consumeBackupFn: func(_ context.Context, _, codeHash string) error {
					if codeHash != hashBackupCode(backupCode) {
						return storage.ErrNotFound
					}
					consumed = true
					return nil
				},
				deleteSecretFn: func(_ context.Context, _ string) error {
					deleted = true
					return nil
				},
			}
			tokens := &mockMFATokenStore{
				recordFailedFn: func(_ context.Context, _ string) (int, error) {
					failures++
					return failures, nil
				},
			}
			users := &mockUserLookup{
				findByIDFn: func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
					return &domain.User{ID: id, PasswordHash: "stored-hash"}, nil
				},
			}
			svc := newTestServiceWithUsers(repo, tokens, &mockTokenIssuer{}, users)
			if !tt.noVerifier {
				svc.SetPasswordVerifier(fakePasswordVerifier{password: goodPassword})
			}

			err := svc.DisableWithVerification(context.Background(), "user-1", tt.password, tt.code, tt.codeType)
			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantDeleted, deleted, "secret deleted")
			assert.Equal(t, tt.wantConsumed, consumed, "backup code consumed")
			assert.Equal(t, tt.wantFailures, failures, "failed attempts recorded")
		})
	}
}

func TestDisableWithVerification_NotEnrolled(t *testing.T) {
	repo := &mockMFARepository{} // GetSecret returns ErrNotFound by default
	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	svc.SetPasswordVerifier(fakePasswordVerifier{password: "pw"})

	err := svc.DisableWithVerification(context.Background(), "user-1", "pw", "123456", "")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}
