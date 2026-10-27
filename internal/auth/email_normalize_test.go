package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// GH-526: every service entry point normalizes (trim + lowercase) the email
// before it reaches the repository.

func TestRegister_NormalizesEmail(t *testing.T) {
	var createdUser *domain.User
	users := &mockUserRepository{
		createFn: func(_ context.Context, u *domain.User) (*domain.User, error) {
			createdUser = u
			return u, nil
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	info, err := svc.Register(context.Background(), "  Alice@X.com ", "valid-password-12345", "Alice")
	require.NoError(t, err)
	require.NotNil(t, createdUser)
	assert.Equal(t, "alice@x.com", createdUser.Email)
	assert.Equal(t, "alice@x.com", info.Email)
}

func TestRegister_CaseVariantDuplicateRejected(t *testing.T) {
	users := &mockUserRepository{
		createFn: func(_ context.Context, u *domain.User) (*domain.User, error) {
			if u.Email == "alice@x.com" {
				return nil, storage.ErrDuplicateEmail
			}
			return u, nil
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	// A case-variant duplicate is normalised and then treated like any other
	// duplicate: neutral success, no error (GH-528).
	info, err := svc.Register(context.Background(), "ALICE@x.com", "valid-password-12345", "Alice")
	require.NoError(t, err)
	assert.Equal(t, "alice@x.com", info.Email)
}

func TestLogin_NormalizesEmail(t *testing.T) {
	var lookedUp string
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, email string) (*domain.User, error) {
			lookedUp = email
			return nil, storage.ErrNotFound
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	_, err := svc.Login(context.Background(), " Alice@X.com\t", "any-password")
	require.ErrorIs(t, err, api.ErrUnauthorized)
	assert.Equal(t, "alice@x.com", lookedUp)
}

func TestResetPassword_NormalizesEmail(t *testing.T) {
	var lookedUp string
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, addr string) (*domain.User, error) {
			lookedUp = addr
			return &domain.User{ID: "user-1", Email: addr}, nil
		},
	}
	sender := &mockEmailSender{}
	svc := newIntegrationServiceWithDeps(t, users, sender, "https://app.example.com/reset")

	require.NoError(t, svc.ResetPassword(context.Background(), " Alice@X.com "))
	svc.waitBackground()
	assert.Equal(t, "alice@x.com", lookedUp)
	require.Len(t, sender.sent, 1)
	assert.Equal(t, "alice@x.com", sender.sent[0].To)
}

func TestRequestEmailChange_NormalizesEmail(t *testing.T) {
	row := &emailChangeRow{user: *emailChangeTestUser()}
	repo := row.repo()
	var lookedUp string
	repo.findByEmailFn = func(_ context.Context, addr string) (*domain.User, error) {
		lookedUp = addr
		return nil, storage.ErrNotFound
	}
	svc, _ := newMiniredisService(t, repo, &mockEmailSender{})

	res, err := svc.RequestEmailChange(context.Background(), "user-1", "  New@Example.COM ", "correct-password")
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", lookedUp)
	assert.Equal(t, "new@example.com", res.PendingEmail)
	require.NotNil(t, row.pendingEmail)
	assert.Equal(t, "new@example.com", *row.pendingEmail)
}

// The duplicate check must not be passable by changing case: the repository
// match is case-insensitive and the service passes the normalized address.
func TestRequestEmailChange_CaseVariantOfOtherUsersEmailRejected(t *testing.T) {
	row := &emailChangeRow{user: *emailChangeTestUser()}
	repo := row.repo()
	repo.findByEmailFn = func(_ context.Context, addr string) (*domain.User, error) {
		if addr == "taken@example.com" {
			return &domain.User{ID: "someone-else", Email: "Taken@Example.com"}, nil
		}
		return nil, storage.ErrNotFound
	}
	svc, _ := newMiniredisService(t, repo, &mockEmailSender{})

	_, err := svc.RequestEmailChange(context.Background(), "user-1", "TAKEN@example.com", "correct-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
	assert.Nil(t, row.pendingEmail)
}
