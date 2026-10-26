package auth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// emailChangeRow is an in-memory stand-in for the email-change columns of a
// users row. Its methods mirror PostgresUserRepository's semantics (the row
// lock is a mutex) so the service flow can be exercised end to end; the SQL
// itself is covered by the storage integration tests.
type emailChangeRow struct {
	mu                  sync.Mutex
	user                domain.User
	pendingEmail        *string
	changeToken         string
	revertToken         string
	revertExpiresAt     time.Time
	previousEmail       *string
	forcePasswordChange bool
}

func (r *emailChangeRow) setPending(userID, pendingEmail, changeToken, revertToken string, revertExpiresAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if userID != r.user.ID {
		return fmt.Errorf("user %s: %w", userID, storage.ErrNotFound)
	}
	if r.previousEmail != nil && r.revertToken != "" && time.Now().Before(r.revertExpiresAt) {
		return fmt.Errorf("user %s: %w", userID, storage.ErrEmailRevertWindowActive)
	}
	r.pendingEmail = &pendingEmail
	r.changeToken = changeToken
	r.revertToken, r.revertExpiresAt = revertToken, revertExpiresAt
	r.previousEmail = nil
	return nil
}

func (r *emailChangeRow) consumeChange(token string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if token == "" || token != r.changeToken {
		return nil, fmt.Errorf("email change token: %w", storage.ErrNotFound)
	}
	prev := r.user.Email
	r.user.Email = *r.pendingEmail
	r.previousEmail = &prev
	r.pendingEmail = nil
	r.changeToken = ""
	u := r.user
	return &u, nil
}

func (r *emailChangeRow) consumeRevert(token string) (*domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if token == "" || token != r.revertToken {
		return nil, fmt.Errorf("email revert token: %w", storage.ErrNotFound)
	}
	if r.previousEmail != nil {
		r.user.Email = *r.previousEmail
	}
	r.previousEmail, r.pendingEmail = nil, nil
	r.changeToken, r.revertToken = "", ""
	r.forcePasswordChange = true
	u := r.user
	u.ForcePasswordChange = true
	return &u, nil
}

func (r *emailChangeRow) repo() *mockUserRepository {
	return &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			r.mu.Lock()
			defer r.mu.Unlock()
			u := r.user
			return &u, nil
		},
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
		setPendingEmailChangeFn: func(_ context.Context, userID, pendingEmail, changeToken string, _ time.Time, revertToken string, revertExpiresAt time.Time) error {
			return r.setPending(userID, pendingEmail, changeToken, revertToken, revertExpiresAt)
		},
		consumeEmailChangeTokenFn: func(_ context.Context, token string) (*domain.User, error) {
			return r.consumeChange(token)
		},
		consumeEmailRevertTokenFn: func(_ context.Context, token string) (*domain.User, error) {
			return r.consumeRevert(token)
		},
	}
}

func TestRequestEmailChange_RevertWindow(t *testing.T) {
	tests := []struct {
		name string
		// confirmFirst confirms the A->B change before the second request.
		confirmFirst bool
		// expireRevertWindow moves the first revert token's expiry into the past.
		expireRevertWindow bool
		wantErr            error
	}{
		{name: "confirmed change inside revert window rejects new request", confirmFirst: true, wantErr: api.ErrEmailChangeRevertWindowOpen},
		{name: "confirmed change past revert window allows new request", confirmFirst: true, expireRevertWindow: true},
		{name: "unconfirmed pending change is replaced", confirmFirst: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			row := &emailChangeRow{user: *emailChangeTestUser()}
			sender := &mockEmailSender{}
			svc, _ := newMiniredisService(t, row.repo(), sender)
			ctx := context.Background()

			_, err := svc.RequestEmailChange(ctx, "user-1", "b@example.com", "correct-password")
			require.NoError(t, err)
			firstChange, firstRevert := row.changeToken, row.revertToken

			if tt.confirmFirst {
				require.NoError(t, svc.ConfirmEmailChange(ctx, firstChange))
				require.Equal(t, "b@example.com", row.user.Email)
			}
			if tt.expireRevertWindow {
				row.revertExpiresAt = time.Now().Add(-time.Minute)
			}

			sentBefore := len(sender.sent)
			_, err = svc.RequestEmailChange(ctx, "user-1", "c@example.com", "correct-password")

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Len(t, sender.sent, sentBefore, "no mail is sent for a rejected request")
				assert.Equal(t, firstRevert, row.revertToken, "original revert token must be kept")

				// The original revert link still restores the old address.
				require.NoError(t, svc.RevertEmailChange(ctx, firstRevert))
				assert.Equal(t, "alice@example.com", row.user.Email)
				assert.True(t, row.forcePasswordChange)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, row.pendingEmail)
			assert.Equal(t, "c@example.com", *row.pendingEmail)
			assert.NotEqual(t, firstChange, row.changeToken, "pending change token is replaced")
			assert.NotEqual(t, firstRevert, row.revertToken)
			assert.Nil(t, row.previousEmail, "a stale previous_email must not survive a new request")
		})
	}
}

func TestRequestEmailChange_RevertWindowConcurrentConfirm(t *testing.T) {
	// A confirmation racing a new request: whichever order the row lock
	// serializes them in, a request that lands after the confirmation must
	// be rejected and the confirmed change's revert token must survive.
	for i := 0; i < 20; i++ {
		row := &emailChangeRow{user: *emailChangeTestUser()}
		svc, _ := newMiniredisService(t, row.repo(), &mockEmailSender{})
		ctx := context.Background()

		_, err := svc.RequestEmailChange(ctx, "user-1", "b@example.com", "correct-password")
		require.NoError(t, err)
		changeToken, revertToken := row.changeToken, row.revertToken

		var wg sync.WaitGroup
		wg.Add(2)
		var confirmErr, requestErr error
		go func() { defer wg.Done(); confirmErr = svc.ConfirmEmailChange(ctx, changeToken) }()
		go func() {
			defer wg.Done()
			_, requestErr = svc.RequestEmailChange(ctx, "user-1", "c@example.com", "correct-password")
		}()
		wg.Wait()

		if confirmErr == nil {
			require.ErrorIs(t, requestErr, api.ErrEmailChangeRevertWindowOpen)
			assert.Equal(t, "b@example.com", row.user.Email)
			assert.Equal(t, revertToken, row.revertToken)
		} else {
			require.NoError(t, requestErr)
			assert.ErrorIs(t, confirmErr, api.ErrNotFound)
			assert.Equal(t, "alice@example.com", row.user.Email)
		}
	}
}

func TestRevertEmailChange_SetsForcePasswordChange(t *testing.T) {
	row := &emailChangeRow{user: *emailChangeTestUser()}
	var revoked string
	svc, _ := newMiniredisService(t, row.repo(), &mockEmailSender{})
	svc.tokens = &mockRefreshTokenRepository{
		revokeAllForUser: func(_ context.Context, userID string) error {
			revoked = userID
			return nil
		},
	}
	ctx := context.Background()

	_, err := svc.RequestEmailChange(ctx, "user-1", "b@example.com", "correct-password")
	require.NoError(t, err)
	require.NoError(t, svc.ConfirmEmailChange(ctx, row.changeToken))
	require.NoError(t, svc.RevertEmailChange(ctx, row.revertToken))

	assert.Equal(t, "alice@example.com", row.user.Email)
	assert.True(t, row.forcePasswordChange)
	assert.Equal(t, "user-1", revoked)
}
