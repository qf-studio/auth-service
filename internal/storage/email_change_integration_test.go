package storage_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/secretbox"
	"github.com/qf-studio/auth-service/internal/storage"
)

func TestPostgresUserRepository_EmailChangeRevertWindow(t *testing.T) {
	tests := []struct {
		name string
		// confirm confirms the first change before the second request.
		confirm bool
		// expireRevert moves the first revert token's expiry into the past
		// before the second request.
		expireRevert bool
		wantErr      error
	}{
		{name: "confirmed change inside revert window blocks new request", confirm: true, wantErr: storage.ErrEmailRevertWindowActive},
		{name: "confirmed change past revert window allows new request", confirm: true, expireRevert: true},
		{name: "unconfirmed pending change is replaced", confirm: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := testPool(t)
			repo := storage.NewPostgresUserRepository(pool)
			ctx := context.Background()

			user := newTestUser()
			_, err := repo.Create(ctx, user)
			require.NoError(t, err)
			originalEmail := user.Email
			now := time.Now().UTC()

			require.NoError(t, repo.SetPendingEmailChange(ctx, domain.DefaultTenantID, user.ID, "b@test.com", "change-1", now.Add(24*time.Hour), "revert-1", now.Add(7*24*time.Hour)))
			if tt.confirm {
				_, err = repo.ConsumeEmailChangeToken(ctx, domain.DefaultTenantID, "change-1")
				require.NoError(t, err)
			}
			if tt.expireRevert {
				_, err = pool.Exec(ctx, `UPDATE users SET email_revert_token_expires_at = $1 WHERE id = $2`, now.Add(-time.Minute), user.ID)
				require.NoError(t, err)
			}

			err = repo.SetPendingEmailChange(ctx, domain.DefaultTenantID, user.ID, "c@test.com", "change-2", now.Add(24*time.Hour), "revert-2", now.Add(7*24*time.Hour))

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				pending, previous := queryPendingEmail(t, pool, user.ID)
				assert.Nil(t, pending, "rejected request must not leave a pending change")
				require.NotNil(t, previous)
				assert.Equal(t, originalEmail, *previous)

				// The original revert link still works and restores the old address.
				reverted, err := repo.ConsumeEmailRevertToken(ctx, domain.DefaultTenantID, "revert-1")
				require.NoError(t, err)
				assert.Equal(t, originalEmail, reverted.Email)
				assert.True(t, reverted.ForcePasswordChange)

				found, err := repo.FindByID(ctx, domain.DefaultTenantID, user.ID)
				require.NoError(t, err)
				assert.Equal(t, originalEmail, found.Email)
				assert.True(t, found.ForcePasswordChange, "revert must require a new password")
				return
			}

			require.NoError(t, err)
			pending, previous := queryPendingEmail(t, pool, user.ID)
			require.NotNil(t, pending)
			assert.Equal(t, "c@test.com", *pending)
			assert.Nil(t, previous, "previous_email from an expired window must be cleared")

			_, err = repo.ConsumeEmailChangeToken(ctx, domain.DefaultTenantID, "change-1")
			assert.ErrorIs(t, err, storage.ErrNotFound, "replaced change token must no longer work")

			// Reverting the new request only cancels it; it must not restore
			// an address from an earlier, expired change.
			before, err := repo.FindByID(ctx, domain.DefaultTenantID, user.ID)
			require.NoError(t, err)
			reverted, err := repo.ConsumeEmailRevertToken(ctx, domain.DefaultTenantID, "revert-2")
			require.NoError(t, err)
			assert.Equal(t, before.Email, reverted.Email)
			assert.True(t, reverted.ForcePasswordChange)
		})
	}
}

func TestPostgresUserRepository_EmailChangeRevertWindow_Concurrent(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		user := newTestUser()
		_, err := repo.Create(ctx, user)
		require.NoError(t, err)
		now := time.Now().UTC()
		changeTok, revertTok := user.ID+"-change", user.ID+"-revert"
		require.NoError(t, repo.SetPendingEmailChange(ctx, domain.DefaultTenantID, user.ID, user.ID+"-b@test.com", changeTok, now.Add(time.Hour), revertTok, now.Add(time.Hour)))

		var wg sync.WaitGroup
		var confirmErr, requestErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, confirmErr = repo.ConsumeEmailChangeToken(ctx, domain.DefaultTenantID, changeTok)
		}()
		go func() {
			defer wg.Done()
			requestErr = repo.SetPendingEmailChange(ctx, domain.DefaultTenantID, user.ID, user.ID+"-c@test.com", user.ID+"-change2", now.Add(time.Hour), user.ID+"-revert2", now.Add(time.Hour))
		}()
		wg.Wait()

		var revert *string
		require.NoError(t, pool.QueryRow(ctx, `SELECT email_revert_token FROM users WHERE id = $1`, user.ID).Scan(&revert))
		require.NotNil(t, revert)

		if confirmErr == nil {
			require.ErrorIs(t, requestErr, storage.ErrEmailRevertWindowActive)
			assert.Equal(t, secretbox.Digest(revertTok), *revert, "confirmed change's revert token must survive")
		} else {
			require.NoError(t, requestErr)
			assert.ErrorIs(t, confirmErr, storage.ErrNotFound)
			assert.Equal(t, secretbox.Digest(user.ID+"-revert2"), *revert)
		}
	}
}
