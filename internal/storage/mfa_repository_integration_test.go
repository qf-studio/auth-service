package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ────────────────────────────────────────────────────────────────────────────
// MFARepository tests
// ────────────────────────────────────────────────────────────────────────────

func newTestMFASecret(userID string) *domain.MFASecret {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.MFASecret{
		ID:        uuid.New().String(),
		UserID:    userID,
		Type:      "totp",
		Secret:    "JBSWY3DPEHPK3PXP",
		Confirmed: false,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func newTestBackupCodes(userID string, n int) []domain.BackupCode {
	now := time.Now().UTC().Truncate(time.Microsecond)
	codes := make([]domain.BackupCode, n)
	for i := range codes {
		codes[i] = domain.BackupCode{
			ID:        uuid.New().String(),
			UserID:    userID,
			CodeHash:  "hash_" + uuid.New().String()[:8],
			CreatedAt: now,
		}
	}
	return codes
}

func TestPostgresMFARepository_SaveSecret(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	secret := newTestMFASecret(user.ID)
	created, err := repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	assert.Equal(t, secret.ID, created.ID)
	assert.Equal(t, secret.UserID, created.UserID)
	assert.Equal(t, "totp", created.Type)
	assert.Equal(t, secret.Secret, created.Secret)
	assert.False(t, created.Confirmed)
	assert.Nil(t, created.ConfirmedAt)
	assert.Nil(t, created.DeletedAt)
}

func TestPostgresMFARepository_SaveSecret_DuplicateType(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	secret1 := newTestMFASecret(user.ID)
	_, err = repo.SaveSecret(ctx, secret1)
	require.NoError(t, err)

	secret2 := newTestMFASecret(user.ID)
	_, err = repo.SaveSecret(ctx, secret2)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateMFA)
}

func TestPostgresMFARepository_GetSecret(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	secret := newTestMFASecret(user.ID)
	_, err = repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	got, err := repo.GetSecret(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, secret.ID, got.ID)
	assert.Equal(t, secret.Secret, got.Secret)
}

func TestPostgresMFARepository_GetSecret_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	_, err := repo.GetSecret(ctx, "nonexistent-user-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_ConfirmSecret(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	secret := newTestMFASecret(user.ID)
	_, err = repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	err = repo.ConfirmSecret(ctx, user.ID)
	require.NoError(t, err)

	got, err := repo.GetSecret(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, got.Confirmed)
	assert.NotNil(t, got.ConfirmedAt)
}

func TestPostgresMFARepository_ConfirmSecret_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	err := repo.ConfirmSecret(ctx, "nonexistent-user-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_DeleteSecret(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	secret := newTestMFASecret(user.ID)
	_, err = repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	err = repo.DeleteSecret(ctx, user.ID)
	require.NoError(t, err)

	// Should not be found after deletion.
	_, err = repo.GetSecret(ctx, user.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_DeleteSecret_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	err := repo.DeleteSecret(ctx, "nonexistent-user-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_SaveAndGetBackupCodes(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	codes := newTestBackupCodes(user.ID, 10)
	err = repo.SaveBackupCodes(ctx, user.ID, codes)
	require.NoError(t, err)

	got, err := repo.GetBackupCodes(ctx, user.ID)
	require.NoError(t, err)
	assert.Len(t, got, 10)

	for _, c := range got {
		assert.Equal(t, user.ID, c.UserID)
		assert.False(t, c.Used)
		assert.Nil(t, c.UsedAt)
	}
}

func TestPostgresMFARepository_SaveBackupCodes_ReplacesUnused(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Save initial codes.
	codes1 := newTestBackupCodes(user.ID, 10)
	err = repo.SaveBackupCodes(ctx, user.ID, codes1)
	require.NoError(t, err)

	// Consume one code.
	err = repo.ConsumeBackupCode(ctx, user.ID, codes1[0].CodeHash)
	require.NoError(t, err)

	// Save new set — should replace only the 9 unused codes.
	codes2 := newTestBackupCodes(user.ID, 10)
	err = repo.SaveBackupCodes(ctx, user.ID, codes2)
	require.NoError(t, err)

	got, err := repo.GetBackupCodes(ctx, user.ID)
	require.NoError(t, err)
	// 1 used from first batch + 10 new = 11
	assert.Len(t, got, 11)
}

func TestPostgresMFARepository_ConsumeBackupCode(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	codes := newTestBackupCodes(user.ID, 3)
	err = repo.SaveBackupCodes(ctx, user.ID, codes)
	require.NoError(t, err)

	err = repo.ConsumeBackupCode(ctx, user.ID, codes[1].CodeHash)
	require.NoError(t, err)

	// Consuming same code again should fail.
	err = repo.ConsumeBackupCode(ctx, user.ID, codes[1].CodeHash)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_ConsumeBackupCode_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	err := repo.ConsumeBackupCode(ctx, "nonexistent", "nonexistent-hash")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_GetMFAStatus_NoMFA(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	status, err := repo.GetMFAStatus(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.ID, status.UserID)
	assert.False(t, status.Enabled)
	assert.Empty(t, status.Type)
	assert.False(t, status.Confirmed)
	assert.Equal(t, 0, status.BackupLeft)
}

func TestPostgresMFARepository_GetMFAStatus_Enrolled(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	secret := newTestMFASecret(user.ID)
	_, err = repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	err = repo.ConfirmSecret(ctx, user.ID)
	require.NoError(t, err)

	codes := newTestBackupCodes(user.ID, 10)
	err = repo.SaveBackupCodes(ctx, user.ID, codes)
	require.NoError(t, err)

	// Consume 2 codes.
	err = repo.ConsumeBackupCode(ctx, user.ID, codes[0].CodeHash)
	require.NoError(t, err)
	err = repo.ConsumeBackupCode(ctx, user.ID, codes[1].CodeHash)
	require.NoError(t, err)

	status, err := repo.GetMFAStatus(ctx, user.ID)
	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.Equal(t, "totp", status.Type)
	assert.True(t, status.Confirmed)
	assert.Equal(t, 8, status.BackupLeft)
}

func TestPostgresMFARepository_DeleteSecret_AllowsReenrollment(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Enroll, confirm, then delete.
	secret1 := newTestMFASecret(user.ID)
	_, err = repo.SaveSecret(ctx, secret1)
	require.NoError(t, err)
	err = repo.ConfirmSecret(ctx, user.ID)
	require.NoError(t, err)
	err = repo.DeleteSecret(ctx, user.ID)
	require.NoError(t, err)

	// Re-enroll with a new secret — should succeed because old one is soft-deleted.
	secret2 := newTestMFASecret(user.ID)
	created, err := repo.SaveSecret(ctx, secret2)
	require.NoError(t, err)
	assert.Equal(t, secret2.ID, created.ID)
}
