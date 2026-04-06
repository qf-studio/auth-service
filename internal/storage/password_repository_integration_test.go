package storage_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ────────────────────────────────────────────────────────────────────────────
// PasswordPolicyRepository tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresPasswordPolicyRepository_Upsert_Create(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresPasswordPolicyRepository(pool)
	ctx := context.Background()

	policy := &domain.PasswordPolicy{
		ID:           "default",
		MinLength:    15,
		MaxLength:    128,
		MaxAgeDays:   90,
		HistoryCount: 5,
		RequireMFA:   true,
	}

	created, err := repo.Upsert(ctx, policy)
	require.NoError(t, err)

	assert.Equal(t, "default", created.ID)
	assert.Equal(t, 15, created.MinLength)
	assert.Equal(t, 128, created.MaxLength)
	assert.Equal(t, 90, created.MaxAgeDays)
	assert.Equal(t, 5, created.HistoryCount)
	assert.True(t, created.RequireMFA)
	assert.False(t, created.CreatedAt.IsZero())
	assert.False(t, created.UpdatedAt.IsZero())
}

func TestPostgresPasswordPolicyRepository_Upsert_Update(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresPasswordPolicyRepository(pool)
	ctx := context.Background()

	policy := &domain.PasswordPolicy{
		ID:           "tenant-1",
		MinLength:    15,
		MaxLength:    128,
		MaxAgeDays:   0,
		HistoryCount: 3,
		RequireMFA:   false,
	}

	_, err := repo.Upsert(ctx, policy)
	require.NoError(t, err)

	// Update the same policy.
	policy.MinLength = 20
	policy.MaxAgeDays = 60
	policy.RequireMFA = true

	updated, err := repo.Upsert(ctx, policy)
	require.NoError(t, err)

	assert.Equal(t, "tenant-1", updated.ID)
	assert.Equal(t, 20, updated.MinLength)
	assert.Equal(t, 60, updated.MaxAgeDays)
	assert.True(t, updated.RequireMFA)
}

func TestPostgresPasswordPolicyRepository_FindByID(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresPasswordPolicyRepository(pool)
	ctx := context.Background()

	policy := &domain.PasswordPolicy{
		ID:           "find-test",
		MinLength:    10,
		MaxLength:    64,
		MaxAgeDays:   30,
		HistoryCount: 2,
		RequireMFA:   false,
	}
	_, err := repo.Upsert(ctx, policy)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, "find-test")
	require.NoError(t, err)
	assert.Equal(t, 10, found.MinLength)
	assert.Equal(t, 64, found.MaxLength)
	assert.Equal(t, 30, found.MaxAgeDays)
}

func TestPostgresPasswordPolicyRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresPasswordPolicyRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresPasswordPolicyRepository_Delete(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresPasswordPolicyRepository(pool)
	ctx := context.Background()

	policy := &domain.PasswordPolicy{
		ID:        "delete-test",
		MinLength: 15,
		MaxLength: 128,
	}
	_, err := repo.Upsert(ctx, policy)
	require.NoError(t, err)

	err = repo.Delete(ctx, "delete-test")
	require.NoError(t, err)

	_, err = repo.FindByID(ctx, "delete-test")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresPasswordPolicyRepository_Delete_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresPasswordPolicyRepository(pool)
	ctx := context.Background()

	err := repo.Delete(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// PasswordHistoryRepository tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresPasswordHistoryRepository_Append(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresPasswordHistoryRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	entry := &domain.PasswordHistoryEntry{
		ID:           uuid.New().String(),
		UserID:       user.ID,
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$salt$oldhash1",
	}

	err = repo.Append(ctx, entry)
	require.NoError(t, err)
}

func TestPostgresPasswordHistoryRepository_Append_InvalidUser(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresPasswordHistoryRepository(pool)
	ctx := context.Background()

	entry := &domain.PasswordHistoryEntry{
		ID:           uuid.New().String(),
		UserID:       "nonexistent-user",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash",
	}

	err := repo.Append(ctx, entry)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresPasswordHistoryRepository_FindByUserID(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresPasswordHistoryRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Add 3 history entries.
	for i := 0; i < 3; i++ {
		entry := &domain.PasswordHistoryEntry{
			ID:           uuid.New().String(),
			UserID:       user.ID,
			PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash" + uuid.New().String(),
		}
		err := repo.Append(ctx, entry)
		require.NoError(t, err)
	}

	// Retrieve with limit 2.
	entries, err := repo.FindByUserID(ctx, user.ID, 2)
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Should be ordered by created_at DESC — most recent first.
	assert.True(t, !entries[0].CreatedAt.Before(entries[1].CreatedAt))
}

func TestPostgresPasswordHistoryRepository_FindByUserID_Empty(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresPasswordHistoryRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	entries, err := repo.FindByUserID(ctx, user.ID, 10)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestPostgresPasswordHistoryRepository_Prune(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresPasswordHistoryRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Add 5 history entries.
	for i := 0; i < 5; i++ {
		entry := &domain.PasswordHistoryEntry{
			ID:           uuid.New().String(),
			UserID:       user.ID,
			PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash" + uuid.New().String(),
		}
		err := repo.Append(ctx, entry)
		require.NoError(t, err)
	}

	// Keep only 2 most recent.
	pruned, err := repo.Prune(ctx, user.ID, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(3), pruned)

	// Verify only 2 remain.
	entries, err := repo.FindByUserID(ctx, user.ID, 10)
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestPostgresPasswordHistoryRepository_Prune_NothingToRemove(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresPasswordHistoryRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Add 2 entries, prune keeping 5.
	for i := 0; i < 2; i++ {
		entry := &domain.PasswordHistoryEntry{
			ID:           uuid.New().String(),
			UserID:       user.ID,
			PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash" + uuid.New().String(),
		}
		err := repo.Append(ctx, entry)
		require.NoError(t, err)
	}

	pruned, err := repo.Prune(ctx, user.ID, 5)
	require.NoError(t, err)
	assert.Equal(t, int64(0), pruned)
}
