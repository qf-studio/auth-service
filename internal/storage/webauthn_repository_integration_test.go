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
// WebAuthnRepository integration tests
// ────────────────────────────────────────────────────────────────────────────

func newTestWebAuthnCredential(userID string) *domain.WebAuthnCredential {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.WebAuthnCredential{
		ID:              uuid.New().String(),
		UserID:          userID,
		CredentialID:    []byte("cred-" + uuid.New().String()[:8]),
		PublicKey:       []byte("pk-" + uuid.New().String()[:8]),
		AAGUID:          "00000000-0000-0000-0000-000000000000",
		SignCount:       0,
		Transports:      []string{"usb", "internal"},
		AttestationType: "none",
		FriendlyName:    "Test Key",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

func TestPostgresWebAuthnRepository_Create(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred := newTestWebAuthnCredential(user.ID)
	created, err := repo.Create(ctx, cred)
	require.NoError(t, err)

	assert.Equal(t, cred.ID, created.ID)
	assert.Equal(t, cred.UserID, created.UserID)
	assert.Equal(t, cred.CredentialID, created.CredentialID)
	assert.Equal(t, cred.PublicKey, created.PublicKey)
	assert.Equal(t, cred.AAGUID, created.AAGUID)
	assert.Equal(t, uint32(0), created.SignCount)
	assert.Equal(t, []string{"usb", "internal"}, created.Transports)
	assert.Equal(t, "none", created.AttestationType)
	assert.Equal(t, "Test Key", created.FriendlyName)
	assert.Nil(t, created.DeletedAt)
}

func TestPostgresWebAuthnRepository_Create_DuplicateCredentialID(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred1 := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred1)
	require.NoError(t, err)

	cred2 := newTestWebAuthnCredential(user.ID)
	cred2.CredentialID = cred1.CredentialID // same credential ID
	_, err = repo.Create(ctx, cred2)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateWebAuthn)
}

func TestPostgresWebAuthnRepository_GetByUser(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Register two credentials.
	cred1 := newTestWebAuthnCredential(user.ID)
	cred1.FriendlyName = "Key A"
	_, err = repo.Create(ctx, cred1)
	require.NoError(t, err)

	cred2 := newTestWebAuthnCredential(user.ID)
	cred2.FriendlyName = "Key B"
	_, err = repo.Create(ctx, cred2)
	require.NoError(t, err)

	creds, err := repo.GetByUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Len(t, creds, 2)
}

func TestPostgresWebAuthnRepository_GetByUser_Empty(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	creds, err := repo.GetByUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestPostgresWebAuthnRepository_GetByCredentialID(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred)
	require.NoError(t, err)

	got, err := repo.GetByCredentialID(ctx, cred.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, cred.ID, got.ID)
	assert.Equal(t, cred.PublicKey, got.PublicKey)
}

func TestPostgresWebAuthnRepository_GetByCredentialID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	_, err := repo.GetByCredentialID(ctx, []byte("nonexistent"))
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresWebAuthnRepository_UpdateSignCount(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred)
	require.NoError(t, err)

	err = repo.UpdateSignCount(ctx, cred.ID, 42)
	require.NoError(t, err)

	got, err := repo.GetByCredentialID(ctx, cred.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, uint32(42), got.SignCount)
}

func TestPostgresWebAuthnRepository_UpdateSignCount_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	err := repo.UpdateSignCount(ctx, "nonexistent-id", 1)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresWebAuthnRepository_Delete(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred)
	require.NoError(t, err)

	err = repo.Delete(ctx, cred.ID)
	require.NoError(t, err)

	// Should not be found after hard delete.
	_, err = repo.GetByCredentialID(ctx, cred.CredentialID)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresWebAuthnRepository_Delete_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	err := repo.Delete(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresWebAuthnRepository_SoftDelete(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, cred.ID)
	require.NoError(t, err)

	// Should not appear in GetByUser results.
	creds, err := repo.GetByUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Empty(t, creds)

	// Should not be found by credential ID.
	_, err = repo.GetByCredentialID(ctx, cred.CredentialID)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresWebAuthnRepository_SoftDelete_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	err := repo.SoftDelete(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresWebAuthnRepository_SoftDelete_AllowsReregistration(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, cred.ID)
	require.NoError(t, err)

	// Re-register with the same credential ID should succeed (unique index is partial).
	cred2 := newTestWebAuthnCredential(user.ID)
	cred2.CredentialID = cred.CredentialID
	created, err := repo.Create(ctx, cred2)
	require.NoError(t, err)
	assert.Equal(t, cred2.ID, created.ID)
}

func TestPostgresWebAuthnRepository_SoftDelete_AlreadyDeleted(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, cred.ID)
	require.NoError(t, err)

	// Second soft-delete should return not found.
	err = repo.SoftDelete(ctx, cred.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresWebAuthnRepository_GetByUser_ExcludesSoftDeleted(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresWebAuthnRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	cred1 := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred1)
	require.NoError(t, err)

	cred2 := newTestWebAuthnCredential(user.ID)
	_, err = repo.Create(ctx, cred2)
	require.NoError(t, err)

	// Soft-delete one credential.
	err = repo.SoftDelete(ctx, cred1.ID)
	require.NoError(t, err)

	creds, err := repo.GetByUser(ctx, user.ID)
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, cred2.ID, creds[0].ID)
}
