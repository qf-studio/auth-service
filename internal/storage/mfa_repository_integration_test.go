package storage_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// mfaTestPool returns a pgxpool.Pool for MFA integration tests.
func mfaTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { pool.Close() })

	createMFATables(t, pool)
	return pool
}

// createMFATables ensures the users + MFA tables exist and are clean.
func createMFATables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			email         TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			name          TEXT NOT NULL,
			roles         TEXT[] NOT NULL DEFAULT '{}',
			locked        BOOLEAN NOT NULL DEFAULT FALSE,
			locked_at     TIMESTAMPTZ,
			locked_reason TEXT NOT NULL DEFAULT '',
			email_verified                BOOLEAN NOT NULL DEFAULT FALSE,
			email_verify_token            TEXT,
			email_verify_token_expires_at TIMESTAMPTZ,
			last_login_at TIMESTAMPTZ,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at    TIMESTAMPTZ
		);

		CREATE TABLE IF NOT EXISTS mfa_secrets (
			id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id      TEXT        NOT NULL REFERENCES users(id),
			method       TEXT        NOT NULL DEFAULT 'totp',
			secret       TEXT        NOT NULL,
			confirmed    BOOLEAN     NOT NULL DEFAULT FALSE,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			UNIQUE (user_id, method)
		);

		CREATE TABLE IF NOT EXISTS mfa_backup_codes (
			id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			user_id      TEXT        NOT NULL REFERENCES users(id),
			code_hash    TEXT        NOT NULL,
			used_at      TIMESTAMPTZ,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `TRUNCATE mfa_backup_codes, mfa_secrets, users CASCADE`)
	require.NoError(t, err)
}

// insertTestUser inserts a minimal user row required by FK constraints.
func insertTestUser(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	userID := uuid.New().String()
	ctx := context.Background()
	_, err := pool.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, $3, $4)`,
		userID, uuid.New().String()+"@test.com", "$argon2id$hash", "Test User",
	)
	require.NoError(t, err)
	return userID
}

// ────────────────────────────────────────────────────────────────────────────
// MFARepository — Secret tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresMFARepository_SaveAndGetSecret(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	secret := &domain.MFASecret{
		UserID: userID,
		Method: domain.MFAMethodTOTP,
		Secret: "JBSWY3DPEHPK3PXP",
	}

	saved, err := repo.SaveSecret(ctx, secret)
	require.NoError(t, err)
	assert.Equal(t, userID, saved.UserID)
	assert.Equal(t, domain.MFAMethodTOTP, saved.Method)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", saved.Secret)
	assert.False(t, saved.Confirmed)
	assert.NotEqual(t, uuid.Nil, saved.ID)

	got, err := repo.GetSecret(ctx, userID, domain.MFAMethodTOTP)
	require.NoError(t, err)
	assert.Equal(t, saved.ID, got.ID)
	assert.Equal(t, saved.Secret, got.Secret)
}

func TestPostgresMFARepository_SaveSecret_Upsert(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	first := &domain.MFASecret{UserID: userID, Method: domain.MFAMethodTOTP, Secret: "SECRET1"}
	_, err := repo.SaveSecret(ctx, first)
	require.NoError(t, err)

	// Confirm it first.
	require.NoError(t, repo.ConfirmSecret(ctx, userID, domain.MFAMethodTOTP))

	// Upsert should reset confirmed to false and update secret.
	second := &domain.MFASecret{UserID: userID, Method: domain.MFAMethodTOTP, Secret: "SECRET2"}
	updated, err := repo.SaveSecret(ctx, second)
	require.NoError(t, err)
	assert.Equal(t, "SECRET2", updated.Secret)
	assert.False(t, updated.Confirmed)
}

func TestPostgresMFARepository_GetSecret_NotFound(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	_, err := repo.GetSecret(ctx, "nonexistent", domain.MFAMethodTOTP)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_ConfirmSecret(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	secret := &domain.MFASecret{UserID: userID, Method: domain.MFAMethodTOTP, Secret: "TOTPSECRET"}
	_, err := repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	err = repo.ConfirmSecret(ctx, userID, domain.MFAMethodTOTP)
	require.NoError(t, err)

	got, err := repo.GetSecret(ctx, userID, domain.MFAMethodTOTP)
	require.NoError(t, err)
	assert.True(t, got.Confirmed)
}

func TestPostgresMFARepository_ConfirmSecret_NotFound(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	err := repo.ConfirmSecret(ctx, "nonexistent", domain.MFAMethodTOTP)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_ConfirmSecret_Idempotent(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	secret := &domain.MFASecret{UserID: userID, Method: domain.MFAMethodTOTP, Secret: "SEC"}
	_, err := repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	require.NoError(t, repo.ConfirmSecret(ctx, userID, domain.MFAMethodTOTP))
	// Second confirm is idempotent.
	require.NoError(t, repo.ConfirmSecret(ctx, userID, domain.MFAMethodTOTP))
}

func TestPostgresMFARepository_DeleteSecret(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	secret := &domain.MFASecret{UserID: userID, Method: domain.MFAMethodTOTP, Secret: "DEL"}
	_, err := repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	err = repo.DeleteSecret(ctx, userID, domain.MFAMethodTOTP)
	require.NoError(t, err)

	_, err = repo.GetSecret(ctx, userID, domain.MFAMethodTOTP)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_DeleteSecret_NotFound(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()

	err := repo.DeleteSecret(ctx, "nonexistent", domain.MFAMethodTOTP)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// MFARepository — Backup code tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresMFARepository_SaveAndGetBackupCodes(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	hashes := []string{"hash1", "hash2", "hash3", "hash4", "hash5"}
	err := repo.SaveBackupCodes(ctx, userID, hashes)
	require.NoError(t, err)

	codes, err := repo.GetBackupCodes(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, codes, 5)
	for _, c := range codes {
		assert.Equal(t, userID, c.UserID)
		assert.Nil(t, c.UsedAt)
	}
}

func TestPostgresMFARepository_SaveBackupCodes_ReplacesExisting(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	require.NoError(t, repo.SaveBackupCodes(ctx, userID, []string{"old1", "old2"}))
	require.NoError(t, repo.SaveBackupCodes(ctx, userID, []string{"new1", "new2", "new3"}))

	codes, err := repo.GetBackupCodes(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, codes, 3)
}

func TestPostgresMFARepository_ConsumeBackupCode(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	require.NoError(t, repo.SaveBackupCodes(ctx, userID, []string{"code1", "code2"}))

	err := repo.ConsumeBackupCode(ctx, userID, "code1")
	require.NoError(t, err)

	// Only one unused code should remain.
	codes, err := repo.GetBackupCodes(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, codes, 1)
	assert.Equal(t, "code2", codes[0].CodeHash)
}

func TestPostgresMFARepository_ConsumeBackupCode_AlreadyUsed(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	require.NoError(t, repo.SaveBackupCodes(ctx, userID, []string{"once"}))
	require.NoError(t, repo.ConsumeBackupCode(ctx, userID, "once"))

	// Second consumption should fail.
	err := repo.ConsumeBackupCode(ctx, userID, "once")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresMFARepository_ConsumeBackupCode_NotFound(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	err := repo.ConsumeBackupCode(ctx, userID, "doesnotexist")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// MFARepository — Status tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresMFARepository_GetMFAStatus_NoMFA(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	status, err := repo.GetMFAStatus(ctx, userID)
	require.NoError(t, err)
	assert.False(t, status.Enabled)
	assert.Empty(t, status.ConfirmedMethods)
	assert.Equal(t, 0, status.BackupCodesLeft)
}

func TestPostgresMFARepository_GetMFAStatus_WithConfirmedTOTP(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	secret := &domain.MFASecret{UserID: userID, Method: domain.MFAMethodTOTP, Secret: "S"}
	_, err := repo.SaveSecret(ctx, secret)
	require.NoError(t, err)
	require.NoError(t, repo.ConfirmSecret(ctx, userID, domain.MFAMethodTOTP))
	require.NoError(t, repo.SaveBackupCodes(ctx, userID, []string{"b1", "b2", "b3"}))

	status, err := repo.GetMFAStatus(ctx, userID)
	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.Contains(t, status.ConfirmedMethods, domain.MFAMethodTOTP)
	assert.Equal(t, 3, status.BackupCodesLeft)
}

func TestPostgresMFARepository_GetMFAStatus_UnconfirmedNotEnabled(t *testing.T) {
	pool := mfaTestPool(t)
	repo := storage.NewPostgresMFARepository(pool)
	ctx := context.Background()
	userID := insertTestUser(t, pool)

	// Unconfirmed secret should not count as enabled.
	secret := &domain.MFASecret{UserID: userID, Method: domain.MFAMethodTOTP, Secret: "X"}
	_, err := repo.SaveSecret(ctx, secret)
	require.NoError(t, err)

	status, err := repo.GetMFAStatus(ctx, userID)
	require.NoError(t, err)
	assert.False(t, status.Enabled)
	assert.Empty(t, status.ConfirmedMethods)
}
