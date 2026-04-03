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

// testPool returns a pgxpool.Pool for integration tests.
// Skips the test if TEST_DATABASE_URL is not set.
func testPool(t *testing.T) *pgxpool.Pool {
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

	// Create tables for the test run.
	createTables(t, pool)

	return pool
}

// createTables ensures the required tables exist for repository tests.
func createTables(t *testing.T, pool *pgxpool.Pool) {
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
			last_login_at TIMESTAMPTZ,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at    TIMESTAMPTZ
		);

		CREATE TABLE IF NOT EXISTS refresh_tokens (
			signature  TEXT PRIMARY KEY,
			user_id    TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			revoked_at TIMESTAMPTZ
		);
	`)
	require.NoError(t, err)

	// Clean tables before each test file run.
	_, err = pool.Exec(ctx, `TRUNCATE users, refresh_tokens`)
	require.NoError(t, err)
}

// newTestUser returns a domain.User with unique values for testing.
func newTestUser() *domain.User {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.User{
		ID:           uuid.New().String(),
		Email:        uuid.New().String() + "@test.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash",
		Name:         "Test User",
		Roles:        []string{"user"},
		Locked:       false,
		LockedReason: "",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

// ────────────────────────────────────────────────────────────────────────────
// UserRepository tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresUserRepository_Create(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	created, err := repo.Create(ctx, user)
	require.NoError(t, err)

	assert.Equal(t, user.ID, created.ID)
	assert.Equal(t, user.Email, created.Email)
	assert.Equal(t, user.PasswordHash, created.PasswordHash)
	assert.Equal(t, user.Name, created.Name)
	assert.Equal(t, user.Roles, created.Roles)
	assert.False(t, created.Locked)
	assert.Nil(t, created.DeletedAt)
}

func TestPostgresUserRepository_Create_DuplicateEmail(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := repo.Create(ctx, user)
	require.NoError(t, err)

	// Second insert with same email should fail.
	dup := newTestUser()
	dup.Email = user.Email
	_, err = repo.Create(ctx, dup)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
}

func TestPostgresUserRepository_FindByID(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := repo.Create(ctx, user)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, found.Email)
}

func TestPostgresUserRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresUserRepository_FindByEmail(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := repo.Create(ctx, user)
	require.NoError(t, err)

	found, err := repo.FindByEmail(ctx, user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)
}

func TestPostgresUserRepository_FindByEmail_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByEmail(ctx, "nonexistent@test.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresUserRepository_UpdateLastLogin(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := repo.Create(ctx, user)
	require.NoError(t, err)

	loginTime := time.Now().UTC().Truncate(time.Microsecond)
	err = repo.UpdateLastLogin(ctx, user.ID, loginTime)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, found.LastLoginAt)
	assert.Equal(t, loginTime, found.LastLoginAt.Truncate(time.Microsecond))
}

func TestPostgresUserRepository_UpdateLastLogin_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	err := repo.UpdateLastLogin(ctx, "nonexistent-id", time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// RefreshTokenRepository tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresRefreshTokenRepository_StoreAndFind(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	sig := "test-sig-" + uuid.New().String()
	userID := uuid.New().String()
	expiresAt := time.Now().Add(7 * 24 * time.Hour).UTC().Truncate(time.Microsecond)

	err := repo.Store(ctx, sig, userID, expiresAt)
	require.NoError(t, err)

	rec, err := repo.FindBySignature(ctx, sig)
	require.NoError(t, err)
	assert.Equal(t, sig, rec.Signature)
	assert.Equal(t, userID, rec.UserID)
	assert.Equal(t, expiresAt, rec.ExpiresAt.Truncate(time.Microsecond))
	assert.Nil(t, rec.RevokedAt)
}

func TestPostgresRefreshTokenRepository_FindBySignature_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	_, err := repo.FindBySignature(ctx, "nonexistent-sig")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresRefreshTokenRepository_Revoke(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	sig := "test-sig-" + uuid.New().String()
	err := repo.Store(ctx, sig, uuid.New().String(), time.Now().Add(time.Hour))
	require.NoError(t, err)

	err = repo.Revoke(ctx, sig)
	require.NoError(t, err)

	rec, err := repo.FindBySignature(ctx, sig)
	require.NoError(t, err)
	assert.NotNil(t, rec.RevokedAt)
}

func TestPostgresRefreshTokenRepository_Revoke_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	err := repo.Revoke(ctx, "nonexistent-sig")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresRefreshTokenRepository_Revoke_AlreadyRevoked(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	sig := "test-sig-" + uuid.New().String()
	err := repo.Store(ctx, sig, uuid.New().String(), time.Now().Add(time.Hour))
	require.NoError(t, err)

	err = repo.Revoke(ctx, sig)
	require.NoError(t, err)

	// Second revoke should return ErrNotFound (already revoked, WHERE revoked_at IS NULL no match).
	err = repo.Revoke(ctx, sig)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresRefreshTokenRepository_RevokeAllForUser(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	userID := uuid.New().String()

	// Store 3 tokens for the same user.
	for i := 0; i < 3; i++ {
		sig := "test-sig-" + uuid.New().String()
		err := repo.Store(ctx, sig, userID, time.Now().Add(time.Hour))
		require.NoError(t, err)
	}

	// Store 1 token for a different user (should not be revoked).
	otherSig := "test-sig-other-" + uuid.New().String()
	err := repo.Store(ctx, otherSig, uuid.New().String(), time.Now().Add(time.Hour))
	require.NoError(t, err)

	err = repo.RevokeAllForUser(ctx, userID)
	require.NoError(t, err)

	// Other user's token should still be active.
	rec, err := repo.FindBySignature(ctx, otherSig)
	require.NoError(t, err)
	assert.Nil(t, rec.RevokedAt)
}

func TestPostgresRefreshTokenRepository_RevokeAllForUser_NoTokens(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	// Should not error even if user has no tokens.
	err := repo.RevokeAllForUser(ctx, uuid.New().String())
	require.NoError(t, err)
}
