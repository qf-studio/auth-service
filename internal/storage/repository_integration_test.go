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

		DO $$ BEGIN
			CREATE TYPE client_type AS ENUM ('service', 'agent');
		EXCEPTION
			WHEN duplicate_object THEN NULL;
		END $$;

		CREATE TABLE IF NOT EXISTS clients (
			id                          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			name                        TEXT        NOT NULL UNIQUE,
			client_type                 client_type NOT NULL,
			secret_hash                 TEXT        NOT NULL,
			previous_secret_hash        TEXT        NOT NULL DEFAULT '',
			previous_secret_expires_at  TIMESTAMPTZ,
			scopes                      TEXT[]      NOT NULL DEFAULT '{}',
			owner                       TEXT        NOT NULL,
			access_token_ttl            INTEGER     NOT NULL DEFAULT 900,
			status                      TEXT        NOT NULL DEFAULT 'active',
			created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_used_at                TIMESTAMPTZ
		);
	`)
	require.NoError(t, err)

	// Clean tables before each test file run.
	_, err = pool.Exec(ctx, `TRUNCATE users, refresh_tokens, clients`)
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

// ────────────────────────────────────────────────────────────────────────────
// AdminUserRepository tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresAdminUserRepository_List(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	// Create 3 users.
	for i := 0; i < 3; i++ {
		_, err := userRepo.Create(ctx, newTestUser())
		require.NoError(t, err)
	}

	users, total, err := repo.List(ctx, 10, 0, false)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, users, 3)
}

func TestPostgresAdminUserRepository_List_Pagination(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := userRepo.Create(ctx, newTestUser())
		require.NoError(t, err)
	}

	users, total, err := repo.List(ctx, 2, 0, false)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, users, 2)

	users, total, err = repo.List(ctx, 2, 4, false)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, users, 1)
}

func TestPostgresAdminUserRepository_List_IncludeDeleted(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := userRepo.Create(ctx, u)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, u.ID)
	require.NoError(t, err)

	// Without includeDeleted, should be empty.
	users, total, err := repo.List(ctx, 10, 0, false)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, users)

	// With includeDeleted, should find the deleted user.
	users, total, err = repo.List(ctx, 10, 0, true)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, users, 1)
}

func TestPostgresAdminUserRepository_FindByID(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := userRepo.Create(ctx, u)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.Email, found.Email)
}

func TestPostgresAdminUserRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresAdminUserRepository_Create(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	created, err := repo.Create(ctx, u)
	require.NoError(t, err)
	assert.Equal(t, u.ID, created.ID)
	assert.Equal(t, u.Email, created.Email)
}

func TestPostgresAdminUserRepository_Create_DuplicateEmail(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := repo.Create(ctx, u)
	require.NoError(t, err)

	dup := newTestUser()
	dup.Email = u.Email
	_, err = repo.Create(ctx, dup)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
}

func TestPostgresAdminUserRepository_Update(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := repo.Create(ctx, u)
	require.NoError(t, err)

	u.Name = "Updated Name"
	u.Roles = []string{"admin"}
	updated, err := repo.Update(ctx, u)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.Equal(t, []string{"admin"}, updated.Roles)
}

func TestPostgresAdminUserRepository_Update_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := repo.Update(ctx, u)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresAdminUserRepository_Update_DuplicateEmail(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u1 := newTestUser()
	_, err := repo.Create(ctx, u1)
	require.NoError(t, err)

	u2 := newTestUser()
	_, err = repo.Create(ctx, u2)
	require.NoError(t, err)

	u2.Email = u1.Email
	_, err = repo.Update(ctx, u2)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateEmail)
}

func TestPostgresAdminUserRepository_SoftDelete(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := repo.Create(ctx, u)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, u.ID)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, u.ID)
	require.NoError(t, err)
	assert.NotNil(t, found.DeletedAt)
}

func TestPostgresAdminUserRepository_SoftDelete_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	err := repo.SoftDelete(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresAdminUserRepository_SoftDelete_AlreadyDeleted(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := repo.Create(ctx, u)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, u.ID)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, u.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrAlreadyDeleted)
}

func TestPostgresAdminUserRepository_Lock(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := repo.Create(ctx, u)
	require.NoError(t, err)

	locked, err := repo.Lock(ctx, u.ID, "suspicious activity")
	require.NoError(t, err)
	assert.True(t, locked.Locked)
	assert.NotNil(t, locked.LockedAt)
	assert.Equal(t, "suspicious activity", locked.LockedReason)
}

func TestPostgresAdminUserRepository_Lock_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	_, err := repo.Lock(ctx, "nonexistent-id", "reason")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresAdminUserRepository_Unlock(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := repo.Create(ctx, u)
	require.NoError(t, err)

	_, err = repo.Lock(ctx, u.ID, "suspicious activity")
	require.NoError(t, err)

	unlocked, err := repo.Unlock(ctx, u.ID)
	require.NoError(t, err)
	assert.False(t, unlocked.Locked)
	assert.Nil(t, unlocked.LockedAt)
	assert.Equal(t, "", unlocked.LockedReason)
}

func TestPostgresAdminUserRepository_Unlock_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	_, err := repo.Unlock(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// ClientRepository tests
// ────────────────────────────────────────────────────────────────────────────

func newTestClient() *domain.Client {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.Client{
		ID:             uuid.New(),
		Name:           "test-client-" + uuid.New().String()[:8],
		ClientType:     domain.ClientTypeService,
		SecretHash:     "$argon2id$v=19$m=19456,t=2,p=1$salt$hash",
		Scopes:         []string{"read:users"},
		Owner:          "admin",
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func TestPostgresClientRepository_Create(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	created, err := repo.Create(ctx, c)
	require.NoError(t, err)
	assert.Equal(t, c.ID, created.ID)
	assert.Equal(t, c.Name, created.Name)
	assert.Equal(t, c.SecretHash, created.SecretHash)
	assert.Equal(t, c.Scopes, created.Scopes)
	assert.Equal(t, domain.ClientStatusActive, created.Status)
}

func TestPostgresClientRepository_Create_DuplicateName(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	dup := newTestClient()
	dup.Name = c.Name
	_, err = repo.Create(ctx, dup)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateClient)
}

func TestPostgresClientRepository_FindByID(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, c.Name, found.Name)
}

func TestPostgresClientRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, uuid.New())
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresClientRepository_FindByName(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	found, err := repo.FindByName(ctx, c.Name)
	require.NoError(t, err)
	assert.Equal(t, c.ID, found.ID)
}

func TestPostgresClientRepository_FindByName_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByName(ctx, "nonexistent-client")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresClientRepository_List(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := repo.Create(ctx, newTestClient())
		require.NoError(t, err)
	}

	clients, total, err := repo.List(ctx, 10, 0, false)
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, clients, 3)
}

func TestPostgresClientRepository_List_Pagination(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := repo.Create(ctx, newTestClient())
		require.NoError(t, err)
	}

	clients, total, err := repo.List(ctx, 2, 0, false)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, clients, 2)
}

func TestPostgresClientRepository_List_IncludeRevoked(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, c.ID)
	require.NoError(t, err)

	// Without includeRevoked.
	clients, total, err := repo.List(ctx, 10, 0, false)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, clients)

	// With includeRevoked.
	clients, total, err = repo.List(ctx, 10, 0, true)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, clients, 1)
}

func TestPostgresClientRepository_Update(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	c.Name = "updated-name-" + uuid.New().String()[:8]
	c.Scopes = []string{"read:users", "write:users"}
	updated, err := repo.Update(ctx, c)
	require.NoError(t, err)
	assert.Equal(t, c.Name, updated.Name)
	assert.Equal(t, []string{"read:users", "write:users"}, updated.Scopes)
}

func TestPostgresClientRepository_Update_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Update(ctx, c)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresClientRepository_Update_DuplicateName(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c1 := newTestClient()
	_, err := repo.Create(ctx, c1)
	require.NoError(t, err)

	c2 := newTestClient()
	_, err = repo.Create(ctx, c2)
	require.NoError(t, err)

	c2.Name = c1.Name
	_, err = repo.Update(ctx, c2)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateClient)
}

func TestPostgresClientRepository_UpdateSecretHash(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	err = repo.UpdateSecretHash(ctx, c.ID, "new-hash")
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-hash", found.SecretHash)
}

func TestPostgresClientRepository_UpdateSecretHash_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	err := repo.UpdateSecretHash(ctx, uuid.New(), "new-hash")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresClientRepository_RotateSecret(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	graceEnd := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Microsecond)
	err = repo.RotateSecret(ctx, c.ID, "new-secret-hash", graceEnd)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-secret-hash", found.SecretHash)
	assert.Equal(t, c.SecretHash, found.PreviousSecretHash)
	require.NotNil(t, found.PreviousSecretExpiresAt)
	assert.Equal(t, graceEnd, found.PreviousSecretExpiresAt.Truncate(time.Microsecond))
}

func TestPostgresClientRepository_RotateSecret_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	graceEnd := time.Now().Add(24 * time.Hour).UTC()
	err := repo.RotateSecret(ctx, uuid.New(), "new-hash", graceEnd)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresClientRepository_RotateSecret_RevokedClient(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, c.ID)
	require.NoError(t, err)

	graceEnd := time.Now().Add(24 * time.Hour).UTC()
	err = repo.RotateSecret(ctx, c.ID, "new-hash", graceEnd)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresClientRepository_SoftDelete(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, c.ID)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, c.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.ClientStatusRevoked, found.Status)
}

func TestPostgresClientRepository_SoftDelete_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	err := repo.SoftDelete(ctx, uuid.New())
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresClientRepository_SoftDelete_AlreadyDeleted(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	c := newTestClient()
	_, err := repo.Create(ctx, c)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, c.ID)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, c.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrAlreadyDeleted)
}
