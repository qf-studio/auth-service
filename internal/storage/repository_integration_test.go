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
		DO $$ BEGIN
			CREATE TYPE tenant_status AS ENUM ('active', 'suspended', 'deleted');
		EXCEPTION
			WHEN duplicate_object THEN NULL;
		END $$;

		CREATE TABLE IF NOT EXISTS tenants (
			id         UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
			name       TEXT          NOT NULL,
			slug       TEXT          NOT NULL UNIQUE,
			config     JSONB         NOT NULL DEFAULT '{}',
			status     tenant_status NOT NULL DEFAULT 'active',
			created_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
		);

		INSERT INTO tenants (id, name, slug, status)
		VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'active')
		ON CONFLICT (id) DO NOTHING;

		CREATE TABLE IF NOT EXISTS users (
			id            TEXT PRIMARY KEY,
			tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants (id),
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
			force_password_change BOOLEAN NOT NULL DEFAULT FALSE,
			password_changed_at   TIMESTAMPTZ,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at    TIMESTAMPTZ
		);

		CREATE TABLE IF NOT EXISTS refresh_tokens (
			signature  TEXT PRIMARY KEY,
			tenant_id  UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants (id),
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
			tenant_id                   UUID        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants (id),
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

		CREATE TABLE IF NOT EXISTS mfa_secrets (
			id           TEXT        PRIMARY KEY,
			tenant_id    UUID        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants (id),
			user_id      TEXT        NOT NULL REFERENCES users (id),
			type         TEXT        NOT NULL DEFAULT 'totp',
			secret       TEXT        NOT NULL,
			confirmed    BOOLEAN     NOT NULL DEFAULT FALSE,
			confirmed_at TIMESTAMPTZ,
			created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted_at   TIMESTAMPTZ
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_mfa_secrets_user_type_active
			ON mfa_secrets (user_id, type) WHERE deleted_at IS NULL;

		CREATE TABLE IF NOT EXISTS mfa_backup_codes (
			id         TEXT        PRIMARY KEY,
			tenant_id  UUID        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants (id),
			user_id    TEXT        NOT NULL REFERENCES users (id),
			code_hash  TEXT        NOT NULL,
			used       BOOLEAN     NOT NULL DEFAULT FALSE,
			used_at    TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS rar_resource_types (
			id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id         UUID        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants (id),
			type              TEXT        NOT NULL UNIQUE,
			description       TEXT        NOT NULL DEFAULT '',
			allowed_actions   TEXT[]      NOT NULL DEFAULT '{}',
			allowed_datatypes TEXT[]      NOT NULL DEFAULT '{}',
			created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
		);

		CREATE TABLE IF NOT EXISTS client_rar_allowed_types (
			tenant_id        UUID        NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants (id),
			client_id        UUID        NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
			resource_type_id UUID        NOT NULL REFERENCES rar_resource_types (id) ON DELETE CASCADE,
			created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
			PRIMARY KEY (client_id, resource_type_id)
		);
	`)
	require.NoError(t, err)

	// Clean tables before each test file run.
	_, err = pool.Exec(ctx, `TRUNCATE users, refresh_tokens, clients, mfa_secrets, mfa_backup_codes, rar_resource_types, client_rar_allowed_types, tenants CASCADE`)
	require.NoError(t, err)

	// Re-insert default tenant after truncation.
	_, err = pool.Exec(ctx, `INSERT INTO tenants (id, name, slug, status) VALUES ('00000000-0000-0000-0000-000000000001', 'Default', 'default', 'active')`)
	require.NoError(t, err)
}

// newTestUser returns a domain.User with unique values for testing.
func newTestUser() *domain.User {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.User{
		ID:           uuid.New().String(),
		TenantID:     domain.DefaultTenantID,
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

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, found.Email)
}

func TestPostgresUserRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, domain.DefaultTenantID, "nonexistent-id")
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

	found, err := repo.FindByEmail(ctx, domain.DefaultTenantID, user.Email)
	require.NoError(t, err)
	assert.Equal(t, user.ID, found.ID)
}

func TestPostgresUserRepository_FindByEmail_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByEmail(ctx, domain.DefaultTenantID, "nonexistent@test.com")
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
	err = repo.UpdateLastLogin(ctx, domain.DefaultTenantID, user.ID, loginTime)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, user.ID)
	require.NoError(t, err)
	require.NotNil(t, found.LastLoginAt)
	assert.Equal(t, loginTime, found.LastLoginAt.Truncate(time.Microsecond))
}

func TestPostgresUserRepository_UpdateLastLogin_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	err := repo.UpdateLastLogin(ctx, domain.DefaultTenantID, "nonexistent-id", time.Now())
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

	tid := domain.DefaultTenantID
	err := repo.Store(ctx, tid, sig, userID, expiresAt)
	require.NoError(t, err)

	rec, err := repo.FindBySignature(ctx, tid, sig)
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

	_, err := repo.FindBySignature(ctx, domain.DefaultTenantID, "nonexistent-sig")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresRefreshTokenRepository_Revoke(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()
	tid := domain.DefaultTenantID

	sig := "test-sig-" + uuid.New().String()
	err := repo.Store(ctx, tid, sig, uuid.New().String(), time.Now().Add(time.Hour))
	require.NoError(t, err)

	err = repo.Revoke(ctx, tid, sig)
	require.NoError(t, err)

	rec, err := repo.FindBySignature(ctx, tid, sig)
	require.NoError(t, err)
	assert.NotNil(t, rec.RevokedAt)
}

func TestPostgresRefreshTokenRepository_Revoke_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	err := repo.Revoke(ctx, domain.DefaultTenantID, "nonexistent-sig")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresRefreshTokenRepository_Revoke_AlreadyRevoked(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()
	tid := domain.DefaultTenantID

	sig := "test-sig-" + uuid.New().String()
	err := repo.Store(ctx, tid, sig, uuid.New().String(), time.Now().Add(time.Hour))
	require.NoError(t, err)

	err = repo.Revoke(ctx, tid, sig)
	require.NoError(t, err)

	// Second revoke should return ErrNotFound (already revoked, WHERE revoked_at IS NULL no match).
	err = repo.Revoke(ctx, tid, sig)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresRefreshTokenRepository_RevokeAllForUser(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()
	tid := domain.DefaultTenantID

	userID := uuid.New().String()

	// Store 3 tokens for the same user.
	for i := 0; i < 3; i++ {
		sig := "test-sig-" + uuid.New().String()
		err := repo.Store(ctx, tid, sig, userID, time.Now().Add(time.Hour))
		require.NoError(t, err)
	}

	// Store 1 token for a different user (should not be revoked).
	otherSig := "test-sig-other-" + uuid.New().String()
	err := repo.Store(ctx, tid, otherSig, uuid.New().String(), time.Now().Add(time.Hour))
	require.NoError(t, err)

	err = repo.RevokeAllForUser(ctx, tid, userID)
	require.NoError(t, err)

	// Other user's token should still be active.
	rec, err := repo.FindBySignature(ctx, tid, otherSig)
	require.NoError(t, err)
	assert.Nil(t, rec.RevokedAt)
}

func TestPostgresRefreshTokenRepository_RevokeAllForUser_NoTokens(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRefreshTokenRepository(pool)
	ctx := context.Background()

	// Should not error even if user has no tokens.
	err := repo.RevokeAllForUser(ctx, domain.DefaultTenantID, uuid.New().String())
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

	users, total, err := repo.List(ctx, domain.DefaultTenantID, 10, 0, "")
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

	users, total, err := repo.List(ctx, domain.DefaultTenantID, 2, 0, "")
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, users, 2)

	users, total, err = repo.List(ctx, domain.DefaultTenantID, 2, 4, "")
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, users, 1)
}

func TestPostgresAdminUserRepository_List_StatusFilter(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	// Create an active user.
	active := newTestUser()
	_, err := userRepo.Create(ctx, active)
	require.NoError(t, err)

	// Create a locked user.
	locked := newTestUser()
	_, err = userRepo.Create(ctx, locked)
	require.NoError(t, err)
	_, err = repo.Lock(ctx, domain.DefaultTenantID, locked.ID, "test lock")
	require.NoError(t, err)

	// Create a deleted user.
	deleted := newTestUser()
	_, err = userRepo.Create(ctx, deleted)
	require.NoError(t, err)
	err = repo.SoftDelete(ctx, domain.DefaultTenantID, deleted.ID)
	require.NoError(t, err)

	// Default (empty) returns all non-deleted (active + locked).
	users, total, err := repo.List(ctx, domain.DefaultTenantID, 10, 0, "")
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, users, 2)

	// "active" returns only non-locked, non-deleted.
	users, total, err = repo.List(ctx, domain.DefaultTenantID, 10, 0, "active")
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, users, 1)
	assert.Equal(t, active.ID, users[0].ID)

	// "locked" returns only locked users.
	users, total, err = repo.List(ctx, domain.DefaultTenantID, 10, 0, "locked")
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, users, 1)
	assert.Equal(t, locked.ID, users[0].ID)

	// "deleted" returns only soft-deleted users.
	users, total, err = repo.List(ctx, domain.DefaultTenantID, 10, 0, "deleted")
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, users, 1)
	assert.Equal(t, deleted.ID, users[0].ID)
}

func TestPostgresAdminUserRepository_FindByID(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	u := newTestUser()
	_, err := userRepo.Create(ctx, u)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.Email, found.Email)
}

func TestPostgresAdminUserRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, domain.DefaultTenantID, "nonexistent-id")
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

	err = repo.SoftDelete(ctx, domain.DefaultTenantID, u.ID)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, u.ID)
	require.NoError(t, err)
	assert.NotNil(t, found.DeletedAt)
}

func TestPostgresAdminUserRepository_SoftDelete_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	err := repo.SoftDelete(ctx, domain.DefaultTenantID, "nonexistent-id")
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

	err = repo.SoftDelete(ctx, domain.DefaultTenantID, u.ID)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, domain.DefaultTenantID, u.ID)
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

	locked, err := repo.Lock(ctx, domain.DefaultTenantID, u.ID, "suspicious activity")
	require.NoError(t, err)
	assert.True(t, locked.Locked)
	assert.NotNil(t, locked.LockedAt)
	assert.Equal(t, "suspicious activity", locked.LockedReason)
}

func TestPostgresAdminUserRepository_Lock_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	_, err := repo.Lock(ctx, domain.DefaultTenantID, "nonexistent-id", "reason")
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

	_, err = repo.Lock(ctx, domain.DefaultTenantID, u.ID, "suspicious activity")
	require.NoError(t, err)

	unlocked, err := repo.Unlock(ctx, domain.DefaultTenantID, u.ID)
	require.NoError(t, err)
	assert.False(t, unlocked.Locked)
	assert.Nil(t, unlocked.LockedAt)
	assert.Equal(t, "", unlocked.LockedReason)
}

func TestPostgresAdminUserRepository_Unlock_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAdminUserRepository(pool)
	ctx := context.Background()

	_, err := repo.Unlock(ctx, domain.DefaultTenantID, "nonexistent-id")
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
		TenantID:       domain.DefaultTenantID,
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

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, c.ID)
	require.NoError(t, err)
	assert.Equal(t, c.Name, found.Name)
}

func TestPostgresClientRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, domain.DefaultTenantID, uuid.New())
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

	found, err := repo.FindByName(ctx, domain.DefaultTenantID, c.Name)
	require.NoError(t, err)
	assert.Equal(t, c.ID, found.ID)
}

func TestPostgresClientRepository_FindByName_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByName(ctx, domain.DefaultTenantID, "nonexistent-client")
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

	clients, total, err := repo.List(ctx, domain.DefaultTenantID, 10, 0, "", false)
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

	clients, total, err := repo.List(ctx, domain.DefaultTenantID, 2, 0, "", false)
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

	err = repo.SoftDelete(ctx, domain.DefaultTenantID, c.ID)
	require.NoError(t, err)

	// Without includeRevoked.
	clients, total, err := repo.List(ctx, domain.DefaultTenantID, 10, 0, "", false)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, clients)

	// With includeRevoked.
	clients, total, err = repo.List(ctx, domain.DefaultTenantID, 10, 0, "", true)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, clients, 1)
}

func TestPostgresClientRepository_List_ClientTypeFilter(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	// Create a service client.
	svc := newTestClient()
	svc.ClientType = domain.ClientTypeService
	_, err := repo.Create(ctx, svc)
	require.NoError(t, err)

	// Create an agent client.
	agent := newTestClient()
	agent.ClientType = domain.ClientTypeAgent
	_, err = repo.Create(ctx, agent)
	require.NoError(t, err)

	// No filter returns all.
	clients, total, err := repo.List(ctx, domain.DefaultTenantID, 10, 0, "", false)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, clients, 2)

	// Filter by service.
	clients, total, err = repo.List(ctx, domain.DefaultTenantID, 10, 0, "service", false)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, clients, 1)
	assert.Equal(t, domain.ClientTypeService, clients[0].ClientType)

	// Filter by agent.
	clients, total, err = repo.List(ctx, domain.DefaultTenantID, 10, 0, "agent", false)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, clients, 1)
	assert.Equal(t, domain.ClientTypeAgent, clients[0].ClientType)
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

	err = repo.UpdateSecretHash(ctx, domain.DefaultTenantID, c.ID, "new-hash")
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, c.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-hash", found.SecretHash)
}

func TestPostgresClientRepository_UpdateSecretHash_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	err := repo.UpdateSecretHash(ctx, domain.DefaultTenantID, uuid.New(), "new-hash")
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
	err = repo.RotateSecret(ctx, domain.DefaultTenantID, c.ID, "new-secret-hash", graceEnd)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, c.ID)
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
	err := repo.RotateSecret(ctx, domain.DefaultTenantID, uuid.New(), "new-hash", graceEnd)
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

	err = repo.SoftDelete(ctx, domain.DefaultTenantID, c.ID)
	require.NoError(t, err)

	graceEnd := time.Now().Add(24 * time.Hour).UTC()
	err = repo.RotateSecret(ctx, domain.DefaultTenantID, c.ID, "new-hash", graceEnd)
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

	err = repo.SoftDelete(ctx, domain.DefaultTenantID, c.ID)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, c.ID)
	require.NoError(t, err)
	assert.Equal(t, domain.ClientStatusRevoked, found.Status)
}

func TestPostgresClientRepository_SoftDelete_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()

	err := repo.SoftDelete(ctx, domain.DefaultTenantID, uuid.New())
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

	err = repo.SoftDelete(ctx, domain.DefaultTenantID, c.ID)
	require.NoError(t, err)

	err = repo.SoftDelete(ctx, domain.DefaultTenantID, c.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrAlreadyDeleted)
}

// ────────────────────────────────────────────────────────────────────────────
// TenantRepository tests
// ────────────────────────────────────────────────────────────────────────────

// newTestTenant returns a domain.Tenant with unique values for testing.
func newTestTenant(status domain.TenantStatus) *domain.Tenant {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.New()
	return &domain.Tenant{
		ID:        id,
		Name:      "Tenant-" + id.String()[:8],
		Slug:      "tenant-" + id.String()[:8],
		Config:    domain.TenantConfig{},
		Status:    status,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func TestPostgresTenantRepository_Create(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	tenant := newTestTenant(domain.TenantStatusActive)
	created, err := repo.Create(ctx, tenant)
	require.NoError(t, err)

	assert.Equal(t, tenant.ID, created.ID)
	assert.Equal(t, tenant.Name, created.Name)
	assert.Equal(t, tenant.Slug, created.Slug)
	assert.Equal(t, domain.TenantStatusActive, created.Status)
}

func TestPostgresTenantRepository_Create_DuplicateSlug(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	tenant := newTestTenant(domain.TenantStatusActive)
	_, err := repo.Create(ctx, tenant)
	require.NoError(t, err)

	dup := newTestTenant(domain.TenantStatusActive)
	dup.Slug = tenant.Slug
	_, err = repo.Create(ctx, dup)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateTenant)
}

func TestPostgresTenantRepository_FindByID(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	tenant := newTestTenant(domain.TenantStatusActive)
	_, err := repo.Create(ctx, tenant)
	require.NoError(t, err)

	found, err := repo.FindByID(ctx, tenant.ID)
	require.NoError(t, err)
	assert.Equal(t, tenant.Name, found.Name)
	assert.Equal(t, tenant.Slug, found.Slug)
}

func TestPostgresTenantRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, uuid.New())
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresTenantRepository_FindBySlug(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	tenant := newTestTenant(domain.TenantStatusActive)
	_, err := repo.Create(ctx, tenant)
	require.NoError(t, err)

	found, err := repo.FindBySlug(ctx, tenant.Slug)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, found.ID)
	assert.Equal(t, tenant.Name, found.Name)
}

func TestPostgresTenantRepository_List(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	// Create 3 additional tenants (default tenant already exists).
	for i := 0; i < 3; i++ {
		_, err := repo.Create(ctx, newTestTenant(domain.TenantStatusActive))
		require.NoError(t, err)
	}

	tenants, total, err := repo.List(ctx, 10, 0, "")
	require.NoError(t, err)
	assert.Equal(t, 4, total) // 3 new + 1 default
	assert.Len(t, tenants, 4)
}

func TestPostgresTenantRepository_List_Pagination(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := repo.Create(ctx, newTestTenant(domain.TenantStatusActive))
		require.NoError(t, err)
	}

	// Page 1: 2 items
	tenants, total, err := repo.List(ctx, 2, 0, "")
	require.NoError(t, err)
	assert.Equal(t, 6, total) // 5 new + 1 default
	assert.Len(t, tenants, 2)

	// Page 2: 2 items
	tenants, total, err = repo.List(ctx, 2, 2, "")
	require.NoError(t, err)
	assert.Equal(t, 6, total)
	assert.Len(t, tenants, 2)
}

func TestPostgresTenantRepository_List_StatusFilter(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	// Default tenant is "active". Create tenants with different statuses.
	for i := 0; i < 2; i++ {
		_, err := repo.Create(ctx, newTestTenant(domain.TenantStatusActive))
		require.NoError(t, err)
	}
	for i := 0; i < 3; i++ {
		_, err := repo.Create(ctx, newTestTenant(domain.TenantStatusSuspended))
		require.NoError(t, err)
	}
	_, err := repo.Create(ctx, newTestTenant(domain.TenantStatusDeleted))
	require.NoError(t, err)

	// Filter: active → 2 new + 1 default = 3
	tenants, total, err := repo.List(ctx, 10, 0, "active")
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, tenants, 3)
	for _, ten := range tenants {
		assert.Equal(t, domain.TenantStatusActive, ten.Status)
	}

	// Filter: suspended → 3
	tenants, total, err = repo.List(ctx, 10, 0, "suspended")
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, tenants, 3)
	for _, ten := range tenants {
		assert.Equal(t, domain.TenantStatusSuspended, ten.Status)
	}

	// Filter: deleted → 1
	tenants, total, err = repo.List(ctx, 10, 0, "deleted")
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, tenants, 1)
	assert.Equal(t, domain.TenantStatusDeleted, tenants[0].Status)

	// No filter → all 7
	tenants, total, err = repo.List(ctx, 10, 0, "")
	require.NoError(t, err)
	assert.Equal(t, 7, total) // 2 active + 1 default + 3 suspended + 1 deleted
	assert.Len(t, tenants, 7)
}

func TestPostgresTenantRepository_List_StatusFilter_Pagination(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	// Create 5 active tenants (plus the default = 6 total active).
	for i := 0; i < 5; i++ {
		_, err := repo.Create(ctx, newTestTenant(domain.TenantStatusActive))
		require.NoError(t, err)
	}
	// 2 suspended
	for i := 0; i < 2; i++ {
		_, err := repo.Create(ctx, newTestTenant(domain.TenantStatusSuspended))
		require.NoError(t, err)
	}

	// Page through active tenants with limit=2
	tenants, total, err := repo.List(ctx, 2, 0, "active")
	require.NoError(t, err)
	assert.Equal(t, 6, total)
	assert.Len(t, tenants, 2)

	tenants, total, err = repo.List(ctx, 2, 4, "active")
	require.NoError(t, err)
	assert.Equal(t, 6, total)
	assert.Len(t, tenants, 2)
}

func TestPostgresTenantRepository_Update(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	tenant := newTestTenant(domain.TenantStatusActive)
	created, err := repo.Create(ctx, tenant)
	require.NoError(t, err)

	created.Name = "Updated Name"
	created.Status = domain.TenantStatusSuspended
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", updated.Name)
	assert.Equal(t, domain.TenantStatusSuspended, updated.Status)
}

func TestPostgresTenantRepository_Update_Config(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	tenant := newTestTenant(domain.TenantStatusActive)
	created, err := repo.Create(ctx, tenant)
	require.NoError(t, err)

	created.Config = domain.TenantConfig{
		AllowedOAuthProviders: []string{"google", "github"},
	}
	updated, err := repo.Update(ctx, created)
	require.NoError(t, err)
	assert.Equal(t, []string{"google", "github"}, updated.Config.AllowedOAuthProviders)

	// Verify via FindByID
	found, err := repo.FindByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, []string{"google", "github"}, found.Config.AllowedOAuthProviders)
}

func TestPostgresTenantRepository_Delete(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	tenant := newTestTenant(domain.TenantStatusActive)
	_, err := repo.Create(ctx, tenant)
	require.NoError(t, err)

	err = repo.Delete(ctx, tenant.ID)
	require.NoError(t, err)

	_, err = repo.FindByID(ctx, tenant.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresTenantRepository_Delete_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	err := repo.Delete(ctx, uuid.New())
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// TestPostgresTenantRepository_Create_WithConfig verifies JSONB config round-trips.
func TestPostgresTenantRepository_Create_WithConfig(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresTenantRepository(pool)
	ctx := context.Background()

	minLen := 20
	tenant := newTestTenant(domain.TenantStatusActive)
	tenant.Config = domain.TenantConfig{
		AllowedOAuthProviders: []string{"google"},
		PasswordPolicy: &domain.TenantPasswordPolicy{
			MinLength: &minLen,
		},
	}

	created, err := repo.Create(ctx, tenant)
	require.NoError(t, err)
	assert.Equal(t, []string{"google"}, created.Config.AllowedOAuthProviders)
	require.NotNil(t, created.Config.PasswordPolicy)
	assert.Equal(t, 20, *created.Config.PasswordPolicy.MinLength)
}

