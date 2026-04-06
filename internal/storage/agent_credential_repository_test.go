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

// credentialTestPool returns a pool and creates required tables for credential vault tests.
// Skips the test if TEST_DATABASE_URL is not set.
func credentialTestPool(t *testing.T) *pgxpool.Pool {
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

	createCredentialTables(t, pool)
	return pool
}

func createCredentialTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := pool.Exec(ctx, `
		DO $$ BEGIN
			CREATE TYPE client_type AS ENUM ('service', 'agent');
		EXCEPTION
			WHEN duplicate_object THEN NULL;
		END $$;

		CREATE TABLE IF NOT EXISTS clients (
			id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			name             TEXT        NOT NULL UNIQUE,
			client_type      client_type NOT NULL,
			secret_hash      TEXT        NOT NULL DEFAULT '',
			scopes           TEXT[]      NOT NULL DEFAULT '{}',
			owner            TEXT        NOT NULL DEFAULT '',
			access_token_ttl INTEGER     NOT NULL DEFAULT 900,
			status           TEXT        NOT NULL DEFAULT 'active',
			created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			last_used_at     TIMESTAMPTZ
		);

		CREATE TABLE IF NOT EXISTS agent_credentials (
			id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			owner_client_id  UUID        NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
			target_name      TEXT        NOT NULL,
			credential_type  TEXT        NOT NULL,
			encrypted_blob   BYTEA       NOT NULL,
			scopes           TEXT[]      NOT NULL DEFAULT '{}',
			status           TEXT        NOT NULL DEFAULT 'active',
			last_rotated_at  TIMESTAMPTZ,
			next_rotation_at TIMESTAMPTZ,
			created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			CONSTRAINT agent_credentials_type_check CHECK (
				credential_type IN ('api_key', 'oauth_token', 'certificate')
			),
			CONSTRAINT agent_credentials_status_check CHECK (
				status IN ('active', 'rotated', 'revoked')
			)
		);

		CREATE UNIQUE INDEX IF NOT EXISTS idx_agent_credentials_owner_target
			ON agent_credentials (owner_client_id, target_name)
			WHERE status = 'active';
	`)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `TRUNCATE agent_credentials, clients CASCADE`)
	require.NoError(t, err)
}

func newTestAgentClient(t *testing.T, pool *pgxpool.Pool) uuid.UUID {
	t.Helper()

	ctx := context.Background()
	var id uuid.UUID
	err := pool.QueryRow(ctx, `
		INSERT INTO clients (id, name, client_type, secret_hash, owner)
		VALUES (gen_random_uuid(), $1, 'agent', 'hash', 'test')
		RETURNING id`, uuid.New().String()).Scan(&id)
	require.NoError(t, err)
	return id
}

func newTestCredential(ownerClientID uuid.UUID) *domain.AgentCredential {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.AgentCredential{
		ID:             uuid.New(),
		OwnerClientID:  ownerClientID,
		TargetName:     "stripe-api",
		CredentialType: domain.CredentialTypeAPIKey,
		EncryptedBlob:  []byte("encrypted-secret-data"),
		Scopes:         []string{"payments:write"},
		Status:         domain.CredentialStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

// ────────────────────────────────────────────────────────────────────────────
// AgentCredentialRepository tests
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresAgentCredentialRepository_Create(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)
	ownerID := newTestAgentClient(t, pool)

	cred := newTestCredential(ownerID)
	created, err := repo.Create(context.Background(), cred)
	require.NoError(t, err)

	assert.Equal(t, cred.ID, created.ID)
	assert.Equal(t, cred.OwnerClientID, created.OwnerClientID)
	assert.Equal(t, cred.TargetName, created.TargetName)
	assert.Equal(t, cred.CredentialType, created.CredentialType)
	assert.Equal(t, cred.EncryptedBlob, created.EncryptedBlob)
	assert.Equal(t, cred.Scopes, created.Scopes)
	assert.Equal(t, domain.CredentialStatusActive, created.Status)
}

func TestPostgresAgentCredentialRepository_GetByID(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)
	ownerID := newTestAgentClient(t, pool)
	ctx := context.Background()

	cred := newTestCredential(ownerID)
	_, err := repo.Create(ctx, cred)
	require.NoError(t, err)

	found, err := repo.GetByID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, cred.ID, found.ID)
	assert.Equal(t, cred.TargetName, found.TargetName)
}

func TestPostgresAgentCredentialRepository_GetByID_NotFound(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)

	_, err := repo.GetByID(context.Background(), uuid.New())
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresAgentCredentialRepository_ListByOwner(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)
	ctx := context.Background()
	ownerID := newTestAgentClient(t, pool)

	cred1 := newTestCredential(ownerID)
	cred2 := newTestCredential(ownerID)
	cred2.ID = uuid.New()
	cred2.TargetName = "github-api"

	_, err := repo.Create(ctx, cred1)
	require.NoError(t, err)
	_, err = repo.Create(ctx, cred2)
	require.NoError(t, err)

	list, err := repo.ListByOwner(ctx, ownerID)
	require.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestPostgresAgentCredentialRepository_ListByOwner_Empty(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)

	list, err := repo.ListByOwner(context.Background(), uuid.New())
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestPostgresAgentCredentialRepository_Update(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)
	ctx := context.Background()
	ownerID := newTestAgentClient(t, pool)

	cred := newTestCredential(ownerID)
	_, err := repo.Create(ctx, cred)
	require.NoError(t, err)

	cred.EncryptedBlob = []byte("updated-encrypted-data")
	cred.Scopes = []string{"payments:read", "payments:write"}
	now := time.Now().UTC().Truncate(time.Microsecond)
	cred.LastRotatedAt = &now

	updated, err := repo.Update(ctx, cred)
	require.NoError(t, err)
	assert.Equal(t, cred.EncryptedBlob, updated.EncryptedBlob)
	assert.Equal(t, cred.Scopes, updated.Scopes)
	assert.NotNil(t, updated.LastRotatedAt)
}

func TestPostgresAgentCredentialRepository_Delete(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)
	ctx := context.Background()
	ownerID := newTestAgentClient(t, pool)

	cred := newTestCredential(ownerID)
	_, err := repo.Create(ctx, cred)
	require.NoError(t, err)

	err = repo.Delete(ctx, cred.ID)
	require.NoError(t, err)

	// Second delete should return ErrAlreadyDeleted.
	err = repo.Delete(ctx, cred.ID)
	assert.ErrorIs(t, err, storage.ErrAlreadyDeleted)
}

func TestPostgresAgentCredentialRepository_Delete_NotFound(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)

	err := repo.Delete(context.Background(), uuid.New())
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresAgentCredentialRepository_GetForBrokering(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)
	ctx := context.Background()
	ownerID := newTestAgentClient(t, pool)

	cred := newTestCredential(ownerID)
	_, err := repo.Create(ctx, cred)
	require.NoError(t, err)

	found, err := repo.GetForBrokering(ctx, ownerID, "stripe-api")
	require.NoError(t, err)
	assert.Equal(t, cred.ID, found.ID)
	assert.Equal(t, cred.EncryptedBlob, found.EncryptedBlob)
}

func TestPostgresAgentCredentialRepository_GetForBrokering_NotFound(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)

	_, err := repo.GetForBrokering(context.Background(), uuid.New(), "stripe-api")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresAgentCredentialRepository_GetForBrokering_AfterDelete(t *testing.T) {
	pool := credentialTestPool(t)
	repo := storage.NewPostgresAgentCredentialRepository(pool)
	ctx := context.Background()
	ownerID := newTestAgentClient(t, pool)

	cred := newTestCredential(ownerID)
	_, err := repo.Create(ctx, cred)
	require.NoError(t, err)

	err = repo.Delete(ctx, cred.ID)
	require.NoError(t, err)

	// Revoked credential should not be returned by GetForBrokering.
	_, err = repo.GetForBrokering(ctx, ownerID, "stripe-api")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}
