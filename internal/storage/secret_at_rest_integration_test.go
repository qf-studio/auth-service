package storage_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/secretbox"
	"github.com/qf-studio/auth-service/internal/storage"
)

func testSecretBox(t *testing.T) *secretbox.Box {
	t.Helper()
	box, err := secretbox.New(bytes.Repeat([]byte{0x24}, secretbox.KeySize))
	require.NoError(t, err)
	return box
}

func ensureWebhooksTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS webhooks (
			id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id     UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001' REFERENCES tenants (id),
			url           TEXT NOT NULL,
			secret_hash   TEXT NOT NULL,
			event_types   TEXT[] NOT NULL DEFAULT '{}',
			active        BOOLEAN NOT NULL DEFAULT true,
			failure_count INTEGER NOT NULL DEFAULT 0,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
			updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
		);
		TRUNCATE webhooks CASCADE`)
	require.NoError(t, err)
}

func TestUserRepository_TokensStoredAsDigests(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()
	tid := domain.DefaultTenantID

	user := newTestUser()
	_, err := repo.Create(ctx, user)
	require.NoError(t, err)

	exp := time.Now().UTC().Add(time.Hour)
	require.NoError(t, repo.SetEmailVerifyToken(ctx, tid, user.ID, "raw-verify", exp))
	require.NoError(t, repo.SetPendingEmailChange(ctx, tid, user.ID, "new@test.com", "raw-change", exp, "raw-revert", exp))

	var verify, change, revert string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT email_verify_token, email_change_token, email_revert_token FROM users WHERE id = $1`, user.ID,
	).Scan(&verify, &change, &revert))
	assert.Equal(t, secretbox.Digest("raw-verify"), verify)
	assert.Equal(t, secretbox.Digest("raw-change"), change)
	assert.Equal(t, secretbox.Digest("raw-revert"), revert)

	// A value copied out of the database is not a usable token.
	_, err = repo.ConsumeEmailVerifyToken(ctx, tid, verify)
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = repo.ConsumeEmailChangeToken(ctx, tid, change)
	assert.ErrorIs(t, err, storage.ErrNotFound)
	_, err = repo.ConsumeEmailRevertToken(ctx, tid, revert)
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// The raw tokens still work.
	_, err = repo.ConsumeEmailVerifyToken(ctx, tid, "raw-verify")
	require.NoError(t, err)
	_, err = repo.ConsumeEmailChangeToken(ctx, tid, "raw-change")
	require.NoError(t, err)
}

func TestMFARepository_SecretEncryptedAtRest(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	repo := storage.NewPostgresMFARepository(pool, testSecretBox(t))
	ctx := context.Background()
	tid := domain.DefaultTenantID

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	secret := newTestMFASecret(user.ID)
	saved, err := repo.SaveSecret(ctx, secret)
	require.NoError(t, err)
	assert.Equal(t, secret.Secret, saved.Secret, "callers get the usable secret back")

	var stored string
	require.NoError(t, pool.QueryRow(ctx, `SELECT secret FROM mfa_secrets WHERE id = $1`, secret.ID).Scan(&stored))
	assert.True(t, secretbox.IsEncrypted(stored))
	assert.NotContains(t, stored, secret.Secret)

	got, err := repo.GetSecret(ctx, tid, user.ID)
	require.NoError(t, err)
	assert.Equal(t, secret.Secret, got.Secret)
}

func TestMFARepository_LegacyPlaintextRewrittenOnRead(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()
	tid := domain.DefaultTenantID

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	// Written before a key was configured.
	secret := newTestMFASecret(user.ID)
	_, err = storage.NewPostgresMFARepository(pool, nil).SaveSecret(ctx, secret)
	require.NoError(t, err)

	repo := storage.NewPostgresMFARepository(pool, testSecretBox(t))
	got, err := repo.GetSecret(ctx, tid, user.ID)
	require.NoError(t, err)
	assert.Equal(t, secret.Secret, got.Secret, "legacy row still verifies")

	var stored string
	require.NoError(t, pool.QueryRow(ctx, `SELECT secret FROM mfa_secrets WHERE id = $1`, secret.ID).Scan(&stored))
	assert.True(t, secretbox.IsEncrypted(stored), "legacy row is rewritten encrypted")

	again, err := repo.GetSecret(ctx, tid, user.ID)
	require.NoError(t, err)
	assert.Equal(t, secret.Secret, again.Secret)
}

func TestMFARepository_EncryptedRowWithoutKeyFails(t *testing.T) {
	pool := testPool(t)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	_, err = storage.NewPostgresMFARepository(pool, testSecretBox(t)).SaveSecret(ctx, newTestMFASecret(user.ID))
	require.NoError(t, err)

	_, err = storage.NewPostgresMFARepository(pool, nil).GetSecret(ctx, domain.DefaultTenantID, user.ID)
	assert.ErrorIs(t, err, secretbox.ErrKeyRequired)
}

func TestWebhookRepository_SecretEncryptedAtRest(t *testing.T) {
	pool := testPool(t)
	ensureWebhooksTable(t, pool)
	repo := storage.NewPostgresWebhookRepository(pool, testSecretBox(t))
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	wh := &domain.Webhook{
		ID: uuid.New(), TenantID: domain.DefaultTenantID, URL: "https://example.test/hook",
		SecretHash: "whsec_fake_secret", EventTypes: []string{"user.created"}, Active: true,
		CreatedAt: now, UpdatedAt: now,
	}
	created, err := repo.Create(ctx, wh)
	require.NoError(t, err)
	assert.Equal(t, "whsec_fake_secret", created.SecretHash)

	var stored string
	require.NoError(t, pool.QueryRow(ctx, `SELECT secret_hash FROM webhooks WHERE id = $1`, wh.ID).Scan(&stored))
	assert.True(t, secretbox.IsEncrypted(stored))

	found, err := repo.FindByID(ctx, domain.DefaultTenantID, wh.ID)
	require.NoError(t, err)
	assert.Equal(t, "whsec_fake_secret", found.SecretHash)

	active, err := repo.FindActiveByEventType(ctx, domain.DefaultTenantID, "user.created")
	require.NoError(t, err)
	require.Len(t, active, 1)
	assert.Equal(t, "whsec_fake_secret", active[0].SecretHash)

	listed, _, err := repo.List(ctx, domain.DefaultTenantID, 10, 0, false)
	require.NoError(t, err)
	require.Len(t, listed, 1)
	assert.Equal(t, "whsec_fake_secret", listed[0].SecretHash)
}

func TestEncryptExistingSecrets(t *testing.T) {
	pool := testPool(t)
	ensureWebhooksTable(t, pool)
	userRepo := storage.NewPostgresUserRepository(pool)
	ctx := context.Background()
	box := testSecretBox(t)

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)
	secret := newTestMFASecret(user.ID)
	_, err = storage.NewPostgresMFARepository(pool, nil).SaveSecret(ctx, secret)
	require.NoError(t, err)

	whID := uuid.New()
	_, err = pool.Exec(ctx, `INSERT INTO webhooks (id, url, secret_hash) VALUES ($1, 'https://example.test/h', 'whsec_legacy')`, whID)
	require.NoError(t, err)

	report, err := storage.EncryptExistingSecrets(ctx, pool, box)
	require.NoError(t, err)
	assert.Equal(t, 1, report.MFASecrets)
	assert.Equal(t, 1, report.Webhooks)

	var mfaStored, whStored string
	require.NoError(t, pool.QueryRow(ctx, `SELECT secret FROM mfa_secrets WHERE id = $1`, secret.ID).Scan(&mfaStored))
	require.NoError(t, pool.QueryRow(ctx, `SELECT secret_hash FROM webhooks WHERE id = $1`, whID).Scan(&whStored))
	for _, v := range []string{mfaStored, whStored} {
		assert.True(t, secretbox.IsEncrypted(v))
	}
	got, err := box.Decrypt(mfaStored)
	require.NoError(t, err)
	assert.Equal(t, secret.Secret, got)

	// Idempotent.
	report, err = storage.EncryptExistingSecrets(ctx, pool, box)
	require.NoError(t, err)
	assert.Equal(t, storage.SecretEncryptionReport{}, report)

	_, err = storage.EncryptExistingSecrets(ctx, pool, nil)
	assert.Error(t, err)
}
