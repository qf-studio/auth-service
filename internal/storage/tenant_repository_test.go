package storage

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestScanTenant_ErrNoRows(t *testing.T) {
	mockRow := &errTenantRow{err: pgx.ErrNoRows}
	_, err := scanTenant(mockRow)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestScanTenant_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.New()
	config := domain.TenantConfig{
		AllowedOAuthProviders: []string{"google"},
	}
	configJSON, err := json.Marshal(config)
	require.NoError(t, err)

	row := &fakeTenantRow{
		id:        id,
		name:      "Acme Corp",
		slug:      "acme-corp",
		config:    configJSON,
		status:    domain.TenantStatusActive,
		createdAt: now,
		updatedAt: now,
	}

	tenant, err := scanTenant(row)
	require.NoError(t, err)
	assert.Equal(t, id, tenant.ID)
	assert.Equal(t, "Acme Corp", tenant.Name)
	assert.Equal(t, "acme-corp", tenant.Slug)
	assert.Equal(t, domain.TenantStatusActive, tenant.Status)
	assert.Equal(t, []string{"google"}, tenant.Config.AllowedOAuthProviders)
	assert.Equal(t, now, tenant.CreatedAt)
	assert.Equal(t, now, tenant.UpdatedAt)
}

func TestScanTenant_OtherError(t *testing.T) {
	mockRow := &errTenantRow{err: assert.AnError}
	_, err := scanTenant(mockRow)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
}

// errTenantRow implements pgx.Row returning the configured error.
type errTenantRow struct {
	err error
}

func (r *errTenantRow) Scan(_ ...interface{}) error {
	return r.err
}

// fakeTenantRow implements pgx.Row, populating scan destinations with preset values.
type fakeTenantRow struct {
	id        uuid.UUID
	name      string
	slug      string
	config    []byte
	status    domain.TenantStatus
	createdAt time.Time
	updatedAt time.Time
}

func (r *fakeTenantRow) Scan(dest ...interface{}) error {
	if len(dest) != 7 {
		return pgx.ErrNoRows
	}
	*dest[0].(*uuid.UUID) = r.id
	*dest[1].(*string) = r.name
	*dest[2].(*string) = r.slug
	*dest[3].(*[]byte) = r.config
	*dest[4].(*domain.TenantStatus) = r.status
	*dest[5].(*time.Time) = r.createdAt
	*dest[6].(*time.Time) = r.updatedAt
	return nil
}

// Verify the concrete type satisfies the interface at compile time.
var _ TenantRepository = (*PostgresTenantRepository)(nil)
