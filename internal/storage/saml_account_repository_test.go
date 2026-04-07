package storage

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanSAMLAccount_ErrNoRows(t *testing.T) {
	mockRow := &errSAMLAccountRow{err: pgx.ErrNoRows}
	_, err := scanSAMLAccount(mockRow)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestScanSAMLAccount_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.New()
	tenantID := uuid.New()
	userID := uuid.New()
	idpID := uuid.New()
	row := &fakeSAMLAccountRow{
		id:           id,
		tenantID:     tenantID,
		userID:       userID,
		idpID:        idpID,
		nameID:       "user@example.com",
		sessionIndex: "session-123",
		attrJSON:     []byte(`{"email":"user@example.com","name":"Test User"}`),
		createdAt:    now,
		updatedAt:    now,
	}

	acct, err := scanSAMLAccount(row)
	require.NoError(t, err)
	assert.Equal(t, id.String(), acct.ID)
	assert.Equal(t, tenantID, acct.TenantID)
	assert.Equal(t, userID.String(), acct.UserID)
	assert.Equal(t, idpID.String(), acct.IdPID)
	assert.Equal(t, "user@example.com", acct.NameID)
	assert.Equal(t, "session-123", acct.SessionIndex)
	assert.Equal(t, map[string]string{"email": "user@example.com", "name": "Test User"}, acct.CachedAttributes)
	assert.Equal(t, now, acct.CreatedAt)
	assert.Equal(t, now, acct.UpdatedAt)
}

func TestScanSAMLAccount_EmptyAttributes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := &fakeSAMLAccountRow{
		id:        uuid.New(),
		tenantID:  uuid.New(),
		userID:    uuid.New(),
		idpID:     uuid.New(),
		nameID:    "user@example.com",
		attrJSON:  []byte(`{}`),
		createdAt: now,
		updatedAt: now,
	}

	acct, err := scanSAMLAccount(row)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, acct.CachedAttributes)
}

func TestScanSAMLAccount_OtherError(t *testing.T) {
	mockRow := &errSAMLAccountRow{err: assert.AnError}
	_, err := scanSAMLAccount(mockRow)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
}

// errSAMLAccountRow implements pgx.Row returning the configured error.
type errSAMLAccountRow struct {
	err error
}

func (r *errSAMLAccountRow) Scan(_ ...interface{}) error {
	return r.err
}

// fakeSAMLAccountRow implements pgx.Row, populating scan destinations with preset values.
type fakeSAMLAccountRow struct {
	id           uuid.UUID
	tenantID     uuid.UUID
	userID       uuid.UUID
	idpID        uuid.UUID
	nameID       string
	sessionIndex string
	attrJSON     []byte
	createdAt    time.Time
	updatedAt    time.Time
}

func (r *fakeSAMLAccountRow) Scan(dest ...interface{}) error {
	if len(dest) != 9 {
		return pgx.ErrNoRows
	}
	*dest[0].(*uuid.UUID) = r.id
	*dest[1].(*uuid.UUID) = r.tenantID
	*dest[2].(*uuid.UUID) = r.userID
	*dest[3].(*uuid.UUID) = r.idpID
	*dest[4].(*string) = r.nameID
	*dest[5].(*string) = r.sessionIndex
	*dest[6].(*[]byte) = r.attrJSON
	*dest[7].(*time.Time) = r.createdAt
	*dest[8].(*time.Time) = r.updatedAt
	return nil
}
