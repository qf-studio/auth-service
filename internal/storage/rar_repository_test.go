package storage

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanRARResourceType_ErrNoRows(t *testing.T) {
	mockRow := &errRARRow{err: pgx.ErrNoRows}
	_, err := scanRARResourceType(mockRow)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestScanRARResourceType_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.New()
	row := &fakeRARResourceTypeRow{
		id:               id,
		typeName:         "payment_initiation",
		description:      "Payment initiation",
		allowedActions:   []string{"initiate", "status"},
		allowedDataTypes: []string{"balance"},
		createdAt:        now,
		updatedAt:        now,
	}

	rt, err := scanRARResourceType(row)
	require.NoError(t, err)
	assert.Equal(t, id, rt.ID)
	assert.Equal(t, "payment_initiation", rt.Type)
	assert.Equal(t, "Payment initiation", rt.Description)
	assert.Equal(t, []string{"initiate", "status"}, rt.AllowedActions)
	assert.Equal(t, []string{"balance"}, rt.AllowedDataTypes)
	assert.Equal(t, now, rt.CreatedAt)
	assert.Equal(t, now, rt.UpdatedAt)
}

func TestScanRARResourceType_OtherError(t *testing.T) {
	mockRow := &errRARRow{err: assert.AnError}
	_, err := scanRARResourceType(mockRow)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
}

// errRARRow implements pgx.Row returning the configured error.
type errRARRow struct {
	err error
}

func (r *errRARRow) Scan(_ ...interface{}) error {
	return r.err
}

// fakeRARResourceTypeRow implements pgx.Row, populating scan destinations with preset values.
type fakeRARResourceTypeRow struct {
	id               uuid.UUID
	typeName         string
	description      string
	allowedActions   []string
	allowedDataTypes []string
	createdAt        time.Time
	updatedAt        time.Time
}

func (r *fakeRARResourceTypeRow) Scan(dest ...interface{}) error {
	if len(dest) != 7 {
		return pgx.ErrNoRows
	}
	*dest[0].(*uuid.UUID) = r.id
	*dest[1].(*string) = r.typeName
	*dest[2].(*string) = r.description
	*dest[3].(*[]string) = r.allowedActions
	*dest[4].(*[]string) = r.allowedDataTypes
	*dest[5].(*time.Time) = r.createdAt
	*dest[6].(*time.Time) = r.updatedAt
	return nil
}
