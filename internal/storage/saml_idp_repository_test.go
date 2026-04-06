package storage

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanSAMLIdP_ErrNoRows(t *testing.T) {
	mockRow := &errSAMLIdPRow{err: pgx.ErrNoRows}
	_, err := scanSAMLIdP(mockRow)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestScanSAMLIdP_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.New()
	row := &fakeSAMLIdPRow{
		id:          id,
		entityID:    "https://idp.example.com/metadata",
		metadataURL: "https://idp.example.com/metadata",
		metadataXML: "<md:EntityDescriptor/>",
		ssoURL:      "https://idp.example.com/sso",
		sloURL:      "https://idp.example.com/slo",
		certificate: "MIIC...",
		name:        "Example IdP",
		attrJSON:    []byte(`{"email":"urn:oid:0.9.2342.19200300.100.1.3"}`),
		enabled:     true,
		createdAt:   now,
		updatedAt:   now,
	}

	idp, err := scanSAMLIdP(row)
	require.NoError(t, err)
	assert.Equal(t, id.String(), idp.ID)
	assert.Equal(t, "https://idp.example.com/metadata", idp.EntityID)
	assert.Equal(t, "https://idp.example.com/metadata", idp.MetadataURL)
	assert.Equal(t, "<md:EntityDescriptor/>", idp.MetadataXML)
	assert.Equal(t, "https://idp.example.com/sso", idp.SSOURL)
	assert.Equal(t, "https://idp.example.com/slo", idp.SLOURL)
	assert.Equal(t, "MIIC...", idp.Certificate)
	assert.Equal(t, "Example IdP", idp.Name)
	assert.Equal(t, map[string]string{"email": "urn:oid:0.9.2342.19200300.100.1.3"}, idp.AttributeMappings)
	assert.True(t, idp.Enabled)
	assert.Equal(t, now, idp.CreatedAt)
	assert.Equal(t, now, idp.UpdatedAt)
}

func TestScanSAMLIdP_EmptyAttributes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	id := uuid.New()
	row := &fakeSAMLIdPRow{
		id:          id,
		entityID:    "https://idp.example.com",
		ssoURL:      "https://idp.example.com/sso",
		certificate: "MIIC...",
		name:        "Example",
		attrJSON:    []byte(`{}`),
		enabled:     true,
		createdAt:   now,
		updatedAt:   now,
	}

	idp, err := scanSAMLIdP(row)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{}, idp.AttributeMappings)
}

func TestScanSAMLIdP_OtherError(t *testing.T) {
	mockRow := &errSAMLIdPRow{err: assert.AnError}
	_, err := scanSAMLIdP(mockRow)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrNotFound)
}

// errSAMLIdPRow implements pgx.Row returning the configured error.
type errSAMLIdPRow struct {
	err error
}

func (r *errSAMLIdPRow) Scan(_ ...interface{}) error {
	return r.err
}

// fakeSAMLIdPRow implements pgx.Row, populating scan destinations with preset values.
type fakeSAMLIdPRow struct {
	id          uuid.UUID
	entityID    string
	metadataURL string
	metadataXML string
	ssoURL      string
	sloURL      string
	certificate string
	name        string
	attrJSON    []byte
	enabled     bool
	createdAt   time.Time
	updatedAt   time.Time
}

func (r *fakeSAMLIdPRow) Scan(dest ...interface{}) error {
	if len(dest) != 12 {
		return pgx.ErrNoRows
	}
	*dest[0].(*uuid.UUID) = r.id
	*dest[1].(*string) = r.entityID
	*dest[2].(*string) = r.metadataURL
	*dest[3].(*string) = r.metadataXML
	*dest[4].(*string) = r.ssoURL
	*dest[5].(*string) = r.sloURL
	*dest[6].(*string) = r.certificate
	*dest[7].(*string) = r.name
	*dest[8].(*[]byte) = r.attrJSON
	*dest[9].(*bool) = r.enabled
	*dest[10].(*time.Time) = r.createdAt
	*dest[11].(*time.Time) = r.updatedAt
	return nil
}
