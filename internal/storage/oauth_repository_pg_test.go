package storage

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestScanOAuthAccount_ErrNoRows(t *testing.T) {
	// scanOAuthAccount should map pgx.ErrNoRows to ErrNotFound.
	mockRow := &errRow{err: pgx.ErrNoRows}
	_, err := scanOAuthAccount(mockRow)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestScanOAuthAccount_Success(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	row := &fakeOAuthAccountRow{
		id:             "oa-1",
		userID:         "u-1",
		provider:       "google",
		providerUserID: "g-123",
		email:          "test@example.com",
		createdAt:      now,
	}

	account, err := scanOAuthAccount(row)
	require.NoError(t, err)
	assert.Equal(t, "oa-1", account.ID)
	assert.Equal(t, "u-1", account.UserID)
	assert.Equal(t, "google", account.Provider)
	assert.Equal(t, "g-123", account.ProviderUserID)
	assert.Equal(t, "test@example.com", account.Email)
	assert.Equal(t, now, account.CreatedAt)
}

// errRow implements pgx.Row returning the configured error.
type errRow struct {
	err error
}

func (r *errRow) Scan(_ ...interface{}) error {
	return r.err
}

// fakeOAuthAccountRow implements pgx.Row, populating scan destinations with preset values.
type fakeOAuthAccountRow struct {
	id, userID, provider, providerUserID, email string
	createdAt                                   time.Time
}

func (r *fakeOAuthAccountRow) Scan(dest ...interface{}) error {
	if len(dest) != 6 {
		return pgx.ErrNoRows
	}
	*dest[0].(*string) = r.id
	*dest[1].(*string) = r.userID
	*dest[2].(*string) = r.provider
	*dest[3].(*string) = r.providerUserID
	*dest[4].(*string) = r.email
	*dest[5].(*time.Time) = r.createdAt
	return nil
}

// Verify the concrete type satisfies the interface at compile time.
var _ OAuthAccountRepository = (*PostgresOAuthAccountRepository)(nil)

// Verify domain model fields align with scan order.
func TestOAuthAccountColumnCount(t *testing.T) {
	// oauthAccountColumns should have exactly 6 fields matching scanOAuthAccount.
	expected := "id, user_id, provider, provider_user_id, email, created_at"
	assert.Equal(t, expected, oauthAccountColumns)
}

func TestNewPostgresOAuthAccountRepository(t *testing.T) {
	repo := NewPostgresOAuthAccountRepository(nil)
	assert.NotNil(t, repo)
	assert.Nil(t, repo.pool)
}

// Verify the domain struct used by the repository has the expected fields.
func TestOAuthAccountDomainFields(t *testing.T) {
	now := time.Now().UTC()
	a := domain.OAuthAccount{
		ID:             "oa-1",
		UserID:         "u-1",
		Provider:       "github",
		ProviderUserID: "gh-456",
		Email:          "dev@example.com",
		CreatedAt:      now,
	}
	assert.Equal(t, "oa-1", a.ID)
	assert.Equal(t, "u-1", a.UserID)
	assert.Equal(t, "github", a.Provider)
	assert.Equal(t, "gh-456", a.ProviderUserID)
	assert.Equal(t, "dev@example.com", a.Email)
	assert.Equal(t, now, a.CreatedAt)
}
