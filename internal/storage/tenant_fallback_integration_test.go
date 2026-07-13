package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

// TestTenantFallback_RegisterLoginRoundTrip proves that user registration and
// login succeed against real Postgres when TenantMiddleware is not wired
// (i.e. the context carries no tenant ID). Before the Nil->Default fallback
// in domain.TenantIDFromContext, this failed the tenant_id FK to tenants(id)
// because uuid.Nil doesn't match any seeded tenant row.
func TestTenantFallback_RegisterLoginRoundTrip(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresUserRepository(pool)
	hasher := password.New(nil)

	// No TenantMiddleware wired: plain background context, no tenant on it.
	ctx := context.Background()
	tenantID := domain.TenantIDFromContext(ctx)
	require.Equal(t, domain.DefaultTenantID, tenantID)

	hash, err := hasher.Hash("super-secure-password-123")
	require.NoError(t, err)

	now := time.Now().UTC()
	user := &domain.User{
		ID:                "usr_tenant_fallback_test",
		TenantID:          tenantID,
		Email:             "tenant-fallback@example.com",
		PasswordHash:      hash,
		Name:              "Fallback User",
		Roles:             []string{"user"},
		PasswordChangedAt: &now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	// "Registration": insert should not FK-fail against the Default tenant.
	created, err := repo.Create(ctx, user)
	require.NoError(t, err)
	assert.Equal(t, domain.DefaultTenantID, created.TenantID)

	// "Login": lookup by email using the same fallback tenant ID, then
	// verify the password as the login flow would.
	loginTenantID := domain.TenantIDFromContext(context.Background())
	found, err := repo.FindByEmail(ctx, loginTenantID, user.Email)
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID)

	ok, err := hasher.Verify("super-secure-password-123", user.PasswordHash)
	require.NoError(t, err)
	assert.True(t, ok)
}
