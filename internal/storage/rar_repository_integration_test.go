package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ────────────────────────────────────────────────────────────────────────────
// RARRepository tests
// ────────────────────────────────────────────────────────────────────────────

func newTestRARResourceType(typeName string) *domain.RARResourceType {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return &domain.RARResourceType{
		ID:               uuid.New(),
		TenantID:         domain.DefaultTenantID,
		Type:             typeName,
		Description:      typeName + " authorization",
		AllowedActions:   []string{"read", "write"},
		AllowedDataTypes: []string{},
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

func TestPostgresRARRepository_ResourceTypeCRUD(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRARRepository(pool)
	ctx := context.Background()
	tid := domain.DefaultTenantID

	// Create
	rt := newTestRARResourceType("payment_initiation")
	created, err := repo.CreateResourceType(ctx, rt)
	require.NoError(t, err)
	assert.Equal(t, rt.ID, created.ID)
	assert.Equal(t, rt.Type, created.Type)
	assert.Equal(t, rt.Description, created.Description)
	assert.Equal(t, rt.AllowedActions, created.AllowedActions)

	// FindByID
	found, err := repo.FindResourceTypeByID(ctx, tid, rt.ID)
	require.NoError(t, err)
	assert.Equal(t, rt.Type, found.Type)

	// FindByType
	found, err = repo.FindResourceTypeByType(ctx, tid, "payment_initiation")
	require.NoError(t, err)
	assert.Equal(t, rt.ID, found.ID)

	// FindByType not found
	_, err = repo.FindResourceTypeByType(ctx, tid, "nonexistent")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// List
	rt2 := newTestRARResourceType("account_information")
	_, err = repo.CreateResourceType(ctx, rt2)
	require.NoError(t, err)

	types, err := repo.ListResourceTypes(ctx, tid)
	require.NoError(t, err)
	assert.Len(t, types, 2)
	assert.Equal(t, "account_information", types[0].Type)
	assert.Equal(t, "payment_initiation", types[1].Type)

	// Update
	rt.Description = "Updated description"
	rt.AllowedActions = []string{"initiate"}
	updated, err := repo.UpdateResourceType(ctx, rt)
	require.NoError(t, err)
	assert.Equal(t, "Updated description", updated.Description)
	assert.Equal(t, []string{"initiate"}, updated.AllowedActions)

	// Update not found
	missing := &domain.RARResourceType{ID: uuid.New(), TenantID: tid}
	_, err = repo.UpdateResourceType(ctx, missing)
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Duplicate type
	dup := newTestRARResourceType("payment_initiation")
	_, err = repo.CreateResourceType(ctx, dup)
	assert.ErrorIs(t, err, storage.ErrDuplicateRARType)

	// Delete
	err = repo.DeleteResourceType(ctx, tid, rt.ID)
	require.NoError(t, err)

	_, err = repo.FindResourceTypeByID(ctx, tid, rt.ID)
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Delete not found
	err = repo.DeleteResourceType(ctx, tid, uuid.New())
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresRARRepository_ClientTypeAssociations(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresRARRepository(pool)
	clientRepo := storage.NewPostgresClientRepository(pool)
	ctx := context.Background()
	tid := domain.DefaultTenantID

	// Create a client
	client := newTestClient()
	_, err := clientRepo.Create(ctx, client)
	require.NoError(t, err)

	// Create resource types
	rt1 := newTestRARResourceType("payment_initiation")
	_, err = repo.CreateResourceType(ctx, rt1)
	require.NoError(t, err)

	rt2 := newTestRARResourceType("account_information")
	_, err = repo.CreateResourceType(ctx, rt2)
	require.NoError(t, err)

	// Initially no allowed types
	types, err := repo.ListClientAllowedTypes(ctx, tid, client.ID)
	require.NoError(t, err)
	assert.Empty(t, types)

	allowed, err := repo.IsClientTypeAllowed(ctx, tid, client.ID, "payment_initiation")
	require.NoError(t, err)
	assert.False(t, allowed)

	// Allow types
	err = repo.AllowClientType(ctx, tid, client.ID, rt1.ID)
	require.NoError(t, err)

	err = repo.AllowClientType(ctx, tid, client.ID, rt2.ID)
	require.NoError(t, err)

	// Duplicate association
	err = repo.AllowClientType(ctx, tid, client.ID, rt1.ID)
	assert.ErrorIs(t, err, storage.ErrDuplicateClientRARType)

	// List allowed types
	types, err = repo.ListClientAllowedTypes(ctx, tid, client.ID)
	require.NoError(t, err)
	assert.Len(t, types, 2)

	// Check allowed
	allowed, err = repo.IsClientTypeAllowed(ctx, tid, client.ID, "payment_initiation")
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = repo.IsClientTypeAllowed(ctx, tid, client.ID, "nonexistent")
	require.NoError(t, err)
	assert.False(t, allowed)

	// Revoke type
	err = repo.RevokeClientType(ctx, tid, client.ID, rt1.ID)
	require.NoError(t, err)

	allowed, err = repo.IsClientTypeAllowed(ctx, tid, client.ID, "payment_initiation")
	require.NoError(t, err)
	assert.False(t, allowed)

	// Revoke not found
	err = repo.RevokeClientType(ctx, tid, client.ID, rt1.ID)
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Cascade: deleting resource type removes associations
	types, err = repo.ListClientAllowedTypes(ctx, tid, client.ID)
	require.NoError(t, err)
	assert.Len(t, types, 1)

	err = repo.DeleteResourceType(ctx, tid, rt2.ID)
	require.NoError(t, err)

	types, err = repo.ListClientAllowedTypes(ctx, tid, client.ID)
	require.NoError(t, err)
	assert.Empty(t, types)
}
