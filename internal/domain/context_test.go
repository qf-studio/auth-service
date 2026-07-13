package domain_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestTenantIDFromContext_NoTenantSet(t *testing.T) {
	got := domain.TenantIDFromContext(context.Background())
	assert.Equal(t, domain.DefaultTenantID, got)
	assert.NotEqual(t, uuid.Nil, got)
}

func TestTenantIDFromContext_TenantSet(t *testing.T) {
	want := uuid.New()
	ctx := domain.WithTenantID(context.Background(), want)

	got := domain.TenantIDFromContext(ctx)

	assert.Equal(t, want, got)
}

func TestTenantIDFromContext_TenantSetToNil(t *testing.T) {
	ctx := domain.WithTenantID(context.Background(), uuid.Nil)

	got := domain.TenantIDFromContext(ctx)

	assert.Equal(t, uuid.Nil, got)
}
