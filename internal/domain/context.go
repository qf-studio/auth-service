package domain

import (
	"context"

	"github.com/google/uuid"
)

type contextKey string

const tenantIDKey contextKey = "tenant_id"

// WithTenantID returns a new context carrying the given tenant ID.
func WithTenantID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantIDKey, id)
}

// TenantIDFromContext extracts the tenant ID from the context.
// Returns uuid.Nil if no tenant ID is set.
func TenantIDFromContext(ctx context.Context) uuid.UUID {
	if v, ok := ctx.Value(tenantIDKey).(uuid.UUID); ok {
		return v
	}
	return uuid.Nil
}
