-- 000015_create_tenants_table.up.sql
-- Multi-tenancy: stores tenant records for tenant resolution middleware.

CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT        PRIMARY KEY,
    slug       TEXT        NOT NULL UNIQUE,
    name       TEXT        NOT NULL,
    active     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at TIMESTAMPTZ
);

-- Fast lookup by slug (used by tenant resolution middleware).
CREATE INDEX IF NOT EXISTS idx_tenants_slug ON tenants (slug) WHERE deleted_at IS NULL;

-- List active tenants sorted by creation time.
CREATE INDEX IF NOT EXISTS idx_tenants_active ON tenants (active, created_at DESC) WHERE deleted_at IS NULL;
