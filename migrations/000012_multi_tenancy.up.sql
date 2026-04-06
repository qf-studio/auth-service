-- 000012_multi_tenancy.up.sql
-- Multi-tenancy: tenants table, tenant_id on all entity tables, RLS policies, composite indexes.

BEGIN;

-- --------------------------------------------------------------------------
-- 1. Tenant status enum and tenants table
-- --------------------------------------------------------------------------

CREATE TYPE tenant_status AS ENUM ('active', 'suspended', 'deleted');

CREATE TABLE tenants (
    id         UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT          NOT NULL,
    slug       TEXT          NOT NULL,
    config     JSONB         NOT NULL DEFAULT '{}',
    status     tenant_status NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ   NOT NULL DEFAULT now(),

    CONSTRAINT tenants_slug_unique UNIQUE (slug),
    CONSTRAINT tenants_name_not_empty CHECK (name <> ''),
    CONSTRAINT tenants_slug_not_empty CHECK (slug <> '')
);

CREATE INDEX idx_tenants_slug ON tenants (slug);
CREATE INDEX idx_tenants_status ON tenants (status) WHERE status = 'active';

-- Seed a default tenant so existing rows can be backfilled.
INSERT INTO tenants (id, name, slug, config, status)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'Default',
    'default',
    '{}',
    'active'
);

-- --------------------------------------------------------------------------
-- 2. Add tenant_id column to every entity table
--    Pattern: add nullable → backfill → set NOT NULL → add FK
-- --------------------------------------------------------------------------

-- users
ALTER TABLE users ADD COLUMN tenant_id UUID;
UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT fk_users_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- clients
ALTER TABLE clients ADD COLUMN tenant_id UUID;
UPDATE clients SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE clients ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE clients ADD CONSTRAINT fk_clients_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- refresh_tokens
ALTER TABLE refresh_tokens ADD COLUMN tenant_id UUID;
UPDATE refresh_tokens SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE refresh_tokens ADD CONSTRAINT fk_refresh_tokens_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- webhooks
ALTER TABLE webhooks ADD COLUMN tenant_id UUID;
UPDATE webhooks SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE webhooks ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE webhooks ADD CONSTRAINT fk_webhooks_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- webhook_deliveries
ALTER TABLE webhook_deliveries ADD COLUMN tenant_id UUID;
UPDATE webhook_deliveries SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE webhook_deliveries ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE webhook_deliveries ADD CONSTRAINT fk_webhook_deliveries_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- audit_logs
ALTER TABLE audit_logs ADD COLUMN tenant_id UUID;
UPDATE audit_logs SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE audit_logs ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- mfa_secrets
ALTER TABLE mfa_secrets ADD COLUMN tenant_id UUID;
UPDATE mfa_secrets SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE mfa_secrets ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE mfa_secrets ADD CONSTRAINT fk_mfa_secrets_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- mfa_backup_codes
ALTER TABLE mfa_backup_codes ADD COLUMN tenant_id UUID;
UPDATE mfa_backup_codes SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE mfa_backup_codes ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE mfa_backup_codes ADD CONSTRAINT fk_mfa_backup_codes_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- oauth_accounts
ALTER TABLE oauth_accounts ADD COLUMN tenant_id UUID;
UPDATE oauth_accounts SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE oauth_accounts ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE oauth_accounts ADD CONSTRAINT fk_oauth_accounts_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- password_history
ALTER TABLE password_history ADD COLUMN tenant_id UUID;
UPDATE password_history SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE password_history ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE password_history ADD CONSTRAINT fk_password_history_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- casbin_policies
ALTER TABLE casbin_policies ADD COLUMN tenant_id UUID;
UPDATE casbin_policies SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE casbin_policies ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE casbin_policies ADD CONSTRAINT fk_casbin_policies_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- rar_resource_types
ALTER TABLE rar_resource_types ADD COLUMN tenant_id UUID;
UPDATE rar_resource_types SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE rar_resource_types ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE rar_resource_types ADD CONSTRAINT fk_rar_resource_types_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- client_rar_allowed_types
ALTER TABLE client_rar_allowed_types ADD COLUMN tenant_id UUID;
UPDATE client_rar_allowed_types SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE client_rar_allowed_types ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE client_rar_allowed_types ADD CONSTRAINT fk_client_rar_allowed_types_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- agent_credentials
ALTER TABLE agent_credentials ADD COLUMN tenant_id UUID;
UPDATE agent_credentials SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE agent_credentials ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE agent_credentials ADD CONSTRAINT fk_agent_credentials_tenant
    FOREIGN KEY (tenant_id) REFERENCES tenants (id);

-- --------------------------------------------------------------------------
-- 3. Update unique constraints to be tenant-scoped
-- --------------------------------------------------------------------------

-- users: email unique per tenant (was globally unique)
ALTER TABLE users DROP CONSTRAINT users_email_unique;
ALTER TABLE users ADD CONSTRAINT users_tenant_email_unique UNIQUE (tenant_id, email);

-- clients: name unique per tenant (was globally unique)
ALTER TABLE clients DROP CONSTRAINT clients_name_unique;
ALTER TABLE clients ADD CONSTRAINT clients_tenant_name_unique UNIQUE (tenant_id, name);

-- rar_resource_types: type unique per tenant (was globally unique)
ALTER TABLE rar_resource_types DROP CONSTRAINT rar_resource_types_type_key;
ALTER TABLE rar_resource_types ADD CONSTRAINT rar_resource_types_tenant_type_unique UNIQUE (tenant_id, type);

-- oauth_accounts: provider+provider_user_id unique per tenant
ALTER TABLE oauth_accounts DROP CONSTRAINT oauth_accounts_provider_provider_user_id_unique;
ALTER TABLE oauth_accounts ADD CONSTRAINT oauth_accounts_tenant_provider_user_unique
    UNIQUE (tenant_id, provider, provider_user_id);

-- mfa_secrets: user+type unique per tenant (partial index)
DROP INDEX idx_mfa_secrets_user_type_active;
CREATE UNIQUE INDEX idx_mfa_secrets_tenant_user_type_active
    ON mfa_secrets (tenant_id, user_id, type) WHERE deleted_at IS NULL;

-- agent_credentials: owner+target+type unique per tenant (partial index)
DROP INDEX idx_agent_credentials_owner_target_type;
CREATE UNIQUE INDEX idx_agent_credentials_tenant_owner_target_type
    ON agent_credentials (tenant_id, owner_client_id, target_name, credential_type)
    WHERE status = 'active';

-- --------------------------------------------------------------------------
-- 4. Composite indexes including tenant_id for query performance
-- --------------------------------------------------------------------------

-- users
CREATE INDEX idx_users_tenant_id ON users (tenant_id);
CREATE INDEX idx_users_tenant_email ON users (tenant_id, email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_tenant_locked ON users (tenant_id, locked) WHERE deleted_at IS NULL;

-- clients
CREATE INDEX idx_clients_tenant_id ON clients (tenant_id);
CREATE INDEX idx_clients_tenant_status ON clients (tenant_id, status);
CREATE INDEX idx_clients_tenant_owner ON clients (tenant_id, owner);

-- refresh_tokens
CREATE INDEX idx_refresh_tokens_tenant_id ON refresh_tokens (tenant_id);
CREATE INDEX idx_refresh_tokens_tenant_user ON refresh_tokens (tenant_id, user_id);

-- webhooks
CREATE INDEX idx_webhooks_tenant_id ON webhooks (tenant_id);
CREATE INDEX idx_webhooks_tenant_active ON webhooks (tenant_id, active) WHERE active = true;

-- webhook_deliveries
CREATE INDEX idx_webhook_deliveries_tenant_id ON webhook_deliveries (tenant_id);

-- audit_logs
CREATE INDEX idx_audit_logs_tenant_id ON audit_logs (tenant_id);
CREATE INDEX idx_audit_logs_tenant_actor ON audit_logs (tenant_id, actor_id, created_at DESC);
CREATE INDEX idx_audit_logs_tenant_target ON audit_logs (tenant_id, target_id, created_at DESC);
CREATE INDEX idx_audit_logs_tenant_event ON audit_logs (tenant_id, event_type, created_at DESC);

-- mfa_secrets
CREATE INDEX idx_mfa_secrets_tenant_id ON mfa_secrets (tenant_id);
CREATE INDEX idx_mfa_secrets_tenant_user ON mfa_secrets (tenant_id, user_id);

-- mfa_backup_codes
CREATE INDEX idx_mfa_backup_codes_tenant_id ON mfa_backup_codes (tenant_id);
CREATE INDEX idx_mfa_backup_codes_tenant_user ON mfa_backup_codes (tenant_id, user_id);

-- oauth_accounts
CREATE INDEX idx_oauth_accounts_tenant_id ON oauth_accounts (tenant_id);
CREATE INDEX idx_oauth_accounts_tenant_user ON oauth_accounts (tenant_id, user_id);

-- password_history
CREATE INDEX idx_password_history_tenant_id ON password_history (tenant_id);
CREATE INDEX idx_password_history_tenant_user ON password_history (tenant_id, user_id, created_at DESC);

-- casbin_policies
CREATE INDEX idx_casbin_policies_tenant_id ON casbin_policies (tenant_id);
CREATE INDEX idx_casbin_policies_tenant_lookup ON casbin_policies (tenant_id, ptype, v0, v1, v2);

-- rar_resource_types
CREATE INDEX idx_rar_resource_types_tenant_id ON rar_resource_types (tenant_id);

-- client_rar_allowed_types
CREATE INDEX idx_client_rar_allowed_types_tenant_id ON client_rar_allowed_types (tenant_id);
CREATE INDEX idx_client_rar_allowed_types_tenant_client ON client_rar_allowed_types (tenant_id, client_id);

-- agent_credentials
CREATE INDEX idx_agent_credentials_tenant_id ON agent_credentials (tenant_id);
CREATE INDEX idx_agent_credentials_tenant_owner ON agent_credentials (tenant_id, owner_client_id);
CREATE INDEX idx_agent_credentials_tenant_status ON agent_credentials (tenant_id, status) WHERE status = 'active';

-- --------------------------------------------------------------------------
-- 5. Row-Level Security policies
--    All policies check: tenant_id = current_setting('app.current_tenant_id')::uuid
--    Superusers and the migration role bypass RLS by default.
-- --------------------------------------------------------------------------

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_users ON users
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_clients ON clients
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_refresh_tokens ON refresh_tokens
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_webhooks ON webhooks
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_webhook_deliveries ON webhook_deliveries
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_audit_logs ON audit_logs
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE mfa_secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_mfa_secrets ON mfa_secrets
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE mfa_backup_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_mfa_backup_codes ON mfa_backup_codes
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE oauth_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_oauth_accounts ON oauth_accounts
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE password_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_password_history ON password_history
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE casbin_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_casbin_policies ON casbin_policies
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE rar_resource_types ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_rar_resource_types ON rar_resource_types
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE client_rar_allowed_types ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_client_rar_allowed_types ON client_rar_allowed_types
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

ALTER TABLE agent_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_agent_credentials ON agent_credentials
    USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid);

COMMIT;
