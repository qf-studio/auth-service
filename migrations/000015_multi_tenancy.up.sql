-- 000015_multi_tenancy.up.sql
-- Adds multi-tenancy support: tenants table, tenant_id columns, RLS policies,
-- composite indexes, and per-tenant unique constraints.

BEGIN;

-- ============================================================================
-- 1. Create the tenants table
-- ============================================================================
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug            TEXT NOT NULL,
    name            TEXT NOT NULL,
    active          BOOLEAN NOT NULL DEFAULT true,

    -- Per-tenant password policy overrides (NULL = use system defaults)
    password_min_length    INTEGER,
    password_max_length    INTEGER,
    password_max_age_days  INTEGER,
    password_history_count INTEGER,

    -- MFA enforcement
    mfa_enforced    BOOLEAN NOT NULL DEFAULT false,

    -- Allowed OAuth providers (NULL = all allowed)
    allowed_oauth_providers TEXT[],

    -- Custom token TTLs in seconds (NULL = use system defaults)
    access_token_ttl  INTEGER,
    refresh_token_ttl INTEGER,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT tenants_slug_unique UNIQUE (slug)
);

CREATE INDEX idx_tenants_active ON tenants (active) WHERE active = true;

-- ============================================================================
-- 2. Add tenant_id to all existing tables
-- ============================================================================

-- A default tenant is required so existing rows can reference it.
-- The application must create a real default tenant during bootstrap;
-- this UUID is a deterministic placeholder used only during migration.
INSERT INTO tenants (id, slug, name, active)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default Tenant', true)
ON CONFLICT (slug) DO NOTHING;

-- -- users ------------------------------------------------------------------
ALTER TABLE users
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE users ALTER COLUMN tenant_id DROP DEFAULT;

-- Replace global email uniqueness with per-tenant uniqueness.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key;
ALTER TABLE users ADD CONSTRAINT users_email_tenant_unique UNIQUE (tenant_id, email);

ALTER TABLE users
    ADD CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_users_tenant_id ON users (tenant_id);

-- -- clients ----------------------------------------------------------------
ALTER TABLE clients
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE clients ALTER COLUMN tenant_id DROP DEFAULT;

-- Replace global name uniqueness with per-tenant uniqueness.
ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_name_key;
ALTER TABLE clients ADD CONSTRAINT clients_name_tenant_unique UNIQUE (tenant_id, name);

ALTER TABLE clients
    ADD CONSTRAINT fk_clients_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_clients_tenant_id ON clients (tenant_id);

-- -- refresh_tokens ---------------------------------------------------------
ALTER TABLE refresh_tokens
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE refresh_tokens ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE refresh_tokens
    ADD CONSTRAINT fk_refresh_tokens_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_refresh_tokens_tenant_id ON refresh_tokens (tenant_id);

-- -- oauth_accounts ---------------------------------------------------------
ALTER TABLE oauth_accounts
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE oauth_accounts ALTER COLUMN tenant_id DROP DEFAULT;

-- Provider+provider_user_id should be unique per tenant, not globally.
ALTER TABLE oauth_accounts DROP CONSTRAINT IF EXISTS oauth_accounts_provider_provider_user_id_key;
ALTER TABLE oauth_accounts ADD CONSTRAINT oauth_accounts_provider_tenant_unique
    UNIQUE (tenant_id, provider, provider_user_id);

ALTER TABLE oauth_accounts
    ADD CONSTRAINT fk_oauth_accounts_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_oauth_accounts_tenant_id ON oauth_accounts (tenant_id);

-- -- mfa_secrets ------------------------------------------------------------
ALTER TABLE mfa_secrets
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE mfa_secrets ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE mfa_secrets
    ADD CONSTRAINT fk_mfa_secrets_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_mfa_secrets_tenant_id ON mfa_secrets (tenant_id);

-- -- mfa_backup_codes -------------------------------------------------------
ALTER TABLE mfa_backup_codes
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE mfa_backup_codes ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE mfa_backup_codes
    ADD CONSTRAINT fk_mfa_backup_codes_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_mfa_backup_codes_tenant_id ON mfa_backup_codes (tenant_id);

-- -- webhooks ---------------------------------------------------------------
ALTER TABLE webhooks
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE webhooks ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE webhooks
    ADD CONSTRAINT fk_webhooks_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_webhooks_tenant_id ON webhooks (tenant_id);

-- -- webhook_deliveries -----------------------------------------------------
ALTER TABLE webhook_deliveries
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE webhook_deliveries ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE webhook_deliveries
    ADD CONSTRAINT fk_webhook_deliveries_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_webhook_deliveries_tenant_id ON webhook_deliveries (tenant_id);

-- -- casbin_policies --------------------------------------------------------
ALTER TABLE casbin_policies
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE casbin_policies ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE casbin_policies
    ADD CONSTRAINT fk_casbin_policies_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_casbin_policies_tenant_id ON casbin_policies (tenant_id);

-- -- audit_logs -------------------------------------------------------------
ALTER TABLE audit_logs
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE audit_logs ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE audit_logs
    ADD CONSTRAINT fk_audit_logs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

-- Composite index for tenant-scoped audit queries (replaces or supplements existing).
CREATE INDEX idx_audit_logs_tenant_id ON audit_logs (tenant_id);
CREATE INDEX idx_audit_logs_tenant_event ON audit_logs (tenant_id, event_type, created_at DESC);

-- -- saml_idp_configs -------------------------------------------------------
ALTER TABLE saml_idp_configs
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE saml_idp_configs ALTER COLUMN tenant_id DROP DEFAULT;

-- Entity ID should be unique per tenant, not globally.
ALTER TABLE saml_idp_configs DROP CONSTRAINT IF EXISTS saml_idp_configs_entity_id_key;
ALTER TABLE saml_idp_configs ADD CONSTRAINT saml_idp_configs_entity_tenant_unique
    UNIQUE (tenant_id, entity_id);

ALTER TABLE saml_idp_configs
    ADD CONSTRAINT fk_saml_idp_configs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_saml_idp_configs_tenant_id ON saml_idp_configs (tenant_id);

-- -- saml_accounts ----------------------------------------------------------
ALTER TABLE saml_accounts
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE saml_accounts ALTER COLUMN tenant_id DROP DEFAULT;

-- IdP+NameID should be unique per tenant.
ALTER TABLE saml_accounts DROP CONSTRAINT IF EXISTS saml_accounts_idp_id_name_id_key;
ALTER TABLE saml_accounts ADD CONSTRAINT saml_accounts_idp_name_tenant_unique
    UNIQUE (tenant_id, idp_id, name_id);

ALTER TABLE saml_accounts
    ADD CONSTRAINT fk_saml_accounts_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_saml_accounts_tenant_id ON saml_accounts (tenant_id);

-- -- rar_resource_types -----------------------------------------------------
ALTER TABLE rar_resource_types
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE rar_resource_types ALTER COLUMN tenant_id DROP DEFAULT;

-- Type should be unique per tenant, not globally.
ALTER TABLE rar_resource_types DROP CONSTRAINT IF EXISTS rar_resource_types_type_key;
ALTER TABLE rar_resource_types ADD CONSTRAINT rar_resource_types_type_tenant_unique
    UNIQUE (tenant_id, type);

ALTER TABLE rar_resource_types
    ADD CONSTRAINT fk_rar_resource_types_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_rar_resource_types_tenant_id ON rar_resource_types (tenant_id);

-- -- client_rar_allowed_types -----------------------------------------------
ALTER TABLE client_rar_allowed_types
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE client_rar_allowed_types ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE client_rar_allowed_types
    ADD CONSTRAINT fk_client_rar_allowed_types_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_client_rar_allowed_types_tenant_id ON client_rar_allowed_types (tenant_id);

-- -- agent_credentials (credential_vault) -----------------------------------
ALTER TABLE agent_credentials
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE agent_credentials ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE agent_credentials
    ADD CONSTRAINT fk_agent_credentials_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_agent_credentials_tenant_id ON agent_credentials (tenant_id);

-- -- password_history -------------------------------------------------------
ALTER TABLE password_history
    ADD COLUMN tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';

ALTER TABLE password_history ALTER COLUMN tenant_id DROP DEFAULT;

ALTER TABLE password_history
    ADD CONSTRAINT fk_password_history_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

CREATE INDEX idx_password_history_tenant_id ON password_history (tenant_id);

-- ============================================================================
-- 3. Row-Level Security (RLS) policies for tenant isolation
-- ============================================================================
-- RLS ensures that queries scoped to a tenant cannot access other tenants'
-- data, even if application-level filtering is bypassed. The application sets
-- the current tenant via: SET LOCAL app.current_tenant = '<tenant-id>';

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_users ON users
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_clients ON clients
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_refresh_tokens ON refresh_tokens
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE oauth_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_oauth_accounts ON oauth_accounts
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE mfa_secrets ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_mfa_secrets ON mfa_secrets
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE mfa_backup_codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_mfa_backup_codes ON mfa_backup_codes
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE webhooks ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_webhooks ON webhooks
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_webhook_deliveries ON webhook_deliveries
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE casbin_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_casbin_policies ON casbin_policies
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_audit_logs ON audit_logs
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE saml_idp_configs ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_saml_idp_configs ON saml_idp_configs
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE saml_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_saml_accounts ON saml_accounts
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE rar_resource_types ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_rar_resource_types ON rar_resource_types
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE client_rar_allowed_types ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_client_rar_allowed_types ON client_rar_allowed_types
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE agent_credentials ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_agent_credentials ON agent_credentials
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

ALTER TABLE password_history ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_password_history ON password_history
    USING (tenant_id = current_setting('app.current_tenant')::UUID);

COMMIT;
