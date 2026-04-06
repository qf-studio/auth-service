-- 000012_multi_tenancy.down.sql
-- Rollback: remove RLS policies, drop tenant_id columns, restore original constraints, drop tenants table.

BEGIN;

-- --------------------------------------------------------------------------
-- 1. Drop RLS policies and disable RLS
-- --------------------------------------------------------------------------

DROP POLICY IF EXISTS tenant_isolation_users ON users;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_clients ON clients;
ALTER TABLE clients DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_refresh_tokens ON refresh_tokens;
ALTER TABLE refresh_tokens DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_webhooks ON webhooks;
ALTER TABLE webhooks DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_webhook_deliveries ON webhook_deliveries;
ALTER TABLE webhook_deliveries DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_audit_logs ON audit_logs;
ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mfa_secrets ON mfa_secrets;
ALTER TABLE mfa_secrets DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mfa_backup_codes ON mfa_backup_codes;
ALTER TABLE mfa_backup_codes DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_oauth_accounts ON oauth_accounts;
ALTER TABLE oauth_accounts DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_password_history ON password_history;
ALTER TABLE password_history DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_casbin_policies ON casbin_policies;
ALTER TABLE casbin_policies DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_rar_resource_types ON rar_resource_types;
ALTER TABLE rar_resource_types DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_client_rar_allowed_types ON client_rar_allowed_types;
ALTER TABLE client_rar_allowed_types DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_agent_credentials ON agent_credentials;
ALTER TABLE agent_credentials DISABLE ROW LEVEL SECURITY;

-- --------------------------------------------------------------------------
-- 2. Drop tenant-scoped composite indexes
-- --------------------------------------------------------------------------

DROP INDEX IF EXISTS idx_users_tenant_id;
DROP INDEX IF EXISTS idx_users_tenant_email;
DROP INDEX IF EXISTS idx_users_tenant_locked;

DROP INDEX IF EXISTS idx_clients_tenant_id;
DROP INDEX IF EXISTS idx_clients_tenant_status;
DROP INDEX IF EXISTS idx_clients_tenant_owner;

DROP INDEX IF EXISTS idx_refresh_tokens_tenant_id;
DROP INDEX IF EXISTS idx_refresh_tokens_tenant_user;

DROP INDEX IF EXISTS idx_webhooks_tenant_id;
DROP INDEX IF EXISTS idx_webhooks_tenant_active;

DROP INDEX IF EXISTS idx_webhook_deliveries_tenant_id;

DROP INDEX IF EXISTS idx_audit_logs_tenant_id;
DROP INDEX IF EXISTS idx_audit_logs_tenant_actor;
DROP INDEX IF EXISTS idx_audit_logs_tenant_target;
DROP INDEX IF EXISTS idx_audit_logs_tenant_event;

DROP INDEX IF EXISTS idx_mfa_secrets_tenant_id;
DROP INDEX IF EXISTS idx_mfa_secrets_tenant_user;

DROP INDEX IF EXISTS idx_mfa_backup_codes_tenant_id;
DROP INDEX IF EXISTS idx_mfa_backup_codes_tenant_user;

DROP INDEX IF EXISTS idx_oauth_accounts_tenant_id;
DROP INDEX IF EXISTS idx_oauth_accounts_tenant_user;

DROP INDEX IF EXISTS idx_password_history_tenant_id;
DROP INDEX IF EXISTS idx_password_history_tenant_user;

DROP INDEX IF EXISTS idx_casbin_policies_tenant_id;
DROP INDEX IF EXISTS idx_casbin_policies_tenant_lookup;

DROP INDEX IF EXISTS idx_rar_resource_types_tenant_id;

DROP INDEX IF EXISTS idx_client_rar_allowed_types_tenant_id;
DROP INDEX IF EXISTS idx_client_rar_allowed_types_tenant_client;

DROP INDEX IF EXISTS idx_agent_credentials_tenant_id;
DROP INDEX IF EXISTS idx_agent_credentials_tenant_owner;
DROP INDEX IF EXISTS idx_agent_credentials_tenant_status;

-- --------------------------------------------------------------------------
-- 3. Restore original unique constraints
-- --------------------------------------------------------------------------

-- users: restore global email uniqueness
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_tenant_email_unique;
ALTER TABLE users ADD CONSTRAINT users_email_unique UNIQUE (email);

-- clients: restore global name uniqueness
ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_tenant_name_unique;
ALTER TABLE clients ADD CONSTRAINT clients_name_unique UNIQUE (name);

-- rar_resource_types: restore global type uniqueness
ALTER TABLE rar_resource_types DROP CONSTRAINT IF EXISTS rar_resource_types_tenant_type_unique;
ALTER TABLE rar_resource_types ADD CONSTRAINT rar_resource_types_type_key UNIQUE (type);

-- oauth_accounts: restore original uniqueness
ALTER TABLE oauth_accounts DROP CONSTRAINT IF EXISTS oauth_accounts_tenant_provider_user_unique;
ALTER TABLE oauth_accounts ADD CONSTRAINT oauth_accounts_provider_provider_user_id_unique
    UNIQUE (provider, provider_user_id);

-- mfa_secrets: restore original unique index
DROP INDEX IF EXISTS idx_mfa_secrets_tenant_user_type_active;
CREATE UNIQUE INDEX idx_mfa_secrets_user_type_active
    ON mfa_secrets (user_id, type) WHERE deleted_at IS NULL;

-- agent_credentials: restore original unique index
DROP INDEX IF EXISTS idx_agent_credentials_tenant_owner_target_type;
CREATE UNIQUE INDEX idx_agent_credentials_owner_target_type
    ON agent_credentials (owner_client_id, target_name, credential_type)
    WHERE status = 'active';

-- --------------------------------------------------------------------------
-- 4. Drop tenant_id columns (cascades FK constraints)
-- --------------------------------------------------------------------------

ALTER TABLE users DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE clients DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE webhooks DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE mfa_secrets DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE mfa_backup_codes DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE oauth_accounts DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE password_history DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE casbin_policies DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE rar_resource_types DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE client_rar_allowed_types DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE agent_credentials DROP COLUMN IF EXISTS tenant_id;

-- --------------------------------------------------------------------------
-- 5. Drop tenants table and enum
-- --------------------------------------------------------------------------

DROP TABLE IF EXISTS tenants;
DROP TYPE IF EXISTS tenant_status;

COMMIT;
