-- 000015_multi_tenancy.down.sql
-- Reverts multi-tenancy: drops RLS policies, tenant_id columns, and tenants table.

BEGIN;

-- ============================================================================
-- 1. Drop RLS policies and disable RLS
-- ============================================================================
DROP POLICY IF EXISTS tenant_isolation_password_history ON password_history;
ALTER TABLE password_history DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_agent_credentials ON agent_credentials;
ALTER TABLE agent_credentials DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_client_rar_allowed_types ON client_rar_allowed_types;
ALTER TABLE client_rar_allowed_types DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_rar_resource_types ON rar_resource_types;
ALTER TABLE rar_resource_types DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_saml_accounts ON saml_accounts;
ALTER TABLE saml_accounts DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_saml_idp_configs ON saml_idp_configs;
ALTER TABLE saml_idp_configs DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_audit_logs ON audit_logs;
ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_casbin_policies ON casbin_policies;
ALTER TABLE casbin_policies DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_webhook_deliveries ON webhook_deliveries;
ALTER TABLE webhook_deliveries DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_webhooks ON webhooks;
ALTER TABLE webhooks DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mfa_backup_codes ON mfa_backup_codes;
ALTER TABLE mfa_backup_codes DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_mfa_secrets ON mfa_secrets;
ALTER TABLE mfa_secrets DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_oauth_accounts ON oauth_accounts;
ALTER TABLE oauth_accounts DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_refresh_tokens ON refresh_tokens;
ALTER TABLE refresh_tokens DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_clients ON clients;
ALTER TABLE clients DISABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation_users ON users;
ALTER TABLE users DISABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 2. Drop tenant_id columns (cascades indexes and FK constraints)
-- ============================================================================

-- password_history
ALTER TABLE password_history DROP CONSTRAINT IF EXISTS fk_password_history_tenant;
DROP INDEX IF EXISTS idx_password_history_tenant_id;
ALTER TABLE password_history DROP COLUMN IF EXISTS tenant_id;

-- agent_credentials
ALTER TABLE agent_credentials DROP CONSTRAINT IF EXISTS fk_agent_credentials_tenant;
DROP INDEX IF EXISTS idx_agent_credentials_tenant_id;
ALTER TABLE agent_credentials DROP COLUMN IF EXISTS tenant_id;

-- client_rar_allowed_types
ALTER TABLE client_rar_allowed_types DROP CONSTRAINT IF EXISTS fk_client_rar_allowed_types_tenant;
DROP INDEX IF EXISTS idx_client_rar_allowed_types_tenant_id;
ALTER TABLE client_rar_allowed_types DROP COLUMN IF EXISTS tenant_id;

-- rar_resource_types
ALTER TABLE rar_resource_types DROP CONSTRAINT IF EXISTS fk_rar_resource_types_tenant;
DROP INDEX IF EXISTS idx_rar_resource_types_tenant_id;
ALTER TABLE rar_resource_types DROP CONSTRAINT IF EXISTS rar_resource_types_type_tenant_unique;
ALTER TABLE rar_resource_types DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE rar_resource_types ADD CONSTRAINT rar_resource_types_type_key UNIQUE (type);

-- saml_accounts
ALTER TABLE saml_accounts DROP CONSTRAINT IF EXISTS fk_saml_accounts_tenant;
DROP INDEX IF EXISTS idx_saml_accounts_tenant_id;
ALTER TABLE saml_accounts DROP CONSTRAINT IF EXISTS saml_accounts_idp_name_tenant_unique;
ALTER TABLE saml_accounts DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE saml_accounts ADD CONSTRAINT saml_accounts_idp_id_name_id_key UNIQUE (idp_id, name_id);

-- saml_idp_configs
ALTER TABLE saml_idp_configs DROP CONSTRAINT IF EXISTS fk_saml_idp_configs_tenant;
DROP INDEX IF EXISTS idx_saml_idp_configs_tenant_id;
ALTER TABLE saml_idp_configs DROP CONSTRAINT IF EXISTS saml_idp_configs_entity_tenant_unique;
ALTER TABLE saml_idp_configs DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE saml_idp_configs ADD CONSTRAINT saml_idp_configs_entity_id_key UNIQUE (entity_id);

-- audit_logs
ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS fk_audit_logs_tenant;
DROP INDEX IF EXISTS idx_audit_logs_tenant_id;
DROP INDEX IF EXISTS idx_audit_logs_tenant_event;
ALTER TABLE audit_logs DROP COLUMN IF EXISTS tenant_id;

-- casbin_policies
ALTER TABLE casbin_policies DROP CONSTRAINT IF EXISTS fk_casbin_policies_tenant;
DROP INDEX IF EXISTS idx_casbin_policies_tenant_id;
ALTER TABLE casbin_policies DROP COLUMN IF EXISTS tenant_id;

-- webhook_deliveries
ALTER TABLE webhook_deliveries DROP CONSTRAINT IF EXISTS fk_webhook_deliveries_tenant;
DROP INDEX IF EXISTS idx_webhook_deliveries_tenant_id;
ALTER TABLE webhook_deliveries DROP COLUMN IF EXISTS tenant_id;

-- webhooks
ALTER TABLE webhooks DROP CONSTRAINT IF EXISTS fk_webhooks_tenant;
DROP INDEX IF EXISTS idx_webhooks_tenant_id;
ALTER TABLE webhooks DROP COLUMN IF EXISTS tenant_id;

-- mfa_backup_codes
ALTER TABLE mfa_backup_codes DROP CONSTRAINT IF EXISTS fk_mfa_backup_codes_tenant;
DROP INDEX IF EXISTS idx_mfa_backup_codes_tenant_id;
ALTER TABLE mfa_backup_codes DROP COLUMN IF EXISTS tenant_id;

-- mfa_secrets
ALTER TABLE mfa_secrets DROP CONSTRAINT IF EXISTS fk_mfa_secrets_tenant;
DROP INDEX IF EXISTS idx_mfa_secrets_tenant_id;
ALTER TABLE mfa_secrets DROP COLUMN IF EXISTS tenant_id;

-- oauth_accounts
ALTER TABLE oauth_accounts DROP CONSTRAINT IF EXISTS fk_oauth_accounts_tenant;
DROP INDEX IF EXISTS idx_oauth_accounts_tenant_id;
ALTER TABLE oauth_accounts DROP CONSTRAINT IF EXISTS oauth_accounts_provider_tenant_unique;
ALTER TABLE oauth_accounts DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE oauth_accounts ADD CONSTRAINT oauth_accounts_provider_provider_user_id_key UNIQUE (provider, provider_user_id);

-- refresh_tokens
ALTER TABLE refresh_tokens DROP CONSTRAINT IF EXISTS fk_refresh_tokens_tenant;
DROP INDEX IF EXISTS idx_refresh_tokens_tenant_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS tenant_id;

-- clients
ALTER TABLE clients DROP CONSTRAINT IF EXISTS fk_clients_tenant;
DROP INDEX IF EXISTS idx_clients_tenant_id;
ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_name_tenant_unique;
ALTER TABLE clients DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE clients ADD CONSTRAINT clients_name_key UNIQUE (name);

-- users
ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_users_tenant;
DROP INDEX IF EXISTS idx_users_tenant_id;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_tenant_unique;
ALTER TABLE users DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email);

-- ============================================================================
-- 3. Drop the tenants table
-- ============================================================================
DROP INDEX IF EXISTS idx_tenants_active;
DROP TABLE IF EXISTS tenants;

COMMIT;
