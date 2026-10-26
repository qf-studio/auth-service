-- 000022_users_email_case_insensitive_unique.down.sql
DROP INDEX IF EXISTS idx_users_tenant_lower_email;
