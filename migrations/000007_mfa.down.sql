-- 000007_mfa.down.sql
-- Removes MFA secrets and backup codes tables.

DROP INDEX IF EXISTS idx_backup_codes_unused;
DROP INDEX IF EXISTS idx_backup_codes_user_id;
DROP TABLE IF EXISTS backup_codes;

DROP INDEX IF EXISTS idx_mfa_secrets_user_id;
DROP TABLE IF EXISTS mfa_secrets;
