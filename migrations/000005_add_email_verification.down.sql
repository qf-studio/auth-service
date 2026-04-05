-- 000005_add_email_verification.down.sql
-- Removes email verification columns from the users table.

DROP INDEX IF EXISTS idx_users_email_verify_token;
DROP INDEX IF EXISTS idx_users_email_verified;

ALTER TABLE users
    DROP COLUMN IF EXISTS email_verify_token_expires_at,
    DROP COLUMN IF EXISTS email_verify_token,
    DROP COLUMN IF EXISTS email_verified;
