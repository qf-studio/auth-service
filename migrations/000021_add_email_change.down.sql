-- 000021_add_email_change.down.sql
DROP INDEX IF EXISTS idx_users_email_revert_token;
DROP INDEX IF EXISTS idx_users_email_change_token;

ALTER TABLE users
    DROP COLUMN previous_email,
    DROP COLUMN email_revert_token_expires_at,
    DROP COLUMN email_revert_token,
    DROP COLUMN email_change_token_expires_at,
    DROP COLUMN email_change_token,
    DROP COLUMN pending_email;
