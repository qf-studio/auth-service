-- 000005_add_email_verification.up.sql
-- Adds email verification columns to the users table.

ALTER TABLE users
    ADD COLUMN email_verified                BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN email_verify_token            TEXT,
    ADD COLUMN email_verify_token_expires_at TIMESTAMPTZ;

CREATE INDEX idx_users_email_verified ON users (email_verified) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email_verify_token ON users (email_verify_token) WHERE email_verify_token IS NOT NULL;
