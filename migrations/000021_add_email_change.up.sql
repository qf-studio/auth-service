-- 000021_add_email_change.up.sql
-- Adds account email-change support (GH-518): a pending change must be
-- confirmed from the new address before it takes effect, and can be
-- reverted from the old address for a window afterward (email change is an
-- account-takeover lever).

ALTER TABLE users
    ADD COLUMN pending_email                  TEXT,
    ADD COLUMN email_change_token             TEXT,
    ADD COLUMN email_change_token_expires_at  TIMESTAMPTZ,
    ADD COLUMN email_revert_token             TEXT,
    ADD COLUMN email_revert_token_expires_at  TIMESTAMPTZ,
    ADD COLUMN previous_email                 TEXT;

CREATE UNIQUE INDEX idx_users_email_change_token ON users (email_change_token) WHERE email_change_token IS NOT NULL;
CREATE UNIQUE INDEX idx_users_email_revert_token ON users (email_revert_token) WHERE email_revert_token IS NOT NULL;
