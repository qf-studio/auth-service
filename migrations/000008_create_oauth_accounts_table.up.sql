-- 000008_create_oauth_accounts_table.up.sql
-- Stores linked social-login identities for users.

CREATE TABLE oauth_accounts (
    id               TEXT        PRIMARY KEY,
    user_id          TEXT        NOT NULL REFERENCES users(id),
    provider         TEXT        NOT NULL,
    provider_user_id TEXT        NOT NULL,
    email            TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT oauth_accounts_provider_user UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts (user_id);
