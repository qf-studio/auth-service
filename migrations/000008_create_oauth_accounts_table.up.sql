-- OAuth accounts: links a local user to an external OAuth identity provider.
-- One user may have at most one linked account per provider.
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id               TEXT        PRIMARY KEY,
    user_id          TEXT        NOT NULL REFERENCES users (id),
    provider         TEXT        NOT NULL,
    provider_user_id TEXT        NOT NULL,
    email            TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_oauth_accounts_provider_user
    ON oauth_accounts (provider, provider_user_id);
CREATE INDEX idx_oauth_accounts_user_id ON oauth_accounts (user_id);
