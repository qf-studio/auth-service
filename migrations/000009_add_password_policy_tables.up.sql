-- Add password lifecycle columns to users table.
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at    TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS force_password_change  BOOLEAN NOT NULL DEFAULT FALSE;

-- Password policies: one row per tenant (or "default" for global).
CREATE TABLE IF NOT EXISTS password_policies (
    id             TEXT        PRIMARY KEY,
    min_length     INTEGER     NOT NULL DEFAULT 15,
    max_length     INTEGER     NOT NULL DEFAULT 128,
    max_age_days   INTEGER     NOT NULL DEFAULT 0,
    history_count  INTEGER     NOT NULL DEFAULT 0,
    require_mfa    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Password history: append-only log of previous password hashes per user.
CREATE TABLE IF NOT EXISTS password_history (
    id            TEXT        PRIMARY KEY,
    user_id       TEXT        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_password_history_user_id ON password_history (user_id);
CREATE INDEX idx_password_history_user_created ON password_history (user_id, created_at DESC);
