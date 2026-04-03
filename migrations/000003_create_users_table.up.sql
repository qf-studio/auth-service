-- 000003_create_users_table.up.sql
-- Creates the users table for human account identities.

CREATE TABLE users (
    id            TEXT        PRIMARY KEY,
    email         TEXT        NOT NULL,
    password_hash TEXT        NOT NULL,
    name          TEXT        NOT NULL,
    roles         TEXT[]      NOT NULL DEFAULT '{}',
    locked        BOOLEAN     NOT NULL DEFAULT FALSE,
    locked_at     TIMESTAMPTZ,
    locked_reason TEXT        NOT NULL DEFAULT '',
    last_login_at TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at    TIMESTAMPTZ,

    CONSTRAINT users_email_unique UNIQUE (email)
);

CREATE INDEX idx_users_email ON users (email);
CREATE INDEX idx_users_locked ON users (locked) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_deleted_at ON users (deleted_at) WHERE deleted_at IS NOT NULL;
