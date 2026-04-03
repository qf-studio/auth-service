-- 000001_create_clients_table.up.sql
-- Creates the clients table for OAuth2 client (service / agent) identities.

CREATE TYPE client_type AS ENUM ('service', 'agent');

CREATE TABLE clients (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name             TEXT        NOT NULL,
    client_type      client_type NOT NULL,
    secret_hash      TEXT        NOT NULL,
    scopes           TEXT[]      NOT NULL DEFAULT '{}',
    owner            TEXT        NOT NULL,
    access_token_ttl INTEGER     NOT NULL DEFAULT 900, -- seconds (15 min default)
    status           TEXT        NOT NULL DEFAULT 'active',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at     TIMESTAMPTZ,

    CONSTRAINT clients_name_unique UNIQUE (name),
    CONSTRAINT clients_status_check CHECK (status IN ('active', 'suspended', 'revoked'))
);

CREATE INDEX idx_clients_owner ON clients (owner);
CREATE INDEX idx_clients_status ON clients (status);
