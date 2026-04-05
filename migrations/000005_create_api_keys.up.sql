-- 000005_create_api_keys.up.sql
-- Creates the api_keys table for machine-to-machine API key authentication.

CREATE TYPE api_key_status AS ENUM ('active', 'revoked');

CREATE TABLE api_keys (
    id                       UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id                UUID          NOT NULL REFERENCES clients (id),
    name                     TEXT          NOT NULL,
    key_hash                 TEXT          NOT NULL,
    previous_key_hash        TEXT          NOT NULL DEFAULT '',
    previous_key_expires_at  TIMESTAMPTZ,
    scopes                   TEXT[]        NOT NULL DEFAULT '{}',
    rate_limit               INTEGER       NOT NULL DEFAULT 0,
    status                   api_key_status NOT NULL DEFAULT 'active',
    expires_at               TIMESTAMPTZ,
    last_used_at             TIMESTAMPTZ,
    created_at               TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ   NOT NULL DEFAULT now(),

    CONSTRAINT api_keys_name_client_unique UNIQUE (client_id, name)
);

CREATE INDEX idx_api_keys_client_id ON api_keys (client_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys (key_hash) WHERE status = 'active';
CREATE INDEX idx_api_keys_status ON api_keys (status);
