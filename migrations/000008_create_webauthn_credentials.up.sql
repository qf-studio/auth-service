CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id   BYTEA       NOT NULL,
    public_key      BYTEA       NOT NULL,
    attestation_type TEXT       NOT NULL DEFAULT 'none',
    aaguid          BYTEA       NOT NULL DEFAULT '\x00000000000000000000000000000000',
    sign_count      BIGINT      NOT NULL DEFAULT 0,
    transports      TEXT[]      NOT NULL DEFAULT '{}',
    name            TEXT        NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMPTZ,
    deleted_at      TIMESTAMPTZ
);

-- Each credential ID must be globally unique (WebAuthn spec requirement).
CREATE UNIQUE INDEX idx_webauthn_credentials_credential_id
    ON webauthn_credentials (credential_id)
    WHERE deleted_at IS NULL;

-- Fast lookup of all credentials for a user.
CREATE INDEX idx_webauthn_credentials_user_id
    ON webauthn_credentials (user_id)
    WHERE deleted_at IS NULL;
