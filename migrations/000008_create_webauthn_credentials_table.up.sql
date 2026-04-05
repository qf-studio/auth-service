-- WebAuthn credentials: stores FIDO2/WebAuthn public-key credentials per user.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id               TEXT        PRIMARY KEY,
    user_id          TEXT        NOT NULL REFERENCES users (id),
    credential_id    BYTEA       NOT NULL,
    public_key       BYTEA       NOT NULL,
    aaguid           TEXT        NOT NULL DEFAULT '',
    sign_count       INTEGER     NOT NULL DEFAULT 0,
    transports       TEXT[]      NOT NULL DEFAULT '{}',
    attestation_type TEXT        NOT NULL DEFAULT 'none',
    friendly_name    TEXT        NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ
);

-- Fast lookup by credential ID for authentication (unique among active credentials).
CREATE UNIQUE INDEX idx_webauthn_credentials_credential_id_active
    ON webauthn_credentials (credential_id) WHERE deleted_at IS NULL;

-- List all credentials for a user.
CREATE INDEX idx_webauthn_credentials_user_id
    ON webauthn_credentials (user_id);
