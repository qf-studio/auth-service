-- Credential vault for encrypted credential storage (agent/service credentials).
CREATE TABLE IF NOT EXISTS agent_credentials (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_client_id   UUID NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    target_name       TEXT NOT NULL,
    credential_type   TEXT NOT NULL,
    encrypted_blob    BYTEA NOT NULL,
    scopes            TEXT[] NOT NULL DEFAULT '{}',
    status            TEXT NOT NULL DEFAULT 'active',
    expires_at        TIMESTAMPTZ,
    last_rotated_at   TIMESTAMPTZ,
    rotation_policy   TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT chk_credential_type CHECK (credential_type IN ('api_key', 'oauth_token', 'certificate')),
    CONSTRAINT chk_credential_status CHECK (status IN ('active', 'expired', 'revoked', 'rotation_pending'))
);

CREATE INDEX idx_agent_credentials_owner ON agent_credentials (owner_client_id);
CREATE INDEX idx_agent_credentials_target ON agent_credentials (owner_client_id, target_name);
CREATE INDEX idx_agent_credentials_status ON agent_credentials (status) WHERE status = 'active';
CREATE UNIQUE INDEX idx_agent_credentials_owner_target_type ON agent_credentials (owner_client_id, target_name, credential_type)
    WHERE status = 'active';
