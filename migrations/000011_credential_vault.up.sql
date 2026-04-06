-- Encrypted credential vault for agent-managed third-party credentials.
-- Raw secrets are never stored; only AES-GCM encrypted blobs.
CREATE TABLE IF NOT EXISTS agent_credentials (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_client_id  UUID        NOT NULL REFERENCES clients (id) ON DELETE CASCADE,
    target_name      TEXT        NOT NULL,
    credential_type  TEXT        NOT NULL,
    encrypted_blob   BYTEA       NOT NULL,
    scopes           TEXT[]      NOT NULL DEFAULT '{}',
    status           TEXT        NOT NULL DEFAULT 'active',
    last_rotated_at  TIMESTAMPTZ,
    next_rotation_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT agent_credentials_type_check CHECK (
        credential_type IN ('api_key', 'oauth_token', 'certificate')
    ),
    CONSTRAINT agent_credentials_status_check CHECK (
        status IN ('active', 'rotated', 'revoked')
    )
);

-- Broker lookup: owner + target name for active credential retrieval.
CREATE UNIQUE INDEX idx_agent_credentials_owner_target
    ON agent_credentials (owner_client_id, target_name)
    WHERE status = 'active';

CREATE INDEX idx_agent_credentials_owner ON agent_credentials (owner_client_id);
CREATE INDEX idx_agent_credentials_status ON agent_credentials (status);
