-- OIDC provider foundation: authorization_codes and consent_sessions tables.

CREATE TYPE consent_state AS ENUM ('pending', 'accepted', 'rejected', 'revoked');

CREATE TABLE authorization_codes (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash             TEXT        NOT NULL,
    client_id             UUID        NOT NULL REFERENCES clients (id),
    user_id               TEXT        NOT NULL REFERENCES users (id),
    redirect_uri          TEXT        NOT NULL,
    scopes                TEXT[]      NOT NULL DEFAULT '{}',
    code_challenge        TEXT        NOT NULL DEFAULT '',
    code_challenge_method TEXT        NOT NULL DEFAULT '',
    nonce                 TEXT        NOT NULL DEFAULT '',
    expires_at            TIMESTAMPTZ NOT NULL,
    used_at               TIMESTAMPTZ,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT authorization_codes_code_hash_unique UNIQUE (code_hash),
    CONSTRAINT authorization_codes_challenge_method_check CHECK (
        code_challenge_method IN ('', 'plain', 'S256')
    )
);

CREATE INDEX idx_authorization_codes_client_id ON authorization_codes (client_id);
CREATE INDEX idx_authorization_codes_user_id ON authorization_codes (user_id);
CREATE INDEX idx_authorization_codes_expires_at ON authorization_codes (expires_at);

CREATE TABLE consent_sessions (
    id               UUID          PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge        TEXT          NOT NULL,
    verifier         TEXT          NOT NULL,
    client_id        UUID          NOT NULL REFERENCES clients (id),
    user_id          TEXT          NOT NULL REFERENCES users (id),
    requested_scopes TEXT[]        NOT NULL DEFAULT '{}',
    granted_scopes   TEXT[]        NOT NULL DEFAULT '{}',
    state            consent_state NOT NULL DEFAULT 'pending',
    login_session_id TEXT          NOT NULL DEFAULT '',
    encrypted_payload BYTEA,
    created_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    expires_at       TIMESTAMPTZ,

    CONSTRAINT consent_sessions_challenge_unique UNIQUE (challenge),
    CONSTRAINT consent_sessions_verifier_unique UNIQUE (verifier)
);

CREATE INDEX idx_consent_sessions_client_id ON consent_sessions (client_id);
CREATE INDEX idx_consent_sessions_user_id ON consent_sessions (user_id);
CREATE INDEX idx_consent_sessions_state ON consent_sessions (state);
CREATE INDEX idx_consent_sessions_login_session_id ON consent_sessions (login_session_id)
    WHERE login_session_id != '';
