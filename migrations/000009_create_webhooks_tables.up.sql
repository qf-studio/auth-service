-- 000009_create_webhooks_tables.up.sql

CREATE TABLE IF NOT EXISTS webhooks (
    id            TEXT        PRIMARY KEY,
    url           TEXT        NOT NULL,
    secret        TEXT        NOT NULL,
    event_types   TEXT[]      NOT NULL DEFAULT '{}',
    active        BOOLEAN     NOT NULL DEFAULT true,
    failure_count INTEGER     NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhooks_active ON webhooks (active) WHERE active = true;
CREATE INDEX idx_webhooks_event_types ON webhooks USING GIN (event_types);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id             TEXT        PRIMARY KEY,
    webhook_id     TEXT        NOT NULL REFERENCES webhooks(id) ON DELETE CASCADE,
    event_type     TEXT        NOT NULL,
    payload        BYTEA       NOT NULL,
    status         TEXT        NOT NULL DEFAULT 'pending',
    response_code  INTEGER     NOT NULL DEFAULT 0,
    response_body  TEXT        NOT NULL DEFAULT '',
    attempt        INTEGER     NOT NULL DEFAULT 1,
    next_retry_at  TIMESTAMPTZ,
    delivered_at   TIMESTAMPTZ,
    duration_ms    INTEGER     NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhook_deliveries_webhook_id ON webhook_deliveries (webhook_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries (status) WHERE status IN ('pending', 'retrying');
