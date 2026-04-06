-- Webhook registrations
CREATE TABLE webhooks (
    id             TEXT        PRIMARY KEY,
    url            TEXT        NOT NULL,
    secret         TEXT        NOT NULL,
    event_types    TEXT[]      NOT NULL DEFAULT '{}',
    active         BOOLEAN     NOT NULL DEFAULT true,
    failure_count  INTEGER     NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhooks_active ON webhooks (active) WHERE active = true;

-- Webhook delivery log
CREATE TABLE webhook_deliveries (
    id             TEXT        PRIMARY KEY,
    webhook_id     TEXT        NOT NULL REFERENCES webhooks (id) ON DELETE CASCADE,
    event_type     TEXT        NOT NULL,
    payload        JSONB       NOT NULL DEFAULT '{}',
    status         TEXT        NOT NULL DEFAULT 'pending',
    response_code  INTEGER,
    attempt        INTEGER     NOT NULL DEFAULT 1,
    next_retry_at  TIMESTAMPTZ,
    delivered_at   TIMESTAMPTZ,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_webhook_deliveries_webhook_id ON webhook_deliveries (webhook_id);
CREATE INDEX idx_webhook_deliveries_status ON webhook_deliveries (status);
CREATE INDEX idx_webhook_deliveries_next_retry ON webhook_deliveries (next_retry_at) WHERE status = 'pending';
