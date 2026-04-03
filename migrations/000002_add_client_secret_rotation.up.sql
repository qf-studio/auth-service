-- 000002_add_client_secret_rotation.up.sql
-- Adds columns for secret rotation with a 24-hour grace period on the old secret.

ALTER TABLE clients
    ADD COLUMN previous_secret_hash       TEXT NOT NULL DEFAULT '',
    ADD COLUMN previous_secret_expires_at TIMESTAMPTZ;
