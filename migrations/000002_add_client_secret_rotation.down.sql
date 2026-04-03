-- 000002_add_client_secret_rotation.down.sql

ALTER TABLE clients
    DROP COLUMN IF EXISTS previous_secret_hash,
    DROP COLUMN IF EXISTS previous_secret_expires_at;
