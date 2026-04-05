DROP INDEX IF EXISTS idx_clients_is_third_party;

ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_approval_status_check;

ALTER TABLE clients
    DROP COLUMN IF EXISTS redirect_uris,
    DROP COLUMN IF EXISTS is_third_party,
    DROP COLUMN IF EXISTS approval_status;
