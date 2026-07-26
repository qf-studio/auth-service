-- 000016_add_public_client_type.up.sql
-- Adds the "public" client type for OAuth2 public clients (e.g. SPAs, mobile
-- apps) that cannot securely hold a client secret and instead authenticate
-- via registered redirect URIs.

ALTER TYPE client_type ADD VALUE 'public';
