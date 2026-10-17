-- Postgres version of migrations/0004_api_keys.sql. Same tables, columns and indexes;
-- times are BIGINT epoch milliseconds (D1 INTEGER is 64-bit, Postgres
-- INTEGER is not), counters stay INTEGER, JSON stays TEXT.
-- Table names are unqualified: set search_path to apply them to another
-- schema (see README).
-- No Postgres store uses this table yet (D1/KV: d1ApiKeyStore / kvApiKeyStore); it is
-- created so both schemas stay numbered and shaped alike.
--
-- @tomu-ai/workers-auth : service API keys (d1ApiKeyStore)
-- The key is `tk_<env>_<key_id>.<secret>`; only sha256(secret) is stored.

CREATE TABLE IF NOT EXISTS auth_api_keys (
  key_id       TEXT    PRIMARY KEY,
  env          TEXT    NOT NULL,
  secret_hash  TEXT    NOT NULL,
  subject_id   TEXT    NOT NULL,
  label        TEXT,
  claims       TEXT,
  created_at   BIGINT  NOT NULL,
  expires_at   BIGINT,
  last_used_at BIGINT,
  revoked_at   BIGINT
);

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_subject_id
  ON auth_api_keys (subject_id);
