-- @tomu-ai/workers-auth : service API keys (d1ApiKeyStore)
-- The key is `tk_<env>_<key_id>.<secret>`; only sha256(secret) is stored.

CREATE TABLE IF NOT EXISTS auth_api_keys (
  key_id       TEXT    PRIMARY KEY,
  env          TEXT    NOT NULL,
  secret_hash  TEXT    NOT NULL,
  subject_id   TEXT    NOT NULL,
  label        TEXT,
  claims       TEXT,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER,
  last_used_at INTEGER,
  revoked_at   INTEGER
);

CREATE INDEX IF NOT EXISTS idx_auth_api_keys_subject_id
  ON auth_api_keys (subject_id);
