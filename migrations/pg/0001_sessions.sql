-- Postgres version of migrations/0001_sessions.sql. Same tables, columns and indexes;
-- times are BIGINT epoch milliseconds (D1 INTEGER is 64-bit, Postgres
-- INTEGER is not), counters stay INTEGER, JSON stays TEXT.
-- Table names are unqualified: set search_path to apply them to another
-- schema (see README).
--
-- @tomu-ai/workers-auth : session store (pgSessionStore)
-- sid_hash is sha256(sid) hex. The raw session id is never stored.

CREATE TABLE IF NOT EXISTS auth_sessions (
  sid_hash            TEXT    PRIMARY KEY,
  user_id             TEXT    NOT NULL,
  subject_type        TEXT    NOT NULL CHECK (subject_type IN ('user', 'service')),
  created_at          BIGINT  NOT NULL,
  last_seen_at        BIGINT  NOT NULL,
  idle_expires_at     BIGINT  NOT NULL,
  absolute_expires_at BIGINT  NOT NULL,
  scope               TEXT,
  meta                TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id
  ON auth_sessions (user_id);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_absolute_expires_at
  ON auth_sessions (absolute_expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_sessions_idle_expires_at
  ON auth_sessions (idle_expires_at);
