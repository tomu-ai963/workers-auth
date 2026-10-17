-- Postgres version of migrations/0006_device_auth.sql. Same tables, columns and indexes;
-- times are BIGINT epoch milliseconds (D1 INTEGER is 64-bit, Postgres
-- INTEGER is not), counters stay INTEGER, JSON stays TEXT.
-- Table names are unqualified: set search_path to apply them to another
-- schema (see README).
--
-- @tomu-ai/workers-auth : PIN + trusted device + email code (pgDeviceAuthStore)
--
-- Nothing secret is stored in the clear:
--   - email codes are HMAC-SHA256(derived key, email || '\n' || code)
--   - device secrets are sha256(secret)
--   - PINs are PBKDF2-SHA256(HMAC(pepper, pin), salt) inside `material`
-- `key_id` / `material.pepperVer` name which secret derived the key, so a
-- rotated-out secret listed in `previousSecrets` can still verify old rows.
--
-- Every counter here is updated by a single conditional statement
-- (UPDATE/UPSERT ... WHERE count < limit RETURNING), which is what keeps
-- concurrent requests from slipping past a limit. KV cannot do that, so there
-- is no KV variant of this store.

-- One live code per address; a resend overwrites the code. Attempts already
-- used carry over until attempts_reset_at (the first code's issue time + its
-- lifetime), so resending can neither refill the 5-try budget nor extend it.
CREATE TABLE IF NOT EXISTS auth_email_codes (
  email             TEXT    PRIMARY KEY,
  code_hash         TEXT    NOT NULL,
  key_id            TEXT    NOT NULL,
  attempts          INTEGER NOT NULL DEFAULT 0,
  attempts_reset_at BIGINT  NOT NULL,
  expires_at        BIGINT  NOT NULL,
  created_at        BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_email_codes_expires_at
  ON auth_email_codes (expires_at);

-- Proof of possession only. Which login methods an account has lives in
-- auth_credentials, not here.
CREATE TABLE IF NOT EXISTS auth_trusted_devices (
  device_id           TEXT    PRIMARY KEY,
  account_id          TEXT    NOT NULL,
  email               TEXT    NOT NULL,
  secret_hash         TEXT    NOT NULL,
  label               TEXT,
  created_at          BIGINT  NOT NULL,
  last_used_at        BIGINT  NOT NULL,
  idle_expires_at     BIGINT  NOT NULL,
  absolute_expires_at BIGINT  NOT NULL,
  revoked_at          BIGINT
);

CREATE INDEX IF NOT EXISTS idx_auth_trusted_devices_account_id
  ON auth_trusted_devices (account_id);

CREATE INDEX IF NOT EXISTS idx_auth_trusted_devices_idle_expires_at
  ON auth_trusted_devices (idle_expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_trusted_devices_absolute_expires_at
  ON auth_trusted_devices (absolute_expires_at);

-- Login methods, of any kind. 'passkey' is allowed by the CHECK from day one
-- because SQLite cannot alter a CHECK constraint without rebuilding the table.
-- device_id NULL = valid on every trusted device of the account (a PIN).
CREATE TABLE IF NOT EXISTS auth_credentials (
  credential_id TEXT    PRIMARY KEY,
  account_id    TEXT    NOT NULL,
  type          TEXT    NOT NULL CHECK (type IN ('pin', 'passkey')),
  device_id     TEXT,
  material      TEXT    NOT NULL,
  created_at    BIGINT  NOT NULL,
  updated_at    BIGINT  NOT NULL,
  last_used_at  BIGINT,
  revoked_at    BIGINT
);

CREATE INDEX IF NOT EXISTS idx_auth_credentials_account_id
  ON auth_credentials (account_id, type);

-- At most one live PIN per account.
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_credentials_one_pin
  ON auth_credentials (account_id)
  WHERE type = 'pin' AND revoked_at IS NULL;

-- Failure counting and lockout, per account, shared by every credential type.
-- An attempt is reserved (failed_count + 1) *before* verification and only
-- given back on success, so N parallel guesses cannot all see "not locked".
CREATE TABLE IF NOT EXISTS auth_login_guards (
  account_id   TEXT    PRIMARY KEY,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_at    BIGINT,
  updated_at   BIGINT  NOT NULL
);

-- Fixed-window counters for resend cooldowns and per-email / per-device /
-- per-IP limits. The /email/verify circuit breaker keeps its two counters in
-- one row — count = checked verifications, failures = the failed ones — so
-- both are always counted in the same window. Other buckets leave failures 0.
CREATE TABLE IF NOT EXISTS auth_rate_limits (
  bucket       TEXT    PRIMARY KEY,
  window_start BIGINT  NOT NULL,
  count        INTEGER NOT NULL,
  failures     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_window_start
  ON auth_rate_limits (window_start);
