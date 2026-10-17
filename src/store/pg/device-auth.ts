/**
 * Postgres-backed DeviceAuthStore — the counterpart of `d1DeviceAuthStore`.
 *
 * Every limit is still one conditional statement that both checks and moves
 * its counter. Under READ COMMITTED Postgres gives such a statement the same
 * guarantee D1's single writer does:
 *
 *   - `UPDATE … WHERE <limit> RETURNING`: a row locked by a concurrent
 *     transaction is waited for, then the WHERE is evaluated again against
 *     the row as that transaction left it, and the row is skipped if it no
 *     longer qualifies (PostgreSQL docs, 13.2.1 "Read Committed").
 *   - `INSERT … ON CONFLICT DO UPDATE … WHERE … RETURNING`: either inserts or
 *     locks the conflicting row and evaluates the DO UPDATE's WHERE against
 *     its latest version; a false WHERE updates nothing and returns no row.
 *     That empty result is the refusal, decided inside the statement.
 *
 * test/pg-node/locks.test.ts holds a row lock on one connection and runs each
 * of these statements on another to show the second waits and re-evaluates.
 *
 * Where D1's single writer made a two-statement batch safe and Postgres does
 * not, the statement changes shape:
 *   - replaceCredential serialises per account with a transaction-scoped
 *     advisory lock (see replaceCredentialStatements);
 *   - resetLoginGuard is one statement that locks the row before reading it.
 * Every call is retried once on 40001 / 40P01 only (see retryOnce).
 *
 * Apply `migrations/pg/0006_device_auth.sql` before use.
 */

import type {
  CircuitBreakerState,
  CredentialRecord,
  DeviceAuthStore,
  DeviceAuthStoreCleanup,
  DeviceRecord,
} from '../../device-auth/store.js';
import type { CredentialMaterial, CredentialType } from '../../device-auth/credentials.js';
import type { Clock } from '../../types.js';
import { affected, assertExecutor, num, numOrNull, retrying, type PgExecutor, type PgStatement } from './executor.js';

export type PgDeviceAuthStoreOptions = {
  clock?: Clock;
};

type DeviceRow = {
  device_id: string;
  account_id: string;
  email: string;
  secret_hash: string;
  label: string | null;
  created_at: unknown;
  last_used_at: unknown;
  idle_expires_at: unknown;
  absolute_expires_at: unknown;
  revoked_at: unknown;
};

type CredentialRow = {
  credential_id: string;
  account_id: string;
  type: CredentialType;
  device_id: string | null;
  material: string;
  created_at: unknown;
  updated_at: unknown;
  last_used_at: unknown;
};

function rowToDevice(row: DeviceRow): DeviceRecord {
  return {
    deviceId: row.device_id,
    accountId: row.account_id,
    email: row.email,
    secretHash: row.secret_hash,
    label: row.label,
    createdAt: num(row.created_at),
    lastUsedAt: num(row.last_used_at),
    idleExpiresAt: num(row.idle_expires_at),
    absoluteExpiresAt: num(row.absolute_expires_at),
    revokedAt: numOrNull(row.revoked_at),
  };
}

function parseMaterial(value: string): CredentialMaterial {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed && typeof parsed === 'object' ? (parsed as CredentialMaterial) : {};
  } catch {
    return {};
  }
}

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Revoke the live credential of the type and insert the new one, in one
 * transaction, after taking an advisory lock scoped to the account.
 *
 * Without the lock, two concurrent replacements race in a way D1 never sees:
 * the second transaction's UPDATE waits for the first, re-checks the row the
 * first revoked and skips it — but cannot see the row the first *inserted*
 * (that row was not in its snapshot), so its own INSERT then violates the
 * one-live-PIN index (23505) and the PIN change fails. With the lock the
 * second transaction starts its UPDATE only after the first committed, sees
 * the new row, revokes it and inserts: last writer wins, as on D1.
 *
 * The key is namespaced so it cannot collide with advisory locks the app
 * takes on the same database. Exported for the race tests only.
 */
export function replaceCredentialStatements(table: string, r: CredentialRecord): PgStatement[] {
  return [
    {
      text: `SELECT pg_advisory_xact_lock(hashtextextended('workers-auth:credential:' || $1::text, 0))`,
      params: [r.accountId],
    },
    {
      text: `UPDATE ${table} SET revoked_at = $3, updated_at = $3
              WHERE account_id = $1 AND type = $2 AND revoked_at IS NULL`,
      params: [r.accountId, r.type, r.updatedAt],
    },
    {
      text: `INSERT INTO ${table}
               (credential_id, account_id, type, device_id, material, created_at, updated_at, last_used_at, revoked_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, NULL)`,
      params: [r.credentialId, r.accountId, r.type, r.deviceId, JSON.stringify(r.material), r.createdAt, r.updatedAt],
    },
  ];
}

export function pgDeviceAuthStore(
  executor: PgExecutor,
  options: PgDeviceAuthStoreOptions = {},
): DeviceAuthStore & DeviceAuthStoreCleanup {
  assertExecutor(executor, 'pgDeviceAuthStore');
  const db = retrying(executor);
  const codes = 'public.auth_email_codes';
  const devices = 'public.auth_trusted_devices';
  const creds = 'public.auth_credentials';
  const guards = 'public.auth_login_guards';
  const limits = 'public.auth_rate_limits';
  const clock: Clock = options.clock ?? Date.now;
  const q = db.query.bind(db);

  return {
    atomic: true,

    async hitRateLimit(bucket, windowMs, now) {
      // Every SET expression sees the pre-update row, as in SQLite.
      const { rows } = await q<{ count: unknown; window_start: unknown }>(
        `INSERT INTO ${limits} AS r (bucket, window_start, count) VALUES ($1, $2, 1)
         ON CONFLICT (bucket) DO UPDATE SET
           count        = CASE WHEN r.window_start <= $3 THEN 1  ELSE r.count + 1   END,
           window_start = CASE WHEN r.window_start <= $3 THEN $2 ELSE r.window_start END
         RETURNING count, window_start`,
        [bucket, now, now - windowMs],
      );
      const row = rows[0];
      return { count: row ? num(row.count) : 1, windowStart: row ? num(row.window_start) : now };
    },

    async reserveRateLimit(bucket, windowMs, now, max) {
      const { rows } = await q<{ count: unknown; window_start: unknown }>(
        `INSERT INTO ${limits} AS r (bucket, window_start, count) VALUES ($1, $2, 1)
         ON CONFLICT (bucket) DO UPDATE SET
           count        = CASE WHEN r.window_start <= $3 THEN 1  ELSE r.count + 1   END,
           window_start = CASE WHEN r.window_start <= $3 THEN $2 ELSE r.window_start END
           WHERE r.window_start <= $3 OR r.count < $4
         RETURNING count, window_start`,
        [bucket, now, now - windowMs, max],
      );
      const row = rows[0];
      return row ? { count: num(row.count), windowStart: num(row.window_start) } : null;
    },

    async readRateLimit(bucket, windowMs, now) {
      const { rows } = await q<{ count: unknown; window_start: unknown }>(
        `SELECT count, window_start FROM ${limits} WHERE bucket = $1 AND window_start > $2`,
        [bucket, now - windowMs],
      );
      const row = rows[0];
      return { count: row ? num(row.count) : 0, windowStart: row ? num(row.window_start) : now };
    },

    async refundRateLimit(bucket, windowStart) {
      await q(`UPDATE ${limits} SET count = count - 1 WHERE bucket = $1 AND window_start = $2 AND count > 0`, [
        bucket,
        windowStart,
      ]);
    },

    async hitCircuitBreaker(bucket, windowMs, now, failed): Promise<CircuitBreakerState> {
      const failure = failed ? 1 : 0;
      const { rows } = await q<{ count: unknown; failures: unknown; window_start: unknown }>(
        `INSERT INTO ${limits} AS r (bucket, window_start, count, failures) VALUES ($1, $2, 1, $4)
         ON CONFLICT (bucket) DO UPDATE SET
           count        = CASE WHEN r.window_start <= $3 THEN 1  ELSE r.count + 1      END,
           failures     = CASE WHEN r.window_start <= $3 THEN $4 ELSE r.failures + $4  END,
           window_start = CASE WHEN r.window_start <= $3 THEN $2 ELSE r.window_start   END
         RETURNING count, failures, window_start`,
        [bucket, now, now - windowMs, failure],
      );
      const row = rows[0];
      return {
        attempts: row ? num(row.count) : 1,
        failures: row ? num(row.failures) : failure,
        windowStart: row ? num(row.window_start) : now,
      };
    },

    async readCircuitBreaker(bucket, windowMs, now) {
      const { rows } = await q<{ count: unknown; failures: unknown; window_start: unknown }>(
        `SELECT count, failures, window_start FROM ${limits} WHERE bucket = $1 AND window_start > $2`,
        [bucket, now - windowMs],
      );
      const row = rows[0];
      return row
        ? { attempts: num(row.count), failures: num(row.failures), windowStart: num(row.window_start) }
        : { attempts: 0, failures: 0, windowStart: now };
    },

    async putEmailCode(record) {
      await q(
        `INSERT INTO ${codes} AS c (email, code_hash, key_id, attempts, attempts_reset_at, expires_at, created_at)
         VALUES ($1, $2, $3, 0, $4, $5, $6)
         ON CONFLICT (email) DO UPDATE SET
           code_hash = excluded.code_hash,
           key_id = excluded.key_id,
           attempts = CASE WHEN c.attempts_reset_at > excluded.created_at THEN c.attempts ELSE 0 END,
           attempts_reset_at = CASE WHEN c.attempts_reset_at > excluded.created_at
                                    THEN c.attempts_reset_at ELSE excluded.attempts_reset_at END,
           expires_at = excluded.expires_at,
           created_at = excluded.created_at`,
        [record.email, record.codeHash, record.keyId, record.attemptsResetAt, record.expiresAt, record.createdAt],
      );
    },

    async reserveEmailCodeAttempt(email, now, maxAttempts) {
      const { rows } = await q<{ code_hash: string; key_id: string; attempts: unknown }>(
        `UPDATE ${codes} SET attempts = attempts + 1
          WHERE email = $1 AND attempts < $3 AND expires_at > $2
          RETURNING code_hash, key_id, attempts`,
        [email, now, maxAttempts],
      );
      const row = rows[0];
      return row ? { codeHash: row.code_hash, keyId: row.key_id, attempts: num(row.attempts) } : null;
    },

    async consumeEmailCode(email, codeHash) {
      const { rows } = await q(`DELETE FROM ${codes} WHERE email = $1 AND code_hash = $2 RETURNING email`, [
        email,
        codeHash,
      ]);
      return rows.length > 0;
    },

    async createDevice(r) {
      await q(
        `INSERT INTO ${devices}
           (device_id, account_id, email, secret_hash, label, created_at, last_used_at,
            idle_expires_at, absolute_expires_at, revoked_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULL)`,
        [
          r.deviceId,
          r.accountId,
          r.email,
          r.secretHash,
          r.label,
          r.createdAt,
          r.lastUsedAt,
          r.idleExpiresAt,
          r.absoluteExpiresAt,
        ],
      );
    },

    async findDevice(deviceId) {
      const { rows } = await q<DeviceRow>(`SELECT * FROM ${devices} WHERE device_id = $1`, [deviceId]);
      return rows[0] ? rowToDevice(rows[0]) : null;
    },

    async touchDevice(deviceId, now, idleExpiresAt) {
      const { rows } = await q<{ idle_expires_at: unknown }>(
        `UPDATE ${devices}
            SET last_used_at = $2, idle_expires_at = LEAST($3::bigint, absolute_expires_at)
          WHERE device_id = $1 AND revoked_at IS NULL
            AND idle_expires_at > $2 AND absolute_expires_at > $2
          RETURNING idle_expires_at`,
        [deviceId, now, idleExpiresAt],
      );
      return rows[0] ? num(rows[0].idle_expires_at) : null;
    },

    async listDevices(accountId, now) {
      const { rows } = await q<DeviceRow>(
        `SELECT * FROM ${devices}
          WHERE account_id = $1 AND revoked_at IS NULL
            AND idle_expires_at > $2 AND absolute_expires_at > $2
          ORDER BY created_at`,
        [accountId, now],
      );
      return rows.map((row) => {
        const { secretHash: _s, email: _e, revokedAt: _r, ...info } = rowToDevice(row);
        return info;
      });
    },

    async revokeDevice(accountId, deviceId, now) {
      const result = await q(
        `UPDATE ${devices} SET revoked_at = $3
          WHERE device_id = $1 AND account_id = $2 AND revoked_at IS NULL`,
        [deviceId, accountId, now],
      );
      return affected(result) > 0;
    },

    async revokeAllDevices(accountId, now, exceptDeviceId) {
      const result = await q(
        `UPDATE ${devices} SET revoked_at = $2
          WHERE account_id = $1 AND revoked_at IS NULL AND device_id IS DISTINCT FROM $3::text`,
        [accountId, now, exceptDeviceId ?? null],
      );
      return affected(result);
    },

    async getActiveCredential(accountId, type) {
      const { rows } = await q<CredentialRow>(
        `SELECT * FROM ${creds}
          WHERE account_id = $1 AND type = $2 AND revoked_at IS NULL
          ORDER BY created_at DESC LIMIT 1`,
        [accountId, type],
      );
      const row = rows[0];
      if (!row) return null;
      return {
        credentialId: row.credential_id,
        accountId: row.account_id,
        type: row.type,
        deviceId: row.device_id,
        material: parseMaterial(row.material),
        createdAt: num(row.created_at),
        updatedAt: num(row.updated_at),
        lastUsedAt: numOrNull(row.last_used_at),
      } satisfies CredentialRecord;
    },

    async replaceCredential(r) {
      // One transaction: the partial unique index allows only one live PIN,
      // so the old one has to be revoked before the insert, never after.
      const [, revoked] = await db.transaction(replaceCredentialStatements(creds, r));
      return (revoked ? affected(revoked) : 0) > 0;
    },

    async markCredentialUsed(credentialId, now, material) {
      if (material) {
        await q(
          `UPDATE ${creds} SET last_used_at = $2, updated_at = $2, material = $3
            WHERE credential_id = $1 AND revoked_at IS NULL`,
          [credentialId, now, JSON.stringify(material)],
        );
        return;
      }
      await q(`UPDATE ${creds} SET last_used_at = $2 WHERE credential_id = $1 AND revoked_at IS NULL`, [
        credentialId,
        now,
      ]);
    },

    async reserveLoginAttempt(accountId, maxAttempts, now) {
      // A DO UPDATE whose WHERE is false changes nothing and RETURNs no row —
      // that empty result *is* the "locked" answer, decided inside one statement.
      const { rows } = await q<{ failed_count: unknown }>(
        `INSERT INTO ${guards} AS g (account_id, failed_count, locked_at, updated_at) VALUES ($1, 1, NULL, $2)
         ON CONFLICT (account_id) DO UPDATE SET failed_count = g.failed_count + 1, updated_at = $2
           WHERE g.failed_count < $3 AND g.locked_at IS NULL
         RETURNING failed_count`,
        [accountId, now, maxAttempts],
      );
      return rows[0] ? num(rows[0].failed_count) : null;
    },

    async lockAccount(accountId, maxAttempts, now) {
      await q(
        `UPDATE ${guards} SET locked_at = COALESCE(locked_at, $2), updated_at = $2
          WHERE account_id = $1 AND failed_count >= $3`,
        [accountId, now, maxAttempts],
      );
    },

    async resetLoginGuard(accountId, now) {
      // One statement. The CTE locks the row (FOR UPDATE) before reading it,
      // so the state returned is the one the UPDATE actually clears — a
      // failure or lock committed by a concurrent request is waited for and
      // reported, not read from an older snapshot. (PostgreSQL 14+; no
      // RETURNING OLD, which needs 18.)
      const { rows } = await q<{ failed_count: unknown; locked_at: unknown }>(
        `WITH before AS (
           SELECT account_id, failed_count, locked_at FROM ${guards} WHERE account_id = $1 FOR UPDATE
         )
         UPDATE ${guards} AS g SET failed_count = 0, locked_at = NULL, updated_at = $2
           FROM before
          WHERE g.account_id = before.account_id
         RETURNING before.failed_count, before.locked_at`,
        [accountId, now],
      );
      const row = rows[0];
      return row ? { failedCount: num(row.failed_count), lockedAt: numOrNull(row.locked_at) } : null;
    },

    async readLoginGuard(accountId) {
      const { rows } = await q<{ failed_count: unknown; locked_at: unknown }>(
        `SELECT failed_count, locked_at FROM ${guards} WHERE account_id = $1`,
        [accountId],
      );
      const row = rows[0];
      return row ? { failedCount: num(row.failed_count), lockedAt: numOrNull(row.locked_at) } : null;
    },

    async cleanup(at, rateLimitHorizonMs = DAY_MS) {
      const now = at ?? clock();
      const statements: Array<[string, unknown[]]> = [
        [`DELETE FROM ${codes} WHERE expires_at <= $1`, [now]],
        [`DELETE FROM ${devices} WHERE absolute_expires_at <= $1`, [now]],
        [`DELETE FROM ${devices} WHERE idle_expires_at <= $1`, [now]],
        [`DELETE FROM ${devices} WHERE revoked_at IS NOT NULL`, []],
        [`DELETE FROM ${creds} WHERE revoked_at IS NOT NULL`, []],
        [`DELETE FROM ${limits} WHERE window_start <= $1`, [now - rateLimitHorizonMs]],
      ];
      let total = 0;
      for (const [text, params] of statements) total += affected(await q(text, params));
      return total;
    },
  };
}
