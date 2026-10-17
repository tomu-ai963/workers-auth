/**
 * Storage for PIN / trusted-device / email-code auth. D1 only.
 *
 * Every limit in this feature — 5 tries per email code, 3 PIN failures per
 * account, resend cooldowns — is enforced by a single conditional statement
 * that both checks and moves the counter. A read-then-write would let N
 * concurrent requests all observe "under the limit"; KV has no other mode, so
 * there is no KV store and `deviceAuth()` refuses any store that does not
 * declare `atomic: true`.
 *
 * Apply `migrations/0006_device_auth.sql` before use.
 */

import { assertIdentifier } from '../store/revocation.js';
import type { Clock } from '../types.js';
import type { CredentialMaterial, CredentialType } from './credentials.js';

export type EmailCodeRecord = {
  email: string;
  codeHash: string;
  keyId: string;
  expiresAt: number;
  createdAt: number;
  /**
   * Until when a resend keeps the attempts already used. Set to
   * `createdAt + ttl` for the first code of a window; a resend before this
   * time inherits both the count and this deadline, so resending can neither
   * refill the budget nor stretch the window.
   */
  attemptsResetAt: number;
};

export type ReservedEmailCode = {
  codeHash: string;
  keyId: string;
  /** Attempts used, including the one just reserved. */
  attempts: number;
};

export type DeviceRecord = {
  deviceId: string;
  accountId: string;
  email: string;
  secretHash: string;
  label: string | null;
  createdAt: number;
  lastUsedAt: number;
  idleExpiresAt: number;
  absoluteExpiresAt: number;
  revokedAt: number | null;
};

/** What listing exposes. The secret hash never leaves the store this way. */
export type DeviceInfo = Omit<DeviceRecord, 'secretHash' | 'email' | 'revokedAt'>;

export type CredentialRecord = {
  credentialId: string;
  accountId: string;
  type: CredentialType;
  deviceId: string | null;
  material: CredentialMaterial;
  createdAt: number;
  updatedAt: number;
  lastUsedAt: number | null;
};

export type ReplaceCredentialOptions = {
  /**
   * Also clear the account's failure count and lock (`resetLoginGuard`), in
   * the same transaction: the counter belonged to the credential being
   * replaced, so it is cleared exactly when — and only if — the new one
   * exists.
   */
  resetLoginGuard?: boolean;
  /**
   * If a live credential of the type is being replaced, also revoke every
   * other device of the account (all but `exceptDeviceId`), in the same
   * transaction: the new credential and the revocation take effect together
   * or not at all. Nothing is revoked when there was no credential to replace.
   */
  revokeOtherDevices?: { exceptDeviceId: string | null };
};

export type ReplaceCredentialResult = {
  /** Whether a live credential of the type existed and was revoked. */
  replaced: boolean;
  /** Devices revoked by `revokeOtherDevices` (0 when not asked, or nothing was replaced). */
  devicesRevoked: number;
};

export type CircuitBreakerState = { attempts: number; failures: number; windowStart: number };

export type GuardState = {
  failedCount: number;
  lockedAt: number | null;
};

export interface DeviceAuthStore {
  /** Must be `true`. See the module comment. */
  readonly atomic: boolean;

  /**
   * Counts one hit in a fixed window and returns the count including it. The
   * window restarts once `windowMs` has passed since it opened.
   */
  hitRateLimit(bucket: string, windowMs: number, now: number): Promise<{ count: number; windowStart: number }>;
  /** The current window's count without adding to it (0 when the window has lapsed). */
  readRateLimit(bucket: string, windowMs: number, now: number): Promise<{ count: number; windowStart: number }>;
  /**
   * Takes one slot of a budget of `max` per fixed window, in one statement
   * that both checks and moves the counter: at the cap it changes nothing and
   * returns null. Unlike `hitRateLimit`, a refused request leaves no count
   * behind, so a slot that is later given back with `refundRateLimit` is the
   * only thing ever added — concurrent refused requests cannot pile up.
   */
  reserveRateLimit(
    bucket: string,
    windowMs: number,
    now: number,
    max: number,
  ): Promise<{ count: number; windowStart: number } | null>;
  /** Gives back one slot taken by `reserveRateLimit`, if that window is still the current one. */
  refundRateLimit(bucket: string, windowStart: number): Promise<void>;

  /**
   * Circuit breaker: counts one checked verification — and, if `failed`, one
   * failure — in a single row and a single fixed window, so the two counts
   * can never drift into different windows. Returns the counts including it.
   */
  hitCircuitBreaker(bucket: string, windowMs: number, now: number, failed: boolean): Promise<CircuitBreakerState>;
  /** The current window's counts without adding to them (zeros when the window has lapsed). */
  readCircuitBreaker(bucket: string, windowMs: number, now: number): Promise<CircuitBreakerState>;

  /**
   * Replaces the address's code. Attempts already used carry over while the
   * stored `attemptsResetAt` is still in the future (see `EmailCodeRecord`).
   */
  putEmailCode(record: EmailCodeRecord): Promise<void>;
  /** Reserves one attempt on a live, unexhausted code. null = nothing to try. */
  reserveEmailCodeAttempt(email: string, now: number, maxAttempts: number): Promise<ReservedEmailCode | null>;
  /** Deletes the code iff it is still the one that was matched. Exactly one caller wins. */
  consumeEmailCode(email: string, codeHash: string): Promise<boolean>;

  createDevice(record: DeviceRecord): Promise<void>;
  findDevice(deviceId: string): Promise<DeviceRecord | null>;
  /** Slides the idle window (never past the absolute one). Returns the new idle expiry, or null if no longer valid. */
  touchDevice(deviceId: string, now: number, idleExpiresAt: number): Promise<number | null>;
  listDevices(accountId: string, now: number): Promise<DeviceInfo[]>;
  revokeDevice(accountId: string, deviceId: string, now: number): Promise<boolean>;
  revokeAllDevices(accountId: string, now: number, exceptDeviceId?: string | null): Promise<number>;

  getActiveCredential(accountId: string, type: CredentialType): Promise<CredentialRecord | null>;
  /**
   * Revokes the live credential of `type` (if any) and inserts the new one —
   * with the options' extra steps — in one transaction: all of it or none.
   * The revocation time is `record.updatedAt`.
   */
  replaceCredential(record: CredentialRecord, options?: ReplaceCredentialOptions): Promise<ReplaceCredentialResult>;
  markCredentialUsed(credentialId: string, now: number, material?: CredentialMaterial): Promise<void>;

  /**
   * Reserves one failure before a credential is checked. Returns the failure
   * count including this one, or null when the account is locked / at its
   * limit — in which case nothing may be verified.
   */
  reserveLoginAttempt(accountId: string, maxAttempts: number, now: number): Promise<number | null>;
  /** Marks the account locked once its reserved failures reach `maxAttempts`. */
  lockAccount(accountId: string, maxAttempts: number, now: number): Promise<void>;
  /** Clears failures and any lock. Returns the state before clearing. */
  resetLoginGuard(accountId: string, now: number): Promise<GuardState | null>;
  readLoginGuard(accountId: string): Promise<GuardState | null>;
}

export interface DeviceAuthStoreCleanup {
  /**
   * Deletes expired codes and devices, revoked devices and credentials, and
   * rate-limit windows older than `rateLimitHorizonMs`. Safe from a cron trigger.
   */
  cleanup(now?: number, rateLimitHorizonMs?: number): Promise<number>;
}

export type D1DeviceAuthStoreOptions = {
  /** Override table names (bare SQL identifiers). */
  tables?: Partial<Record<'emailCodes' | 'devices' | 'credentials' | 'guards' | 'rateLimits', string>>;
  clock?: Clock;
};

type DeviceRow = {
  device_id: string;
  account_id: string;
  email: string;
  secret_hash: string;
  label: string | null;
  created_at: number;
  last_used_at: number;
  idle_expires_at: number;
  absolute_expires_at: number;
  revoked_at: number | null;
};

type CredentialRow = {
  credential_id: string;
  account_id: string;
  type: CredentialType;
  device_id: string | null;
  material: string;
  created_at: number;
  updated_at: number;
  last_used_at: number | null;
};

function rowToDevice(row: DeviceRow): DeviceRecord {
  return {
    deviceId: row.device_id,
    accountId: row.account_id,
    email: row.email,
    secretHash: row.secret_hash,
    label: row.label,
    createdAt: row.created_at,
    lastUsedAt: row.last_used_at,
    idleExpiresAt: row.idle_expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    revokedAt: row.revoked_at,
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

export function d1DeviceAuthStore(
  db: D1Database,
  options: D1DeviceAuthStoreOptions = {},
): DeviceAuthStore & DeviceAuthStoreCleanup {
  const t = options.tables ?? {};
  const codes = assertIdentifier(t.emailCodes ?? 'auth_email_codes', 'd1DeviceAuthStore.tables.emailCodes');
  const devices = assertIdentifier(t.devices ?? 'auth_trusted_devices', 'd1DeviceAuthStore.tables.devices');
  const creds = assertIdentifier(t.credentials ?? 'auth_credentials', 'd1DeviceAuthStore.tables.credentials');
  const guards = assertIdentifier(t.guards ?? 'auth_login_guards', 'd1DeviceAuthStore.tables.guards');
  const limits = assertIdentifier(t.rateLimits ?? 'auth_rate_limits', 'd1DeviceAuthStore.tables.rateLimits');
  const clock: Clock = options.clock ?? Date.now;

  return {
    atomic: true,

    async hitRateLimit(bucket, windowMs, now) {
      // SQLite evaluates every SET expression against the pre-update row, so
      // both CASEs see the same old window_start.
      const row = await db
        .prepare(
          `INSERT INTO ${limits} (bucket, window_start, count) VALUES (?1, ?2, 1)
           ON CONFLICT(bucket) DO UPDATE SET
             count        = CASE WHEN window_start <= ?3 THEN 1  ELSE count + 1   END,
             window_start = CASE WHEN window_start <= ?3 THEN ?2 ELSE window_start END
           RETURNING count, window_start`,
        )
        .bind(bucket, now, now - windowMs)
        .first<{ count: number; window_start: number }>();
      return { count: row?.count ?? 1, windowStart: row?.window_start ?? now };
    },

    async reserveRateLimit(bucket, windowMs, now, max) {
      // Same shape as reserveLoginAttempt: a DO UPDATE whose WHERE is false
      // changes nothing and RETURNs no row — that empty result is the refusal.
      // A lapsed window always restarts (at 1), whatever its old count.
      const row = await db
        .prepare(
          `INSERT INTO ${limits} (bucket, window_start, count) VALUES (?1, ?2, 1)
           ON CONFLICT(bucket) DO UPDATE SET
             count        = CASE WHEN window_start <= ?3 THEN 1  ELSE count + 1   END,
             window_start = CASE WHEN window_start <= ?3 THEN ?2 ELSE window_start END
             WHERE window_start <= ?3 OR count < ?4
           RETURNING count, window_start`,
        )
        .bind(bucket, now, now - windowMs, max)
        .first<{ count: number; window_start: number }>();
      return row ? { count: row.count, windowStart: row.window_start } : null;
    },

    async readRateLimit(bucket, windowMs, now) {
      const row = await db
        .prepare(`SELECT count, window_start FROM ${limits} WHERE bucket = ?1 AND window_start > ?2`)
        .bind(bucket, now - windowMs)
        .first<{ count: number; window_start: number }>();
      return { count: row?.count ?? 0, windowStart: row?.window_start ?? now };
    },

    async refundRateLimit(bucket, windowStart) {
      await db
        .prepare(`UPDATE ${limits} SET count = count - 1 WHERE bucket = ?1 AND window_start = ?2 AND count > 0`)
        .bind(bucket, windowStart)
        .run();
    },

    async hitCircuitBreaker(bucket, windowMs, now, failed) {
      const failure = failed ? 1 : 0;
      const row = await db
        .prepare(
          `INSERT INTO ${limits} (bucket, window_start, count, failures) VALUES (?1, ?2, 1, ?4)
           ON CONFLICT(bucket) DO UPDATE SET
             count        = CASE WHEN window_start <= ?3 THEN 1  ELSE count + 1        END,
             failures     = CASE WHEN window_start <= ?3 THEN ?4 ELSE failures + ?4    END,
             window_start = CASE WHEN window_start <= ?3 THEN ?2 ELSE window_start     END
           RETURNING count, failures, window_start`,
        )
        .bind(bucket, now, now - windowMs, failure)
        .first<{ count: number; failures: number; window_start: number }>();
      return {
        attempts: row?.count ?? 1,
        failures: row?.failures ?? failure,
        windowStart: row?.window_start ?? now,
      };
    },

    async readCircuitBreaker(bucket, windowMs, now) {
      const row = await db
        .prepare(`SELECT count, failures, window_start FROM ${limits} WHERE bucket = ?1 AND window_start > ?2`)
        .bind(bucket, now - windowMs)
        .first<{ count: number; failures: number; window_start: number }>();
      return { attempts: row?.count ?? 0, failures: row?.failures ?? 0, windowStart: row?.window_start ?? now };
    },

    async putEmailCode(record) {
      await db
        .prepare(
          `INSERT INTO ${codes} (email, code_hash, key_id, attempts, attempts_reset_at, expires_at, created_at)
           VALUES (?1, ?2, ?3, 0, ?4, ?5, ?6)
           ON CONFLICT(email) DO UPDATE SET
             code_hash = excluded.code_hash,
             key_id = excluded.key_id,
             attempts = CASE WHEN attempts_reset_at > excluded.created_at THEN attempts ELSE 0 END,
             attempts_reset_at = CASE WHEN attempts_reset_at > excluded.created_at
                                      THEN attempts_reset_at ELSE excluded.attempts_reset_at END,
             expires_at = excluded.expires_at,
             created_at = excluded.created_at`,
        )
        .bind(record.email, record.codeHash, record.keyId, record.attemptsResetAt, record.expiresAt, record.createdAt)
        .run();
    },

    async reserveEmailCodeAttempt(email, now, maxAttempts) {
      const row = await db
        .prepare(
          `UPDATE ${codes} SET attempts = attempts + 1
            WHERE email = ?1 AND attempts < ?3 AND expires_at > ?2
            RETURNING code_hash, key_id, attempts`,
        )
        .bind(email, now, maxAttempts)
        .first<{ code_hash: string; key_id: string; attempts: number }>();
      return row ? { codeHash: row.code_hash, keyId: row.key_id, attempts: row.attempts } : null;
    },

    async consumeEmailCode(email, codeHash) {
      const row = await db
        .prepare(`DELETE FROM ${codes} WHERE email = ?1 AND code_hash = ?2 RETURNING email`)
        .bind(email, codeHash)
        .first();
      return row !== null;
    },

    async createDevice(r) {
      await db
        .prepare(
          `INSERT INTO ${devices}
             (device_id, account_id, email, secret_hash, label, created_at, last_used_at,
              idle_expires_at, absolute_expires_at, revoked_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL)`,
        )
        .bind(
          r.deviceId,
          r.accountId,
          r.email,
          r.secretHash,
          r.label,
          r.createdAt,
          r.lastUsedAt,
          r.idleExpiresAt,
          r.absoluteExpiresAt,
        )
        .run();
    },

    async findDevice(deviceId) {
      const row = await db.prepare(`SELECT * FROM ${devices} WHERE device_id = ?1`).bind(deviceId).first<DeviceRow>();
      return row ? rowToDevice(row) : null;
    },

    async touchDevice(deviceId, now, idleExpiresAt) {
      const row = await db
        .prepare(
          `UPDATE ${devices}
              SET last_used_at = ?2, idle_expires_at = MIN(?3, absolute_expires_at)
            WHERE device_id = ?1 AND revoked_at IS NULL
              AND idle_expires_at > ?2 AND absolute_expires_at > ?2
            RETURNING idle_expires_at`,
        )
        .bind(deviceId, now, idleExpiresAt)
        .first<{ idle_expires_at: number }>();
      return row ? row.idle_expires_at : null;
    },

    async listDevices(accountId, now) {
      const { results } = await db
        .prepare(
          `SELECT * FROM ${devices}
            WHERE account_id = ?1 AND revoked_at IS NULL
              AND idle_expires_at > ?2 AND absolute_expires_at > ?2
            ORDER BY created_at`,
        )
        .bind(accountId, now)
        .all<DeviceRow>();
      return results.map((row) => {
        const { secretHash: _s, email: _e, revokedAt: _r, ...info } = rowToDevice(row);
        return info;
      });
    },

    async revokeDevice(accountId, deviceId, now) {
      const result = await db
        .prepare(
          `UPDATE ${devices} SET revoked_at = ?3
            WHERE device_id = ?1 AND account_id = ?2 AND revoked_at IS NULL`,
        )
        .bind(deviceId, accountId, now)
        .run();
      return (result.meta.changes ?? 0) > 0;
    },

    async revokeAllDevices(accountId, now, exceptDeviceId) {
      const result = await db
        .prepare(
          `UPDATE ${devices} SET revoked_at = ?2
            WHERE account_id = ?1 AND revoked_at IS NULL AND device_id IS NOT ?3`,
        )
        .bind(accountId, now, exceptDeviceId ?? null)
        .run();
      return result.meta.changes ?? 0;
    },

    async getActiveCredential(accountId, type) {
      const row = await db
        .prepare(
          `SELECT * FROM ${creds}
            WHERE account_id = ?1 AND type = ?2 AND revoked_at IS NULL
            ORDER BY created_at DESC LIMIT 1`,
        )
        .bind(accountId, type)
        .first<CredentialRow>();
      if (!row) return null;
      return {
        credentialId: row.credential_id,
        accountId: row.account_id,
        type: row.type,
        deviceId: row.device_id,
        material: parseMaterial(row.material),
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        lastUsedAt: row.last_used_at,
      };
    },

    async replaceCredential(r, options = {}) {
      // One batch = one transaction. Order matters: the devices are revoked
      // first, conditioned on a live credential still existing (the one about
      // to be replaced); then the old credential is revoked before the insert,
      // since the partial unique index allows only one live PIN.
      const statements: D1PreparedStatement[] = [];
      if (options.revokeOtherDevices) {
        statements.push(
          db
            .prepare(
              `UPDATE ${devices} SET revoked_at = ?2
                WHERE account_id = ?1 AND revoked_at IS NULL AND device_id IS NOT ?3
                  AND EXISTS (SELECT 1 FROM ${creds} WHERE account_id = ?1 AND type = ?4 AND revoked_at IS NULL)`,
            )
            .bind(r.accountId, r.updatedAt, options.revokeOtherDevices.exceptDeviceId, r.type),
        );
      }
      const revokeAt = statements.length;
      statements.push(
        db
          .prepare(
            `UPDATE ${creds} SET revoked_at = ?3, updated_at = ?3
              WHERE account_id = ?1 AND type = ?2 AND revoked_at IS NULL`,
          )
          .bind(r.accountId, r.type, r.updatedAt),
        db
          .prepare(
            `INSERT INTO ${creds}
               (credential_id, account_id, type, device_id, material, created_at, updated_at, last_used_at, revoked_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, NULL, NULL)`,
          )
          .bind(
            r.credentialId,
            r.accountId,
            r.type,
            r.deviceId,
            JSON.stringify(r.material),
            r.createdAt,
            r.updatedAt,
          ),
      );
      if (options.resetLoginGuard) {
        statements.push(
          db
            .prepare(`UPDATE ${guards} SET failed_count = 0, locked_at = NULL, updated_at = ?2 WHERE account_id = ?1`)
            .bind(r.accountId, r.updatedAt),
        );
      }
      const results = await db.batch(statements);
      return {
        replaced: (results[revokeAt]?.meta.changes ?? 0) > 0,
        devicesRevoked: options.revokeOtherDevices ? (results[0]?.meta.changes ?? 0) : 0,
      };
    },

    async markCredentialUsed(credentialId, now, material) {
      if (material) {
        await db
          .prepare(
            `UPDATE ${creds} SET last_used_at = ?2, updated_at = ?2, material = ?3
              WHERE credential_id = ?1 AND revoked_at IS NULL`,
          )
          .bind(credentialId, now, JSON.stringify(material))
          .run();
        return;
      }
      await db
        .prepare(`UPDATE ${creds} SET last_used_at = ?2 WHERE credential_id = ?1 AND revoked_at IS NULL`)
        .bind(credentialId, now)
        .run();
    },

    async reserveLoginAttempt(accountId, maxAttempts, now) {
      // A DO UPDATE whose WHERE is false changes nothing and RETURNs no row —
      // that empty result *is* the "locked" answer, decided inside one statement.
      const row = await db
        .prepare(
          `INSERT INTO ${guards} (account_id, failed_count, locked_at, updated_at) VALUES (?1, 1, NULL, ?2)
           ON CONFLICT(account_id) DO UPDATE SET failed_count = failed_count + 1, updated_at = ?2
             WHERE failed_count < ?3 AND locked_at IS NULL
           RETURNING failed_count`,
        )
        .bind(accountId, now, maxAttempts)
        .first<{ failed_count: number }>();
      return row ? row.failed_count : null;
    },

    async lockAccount(accountId, maxAttempts, now) {
      await db
        .prepare(
          `UPDATE ${guards} SET locked_at = COALESCE(locked_at, ?2), updated_at = ?2
            WHERE account_id = ?1 AND failed_count >= ?3`,
        )
        .bind(accountId, now, maxAttempts)
        .run();
    },

    async resetLoginGuard(accountId, now) {
      const [before] = await db.batch<{ failed_count: number; locked_at: number | null }>([
        db.prepare(`SELECT failed_count, locked_at FROM ${guards} WHERE account_id = ?1`).bind(accountId),
        db
          .prepare(`UPDATE ${guards} SET failed_count = 0, locked_at = NULL, updated_at = ?2 WHERE account_id = ?1`)
          .bind(accountId, now),
      ]);
      const row = before?.results[0];
      return row ? { failedCount: row.failed_count, lockedAt: row.locked_at } : null;
    },

    async readLoginGuard(accountId) {
      const row = await db
        .prepare(`SELECT failed_count, locked_at FROM ${guards} WHERE account_id = ?1`)
        .bind(accountId)
        .first<{ failed_count: number; locked_at: number | null }>();
      return row ? { failedCount: row.failed_count, lockedAt: row.locked_at } : null;
    },

    async cleanup(at, rateLimitHorizonMs = DAY_MS) {
      const now = at ?? clock();
      const results = await db.batch([
        db.prepare(`DELETE FROM ${codes} WHERE expires_at <= ?1`).bind(now),
        db.prepare(`DELETE FROM ${devices} WHERE absolute_expires_at <= ?1`).bind(now),
        db.prepare(`DELETE FROM ${devices} WHERE idle_expires_at <= ?1`).bind(now),
        db.prepare(`DELETE FROM ${devices} WHERE revoked_at IS NOT NULL`),
        db.prepare(`DELETE FROM ${creds} WHERE revoked_at IS NOT NULL`),
        db.prepare(`DELETE FROM ${limits} WHERE window_start <= ?1`).bind(now - rateLimitHorizonMs),
      ]);
      return results.reduce((sum, r) => sum + (r.meta.changes ?? 0), 0);
    },
  };
}
