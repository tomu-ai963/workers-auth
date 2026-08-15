/**
 * D1-backed SessionStore.
 *
 * Strongly consistent, so `revoke()` takes effect immediately without a
 * separate revocation list. Costs one D1 read per authenticated request.
 *
 * Apply `migrations/0001_sessions.sql` before use.
 */

import { randomToken, sha256Hex } from '../crypto.js';
import type { Clock, NewSession, RevocationList, Session, SessionStore, SubjectType } from '../types.js';
import { assertIdentifier } from './revocation.js';

export { revocationList, assertIdentifier } from './revocation.js';
export type { RevocationListOptions } from './revocation.js';

export type D1SessionStoreOptions = {
  /** Table name. Must be a bare SQL identifier. Default: `auth_sessions`. */
  table?: string;
  /** Optional extra revocation list. Redundant for D1; accepted for symmetry. */
  revocation?: RevocationList;
  clock?: Clock;
};

type Row = {
  sid_hash: string;
  user_id: string;
  subject_type: string;
  created_at: number;
  last_seen_at: number;
  idle_expires_at: number;
  absolute_expires_at: number;
  scope: string | null;
  meta: string | null;
};

function parseJson<T>(value: string | null): T | undefined {
  if (!value) return undefined;
  try {
    return JSON.parse(value) as T;
  } catch {
    return undefined;
  }
}

function rowToSession(row: Row, sid: string): Session {
  const scope = parseJson<Session['scope']>(row.scope);
  const meta = parseJson<Record<string, unknown>>(row.meta);
  return {
    sid,
    userId: row.user_id,
    subjectType: row.subject_type as SubjectType,
    createdAt: row.created_at,
    lastSeenAt: row.last_seen_at,
    idleExpiresAt: row.idle_expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    ...(scope ? { scope } : {}),
    ...(meta ? { meta } : {}),
  };
}

export interface D1SessionStore extends SessionStore {
  /** Deletes rows past either expiry. Returns the number of rows removed. */
  cleanup(now?: number): Promise<number>;
}

export function d1SessionStore(db: D1Database, options: D1SessionStoreOptions = {}): D1SessionStore {
  const table = assertIdentifier(options.table ?? 'auth_sessions', 'd1SessionStore.table');
  const revocation = options.revocation;
  const now: Clock = options.clock ?? Date.now;

  async function readRow(sidHash: string): Promise<Row | null> {
    return db.prepare(`SELECT * FROM ${table} WHERE sid_hash = ?1`).bind(sidHash).first<Row>();
  }

  return {
    // D1 is strongly consistent, so revokeAllForUser() is always a real
    // DELETE here — no attached RevocationList is needed to make it work.
    canRevokeAllForUser: true,

    async create(input: NewSession): Promise<Session> {
      if (!Number.isFinite(input.idleTtlSec) || input.idleTtlSec <= 0) {
        throw new TypeError('session: idleTtlSec must be a positive number of seconds');
      }
      if (!Number.isFinite(input.absoluteTtlSec) || input.absoluteTtlSec <= 0) {
        throw new TypeError('session: absoluteTtlSec must be a positive number of seconds');
      }

      const at = now();
      const sid = randomToken();
      const sidHash = await sha256Hex(sid);
      const absoluteExpiresAt = at + input.absoluteTtlSec * 1000;
      const idleExpiresAt = Math.min(at + input.idleTtlSec * 1000, absoluteExpiresAt);

      await db
        .prepare(
          `INSERT INTO ${table}
             (sid_hash, user_id, subject_type, created_at, last_seen_at, idle_expires_at, absolute_expires_at, scope, meta)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)`,
        )
        .bind(
          sidHash,
          input.userId,
          input.subjectType,
          at,
          at,
          idleExpiresAt,
          absoluteExpiresAt,
          input.scope ? JSON.stringify(input.scope) : null,
          input.meta ? JSON.stringify(input.meta) : null,
        )
        .run();

      return {
        sid,
        userId: input.userId,
        subjectType: input.subjectType,
        createdAt: at,
        lastSeenAt: at,
        idleExpiresAt,
        absoluteExpiresAt,
        ...(input.scope ? { scope: input.scope } : {}),
        ...(input.meta ? { meta: input.meta } : {}),
      };
    },

    async get(sid: string): Promise<Session | null> {
      const sidHash = await sha256Hex(sid);
      const row = await readRow(sidHash);
      if (!row) return null;
      if (
        revocation &&
        (await revocation.isRevoked({ sidHash, userId: row.user_id, createdAt: row.created_at }))
      ) {
        return null;
      }

      const at = now();
      if (at >= row.idle_expires_at || at >= row.absolute_expires_at) {
        await db.prepare(`DELETE FROM ${table} WHERE sid_hash = ?1`).bind(sidHash).run();
        return null;
      }
      return rowToSession(row, sid);
    },

    async touch(sid: string, idleExpiresAt: number): Promise<void> {
      const sidHash = await sha256Hex(sid);
      const at = now();
      await db
        .prepare(
          `UPDATE ${table}
              SET last_seen_at = ?2,
                  idle_expires_at = MIN(?3, absolute_expires_at)
            WHERE sid_hash = ?1
              AND idle_expires_at > ?2
              AND absolute_expires_at > ?2`,
        )
        .bind(sidHash, at, idleExpiresAt)
        .run();
    },

    async revoke(sid: string): Promise<void> {
      const sidHash = await sha256Hex(sid);
      if (revocation) {
        const row = await readRow(sidHash);
        if (row) await revocation.revoke(sidHash, row.absolute_expires_at);
      }
      await db.prepare(`DELETE FROM ${table} WHERE sid_hash = ?1`).bind(sidHash).run();
    },

    /**
     * D1 is strongly consistent, so a single DELETE is authoritative — no
     * enumeration hazard, and no revocation list required.
     */
    async revokeAllForUser(userId: string): Promise<void> {
      if (revocation) {
        // Only relevant when the list is shared with another store.
        await revocation.revokeUser(userId, now() + 1);
      }
      await db.prepare(`DELETE FROM ${table} WHERE user_id = ?1`).bind(userId).run();
    },

    /**
     * Two DELETEs instead of one `OR`-joined statement: an `OR` across two
     * columns can't use either index for a seek, so it degrades to a full
     * table scan as the table grows. Each half here is a plain indexed range
     * delete. A session already removed by the first statement is silently
     * skipped by the second.
     */
    async cleanup(at?: number): Promise<number> {
      const cutoff = at ?? now();
      const [byAbsolute, byIdle] = await db.batch<unknown>([
        db.prepare(`DELETE FROM ${table} WHERE absolute_expires_at <= ?1`).bind(cutoff),
        db.prepare(`DELETE FROM ${table} WHERE idle_expires_at <= ?1`).bind(cutoff),
      ]);
      return (byAbsolute?.meta.changes ?? 0) + (byIdle?.meta.changes ?? 0);
    },
  };
}
