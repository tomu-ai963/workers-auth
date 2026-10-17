/**
 * Postgres-backed SessionStore — the counterpart of `d1SessionStore`.
 *
 * Strongly consistent (on the primary, with no query cache — see executor.ts),
 * so `revoke()` and `revokeAllForUser()` take effect immediately and
 * `canRevokeAllForUser` is true. Apply `migrations/pg/0001_sessions.sql`.
 *
 * There is no `revocation` option: a shared RevocationList only matters when
 * a KV store runs alongside, and that pairing is D1's.
 */

import { randomToken, sha256Hex } from '../../crypto.js';
import type { Clock, NewSession, Session, SessionStore, SubjectType } from '../../types.js';
import { affected, assertExecutor, num, retrying, type PgExecutor } from './executor.js';

export type PgSessionStoreOptions = {
  clock?: Clock;
};

export interface PgSessionStore extends SessionStore {
  /** Deletes rows past either expiry. Returns the number of rows removed. */
  cleanup(now?: number): Promise<number>;
}

type Row = {
  sid_hash: string;
  user_id: string;
  subject_type: string;
  created_at: unknown;
  last_seen_at: unknown;
  idle_expires_at: unknown;
  absolute_expires_at: unknown;
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
    createdAt: num(row.created_at),
    lastSeenAt: num(row.last_seen_at),
    idleExpiresAt: num(row.idle_expires_at),
    absoluteExpiresAt: num(row.absolute_expires_at),
    ...(scope ? { scope } : {}),
    ...(meta ? { meta } : {}),
  };
}

export function pgSessionStore(executor: PgExecutor, options: PgSessionStoreOptions = {}): PgSessionStore {
  assertExecutor(executor, 'pgSessionStore');
  const db = retrying(executor);
  const table = 'public.auth_sessions';
  const now: Clock = options.clock ?? Date.now;

  return {
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

      await db.query(
        `INSERT INTO ${table}
           (sid_hash, user_id, subject_type, created_at, last_seen_at, idle_expires_at, absolute_expires_at, scope, meta)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          sidHash,
          input.userId,
          input.subjectType,
          at,
          at,
          idleExpiresAt,
          absoluteExpiresAt,
          input.scope ? JSON.stringify(input.scope) : null,
          input.meta ? JSON.stringify(input.meta) : null,
        ],
      );

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
      const { rows } = await db.query<Row>(`SELECT * FROM ${table} WHERE sid_hash = $1`, [sidHash]);
      const row = rows[0];
      if (!row) return null;
      const at = now();
      if (at >= num(row.idle_expires_at) || at >= num(row.absolute_expires_at)) {
        await db.query(`DELETE FROM ${table} WHERE sid_hash = $1`, [sidHash]);
        return null;
      }
      return rowToSession(row, sid);
    },

    async touch(sid: string, idleExpiresAt: number): Promise<void> {
      const sidHash = await sha256Hex(sid);
      await db.query(
        `UPDATE ${table}
            SET last_seen_at = $2,
                idle_expires_at = LEAST($3::bigint, absolute_expires_at)
          WHERE sid_hash = $1
            AND idle_expires_at > $2
            AND absolute_expires_at > $2`,
        [sidHash, now(), idleExpiresAt],
      );
    },

    async revoke(sid: string): Promise<void> {
      await db.query(`DELETE FROM ${table} WHERE sid_hash = $1`, [await sha256Hex(sid)]);
    },

    async revokeAllForUser(userId: string): Promise<void> {
      await db.query(`DELETE FROM ${table} WHERE user_id = $1`, [userId]);
    },

    /** Two indexed range deletes rather than one OR (see d1SessionStore). */
    async cleanup(at?: number): Promise<number> {
      const cutoff = at ?? now();
      const byAbsolute = await db.query(`DELETE FROM ${table} WHERE absolute_expires_at <= $1`, [cutoff]);
      const byIdle = await db.query(`DELETE FROM ${table} WHERE idle_expires_at <= $1`, [cutoff]);
      return affected(byAbsolute) + affected(byIdle);
    },
  };
}
