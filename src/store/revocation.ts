/**
 * D1-backed revocation, in two forms.
 *
 * 1. Per-session tombstones (`auth_revocations`) — KV deletes are eventually
 *    consistent, so a logged-out session can keep working for up to ~a minute.
 * 2. Per-user markers (`auth_user_revocations`) — "log out everywhere" cannot
 *    be built on an enumeration of sessions, because KV's listing is itself
 *    eventually consistent and a session created moments earlier may not appear
 *    in it. A single timestamp per user needs no enumeration and therefore
 *    cannot miss anything.
 *
 * Only `sha256(sid)` hex ever reaches this module.
 */

import type { Clock, RevocationList, RevocationQuery } from '../types.js';

export type RevocationListOptions = {
  /** Per-session tombstone table. Default: `auth_revocations`. */
  table?: string;
  /** Per-user marker table. Default: `auth_user_revocations`. */
  userTable?: string;
  /**
   * Longest absolute session lifetime any caller configures, in seconds.
   * `cleanup()` uses it to decide when a user marker is finally safe to delete.
   * Too small and cleanup un-revokes sessions; the default is deliberately
   * generous. Default: 90 days.
   */
  maxSessionLifetimeSec?: number;
  clock?: Clock;
};

const IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function assertIdentifier(name: string, label: string): string {
  if (!IDENTIFIER_RE.test(name)) {
    throw new TypeError(`${label}: ${JSON.stringify(name)} is not a valid SQL identifier`);
  }
  return name;
}

export function revocationList(db: D1Database, options: RevocationListOptions = {}): RevocationList {
  const table = assertIdentifier(options.table ?? 'auth_revocations', 'revocationList.table');
  const userTable = assertIdentifier(
    options.userTable ?? 'auth_user_revocations',
    'revocationList.userTable',
  );
  const maxSessionLifetimeMs = (options.maxSessionLifetimeSec ?? 60 * 60 * 24 * 90) * 1000;
  const now: Clock = options.clock ?? Date.now;

  const upsertTombstone = `INSERT INTO ${table} (sid_hash, expires_at, revoked_at) VALUES (?1, ?2, ?3)
     ON CONFLICT(sid_hash) DO UPDATE SET expires_at = MAX(expires_at, excluded.expires_at)`;

  return {
    /**
     * One round trip covers both questions. `revoked_before > createdAt` is the
     * user-level test: the marker is written as `now + 1`, so a session created
     * in the same millisecond as the revocation is also invalidated.
     */
    async isRevoked(query: RevocationQuery): Promise<boolean> {
      const row = await db
        .prepare(
          `SELECT 1 AS hit FROM ${table} WHERE sid_hash = ?1 AND expires_at > ?3
           UNION ALL
           SELECT 1 AS hit FROM ${userTable} WHERE user_id = ?2 AND revoked_before > ?4
           LIMIT 1`,
        )
        .bind(query.sidHash, query.userId, now(), query.createdAt)
        .first<{ hit: number }>();
      return row !== null;
    },

    async revoke(sidHash: string, expiresAt: number): Promise<void> {
      await db.prepare(upsertTombstone).bind(sidHash, expiresAt, now()).run();
    },

    async revokeMany(entries: Array<{ sidHash: string; expiresAt: number }>): Promise<void> {
      if (entries.length === 0) return;
      const stmt = db.prepare(upsertTombstone);
      const at = now();
      await db.batch(entries.map((e) => stmt.bind(e.sidHash, e.expiresAt, at)));
    },

    async revokeUser(userId: string, revokedBefore: number): Promise<void> {
      await db
        .prepare(
          `INSERT INTO ${userTable} (user_id, revoked_before, revoked_at) VALUES (?1, ?2, ?3)
           ON CONFLICT(user_id) DO UPDATE SET
             revoked_before = MAX(revoked_before, excluded.revoked_before),
             revoked_at = excluded.revoked_at`,
        )
        .bind(userId, revokedBefore, now())
        .run();
    },

    /**
     * Safe to run from a cron trigger. Returns the number of rows removed.
     *
     * The two tables have very different deletion rules:
     *
     * - a tombstone may go as soon as its own session would have expired
     *   (`expires_at <= now`);
     * - a user marker may NOT. It has no expiry of its own — it must outlive
     *   every session it invalidates, and the oldest such session can be as old
     *   as `maxSessionLifetimeSec`. Deleting a marker early silently
     *   un-revokes every session created before it. Hence the cutoff is
     *   `now - maxSessionLifetimeMs`, never `now`.
     */
    async cleanup(at?: number): Promise<number> {
      const cutoff = at ?? now();
      const [tombstones, markers] = await db.batch<unknown>([
        db.prepare(`DELETE FROM ${table} WHERE expires_at <= ?1`).bind(cutoff),
        db
          .prepare(`DELETE FROM ${userTable} WHERE revoked_before <= ?1`)
          .bind(cutoff - maxSessionLifetimeMs),
      ]);
      return (tombstones?.meta.changes ?? 0) + (markers?.meta.changes ?? 0);
    },
  };
}
