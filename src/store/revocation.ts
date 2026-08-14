/**
 * D1-backed revocation list.
 *
 * KV is eventually consistent: a `delete` can take up to ~60s to be visible at
 * every PoP, which means a logged-out session can keep working. When immediate
 * revocation matters, keep KV as the primary store and put the (small,
 * short-lived) tombstones in D1, which is strongly consistent.
 *
 * Only `sha256(sid)` hex ever reaches this table.
 */

import type { Clock, RevocationList } from '../types.js';

export type RevocationListOptions = {
  /** Table name. Must be a bare SQL identifier. Default: `auth_revocations`. */
  table?: string;
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
  const now: Clock = options.clock ?? Date.now;

  return {
    async isRevoked(sidHash: string): Promise<boolean> {
      const row = await db
        .prepare(`SELECT 1 AS hit FROM ${table} WHERE sid_hash = ?1 AND expires_at > ?2 LIMIT 1`)
        .bind(sidHash, now())
        .first<{ hit: number }>();
      return row !== null;
    },

    async revoke(sidHash: string, expiresAt: number): Promise<void> {
      await db
        .prepare(
          `INSERT INTO ${table} (sid_hash, expires_at, revoked_at) VALUES (?1, ?2, ?3)
           ON CONFLICT(sid_hash) DO UPDATE SET expires_at = MAX(expires_at, excluded.expires_at)`,
        )
        .bind(sidHash, expiresAt, now())
        .run();
    },

    async revokeMany(entries: Array<{ sidHash: string; expiresAt: number }>): Promise<void> {
      if (entries.length === 0) return;
      const stmt = db.prepare(
        `INSERT INTO ${table} (sid_hash, expires_at, revoked_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(sid_hash) DO UPDATE SET expires_at = MAX(expires_at, excluded.expires_at)`,
      );
      const at = now();
      await db.batch(entries.map((e) => stmt.bind(e.sidHash, e.expiresAt, at)));
    },

    /**
     * Drops tombstones whose underlying session has expired on its own. Safe to
     * run from a cron trigger; returns the number of rows removed.
     */
    async cleanup(at?: number): Promise<number> {
      const result = await db
        .prepare(`DELETE FROM ${table} WHERE expires_at <= ?1`)
        .bind(at ?? now())
        .run();
      return result.meta.changes ?? 0;
    },
  };
}
