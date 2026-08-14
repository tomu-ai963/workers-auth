/**
 * KV-backed SessionStore — the default.
 *
 * Layout:
 *   sess:<sha256(sid)>              -> JSON session record (no raw sid inside)
 *   uidx:<enc(userId)>:<sha256(sid)> -> "1", reverse index for revokeAllForUser
 *
 * Expiry is enforced in code as well as through `expirationTtl`: KV's minimum
 * TTL is 60s and its deletes are eventually consistent, so the TTL is garbage
 * collection, not an access control mechanism.
 */

import { randomToken, sha256Hex } from '../crypto.js';
import type { Clock, NewSession, RevocationList, Session, SessionStore, SubjectType } from '../types.js';

export type KvSessionStoreOptions = {
  /** Key prefix for session records. Default: `sess:`. */
  prefix?: string;
  /** Key prefix for the per-user reverse index. Default: `uidx:`. */
  userIndexPrefix?: string;
  /**
   * Optional strongly-consistent revocation list. Without it, `revoke()` is
   * subject to KV's eventual consistency; with it, `get()` costs one D1 read.
   */
  revocation?: RevocationList;
  /**
   * Tombstone horizon used when `revoke()` cannot read the session record (KV
   * read-after-write lag). Default: 30 days.
   */
  tombstoneFallbackSec?: number;
  clock?: Clock;
};

type StoredSession = {
  v: 1;
  userId: string;
  subjectType: SubjectType;
  createdAt: number;
  lastSeenAt: number;
  idleExpiresAt: number;
  absoluteExpiresAt: number;
  scope?: Session['scope'];
  meta?: Record<string, unknown>;
};

/** KV refuses TTLs below 60 seconds. */
const KV_MIN_TTL_SEC = 60;

function ttlSecondsUntil(expiresAt: number, now: number): number {
  return Math.max(KV_MIN_TTL_SEC, Math.ceil((expiresAt - now) / 1000));
}

function assertTtls(input: NewSession): void {
  if (!Number.isFinite(input.idleTtlSec) || input.idleTtlSec <= 0) {
    throw new TypeError('session: idleTtlSec must be a positive number of seconds');
  }
  if (!Number.isFinite(input.absoluteTtlSec) || input.absoluteTtlSec <= 0) {
    throw new TypeError('session: absoluteTtlSec must be a positive number of seconds');
  }
}

export function kvSessionStore(kv: KVNamespace, options: KvSessionStoreOptions = {}): SessionStore {
  const prefix = options.prefix ?? 'sess:';
  const userIndexPrefix = options.userIndexPrefix ?? 'uidx:';
  const revocation = options.revocation;
  const tombstoneFallbackMs = (options.tombstoneFallbackSec ?? 60 * 60 * 24 * 30) * 1000;
  const now: Clock = options.clock ?? Date.now;

  const sessionKey = (sidHash: string) => `${prefix}${sidHash}`;
  const indexKey = (userId: string, sidHash: string) =>
    `${userIndexPrefix}${encodeURIComponent(userId)}:${sidHash}`;

  async function readRecord(sidHash: string): Promise<StoredSession | null> {
    const record = await kv.get<StoredSession>(sessionKey(sidHash), 'json');
    return record ?? null;
  }

  async function forget(sidHash: string, userId?: string): Promise<void> {
    const deletions = [kv.delete(sessionKey(sidHash))];
    if (userId !== undefined) deletions.push(kv.delete(indexKey(userId, sidHash)));
    await Promise.all(deletions);
  }

  return {
    async create(input: NewSession): Promise<Session> {
      assertTtls(input);
      const at = now();
      const sid = randomToken();
      const sidHash = await sha256Hex(sid);

      const absoluteExpiresAt = at + input.absoluteTtlSec * 1000;
      // The idle window can never outlive the absolute one.
      const idleExpiresAt = Math.min(at + input.idleTtlSec * 1000, absoluteExpiresAt);

      const record: StoredSession = {
        v: 1,
        userId: input.userId,
        subjectType: input.subjectType,
        createdAt: at,
        lastSeenAt: at,
        idleExpiresAt,
        absoluteExpiresAt,
        ...(input.scope ? { scope: input.scope } : {}),
        ...(input.meta ? { meta: input.meta } : {}),
      };

      const expirationTtl = ttlSecondsUntil(absoluteExpiresAt, at);
      await Promise.all([
        kv.put(sessionKey(sidHash), JSON.stringify(record), { expirationTtl }),
        kv.put(indexKey(input.userId, sidHash), '1', { expirationTtl }),
      ]);

      return { sid, ...toSession(record) };
    },

    async get(sid: string): Promise<Session | null> {
      const sidHash = await sha256Hex(sid);
      const record = await readRecord(sidHash);
      if (!record) return null;

      if (revocation && (await revocation.isRevoked(sidHash))) return null;

      const at = now();
      if (at >= record.idleExpiresAt || at >= record.absoluteExpiresAt) {
        await forget(sidHash, record.userId);
        return null;
      }
      return { sid, ...toSession(record) };
    },

    async touch(sid: string, idleExpiresAt: number): Promise<void> {
      const sidHash = await sha256Hex(sid);
      const record = await readRecord(sidHash);
      if (!record) return;

      const at = now();
      if (at >= record.idleExpiresAt || at >= record.absoluteExpiresAt) {
        await forget(sidHash, record.userId);
        return;
      }

      const next: StoredSession = {
        ...record,
        lastSeenAt: at,
        idleExpiresAt: Math.min(idleExpiresAt, record.absoluteExpiresAt),
      };
      await kv.put(sessionKey(sidHash), JSON.stringify(next), {
        expirationTtl: ttlSecondsUntil(record.absoluteExpiresAt, at),
      });
    },

    async revoke(sid: string): Promise<void> {
      const sidHash = await sha256Hex(sid);
      const record = await readRecord(sidHash);

      // Tombstone first: if the record is not visible yet (KV read-after-write
      // lag) we still must not let the session keep working.
      if (revocation) {
        const expiresAt = record?.absoluteExpiresAt ?? now() + tombstoneFallbackMs;
        await revocation.revoke(sidHash, expiresAt);
      }
      await forget(sidHash, record?.userId);
    },

    async revokeAllForUser(userId: string): Promise<void> {
      const listPrefix = `${userIndexPrefix}${encodeURIComponent(userId)}:`;
      let cursor: string | undefined;

      do {
        const page = await kv.list({ prefix: listPrefix, ...(cursor ? { cursor } : {}) });
        const sidHashes = page.keys.map((k) => k.name.slice(listPrefix.length)).filter(Boolean);

        if (sidHashes.length > 0) {
          if (revocation) {
            const records = await Promise.all(sidHashes.map((h) => readRecord(h)));
            const fallback = now() + tombstoneFallbackMs;
            await revocation.revokeMany(
              sidHashes.map((sidHash, i) => ({
                sidHash,
                expiresAt: records[i]?.absoluteExpiresAt ?? fallback,
              })),
            );
          }
          await Promise.all(
            sidHashes.flatMap((sidHash) => [
              kv.delete(sessionKey(sidHash)),
              kv.delete(`${listPrefix}${sidHash}`),
            ]),
          );
        }

        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
    },
  };
}

function toSession(record: StoredSession): Omit<Session, 'sid'> {
  return {
    userId: record.userId,
    subjectType: record.subjectType,
    createdAt: record.createdAt,
    lastSeenAt: record.lastSeenAt,
    idleExpiresAt: record.idleExpiresAt,
    absoluteExpiresAt: record.absoluteExpiresAt,
    ...(record.scope ? { scope: record.scope } : {}),
    ...(record.meta ? { meta: record.meta } : {}),
  };
}
