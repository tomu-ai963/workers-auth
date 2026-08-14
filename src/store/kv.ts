/**
 * KV-backed SessionStore — the default.
 *
 * Layout:
 *   sess:<sha256(sid)>  -> the session record. Written once at create, never
 *                          rewritten. Holds the absolute expiry.
 *   seen:<sha256(sid)>  -> the sliding idle window. Written by `touch()`.
 *
 * Why two keys: KV has no compare-and-set, so any read-modify-write on the
 * session record races with `revoke()`. If `touch()` re-wrote the record, a
 * request already in flight could land its write *after* a logout deleted the
 * record and bring the session back from the dead. Splitting the mutable part
 * out means a late `touch()` writes a marker for a record that no longer
 * exists, which `get()` ignores. The race stops being a correctness problem
 * and becomes a stray key that KV expires on its own.
 *
 * Expiry is enforced in code as well as through `expirationTtl`: KV's minimum
 * TTL is 60s and its deletes are eventually consistent, so the TTL is garbage
 * collection, not access control.
 */

import { randomToken, sha256Hex } from '../crypto.js';
import type { Clock, NewSession, RevocationList, Session, SessionStore, SubjectType } from '../types.js';

export type KvSessionStoreOptions = {
  /** Key prefix for session records. Default: `sess:`. */
  prefix?: string;
  /** Key prefix for idle-window markers. Default: `seen:`. */
  seenPrefix?: string;
  /**
   * Strongly-consistent revocation list. Without it `revoke()` is subject to
   * KV's eventual consistency and `revokeAllForUser()` throws outright.
   */
  revocation?: RevocationList;
  /**
   * Tombstone horizon used when `revoke()` cannot read the session record (KV
   * read-after-write lag). Default: 30 days.
   */
  tombstoneFallbackSec?: number;
  /**
   * Floor on how often one session's idle marker is written, in seconds.
   * KV rate-limits writes to a single key to about one per second, and a burst
   * of concurrent requests would otherwise all decide to touch at once.
   * Default: 10.
   */
  touchThrottleSec?: number;
  clock?: Clock;
};

type StoredSession = {
  v: 2;
  userId: string;
  subjectType: SubjectType;
  createdAt: number;
  absoluteExpiresAt: number;
  /** Kept so `get()` can derive the initial idle window without a marker. */
  idleTtlSec: number;
  scope?: Session['scope'];
  meta?: Record<string, unknown>;
};

/** `e` = idle expiry, `s` = last seen. Both epoch ms. */
type SeenMarker = { e: number; s: number };

const RECORD_VERSION = 2;

/** KV refuses TTLs below 60 seconds. */
const KV_MIN_TTL_SEC = 60;

/**
 * Per-isolate record of the last idle-marker write per key. Module scope on
 * purpose: `createAuth()` is typically called per request, so a store-instance
 * map would reset every time and throttle nothing.
 */
const touchGuard = new Map<string, number>();
const TOUCH_GUARD_MAX = 4096;

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
  const seenPrefix = options.seenPrefix ?? 'seen:';
  const revocation = options.revocation;
  const tombstoneFallbackMs = (options.tombstoneFallbackSec ?? 60 * 60 * 24 * 30) * 1000;
  const touchThrottleMs = (options.touchThrottleSec ?? 10) * 1000;
  const now: Clock = options.clock ?? Date.now;

  const sessionKey = (sidHash: string) => `${prefix}${sidHash}`;
  const seenKey = (sidHash: string) => `${seenPrefix}${sidHash}`;

  async function forget(sidHash: string): Promise<void> {
    await Promise.all([kv.delete(sessionKey(sidHash)), kv.delete(seenKey(sidHash))]);
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
        v: RECORD_VERSION,
        userId: input.userId,
        subjectType: input.subjectType,
        createdAt: at,
        absoluteExpiresAt,
        idleTtlSec: input.idleTtlSec,
        ...(input.scope ? { scope: input.scope } : {}),
        ...(input.meta ? { meta: input.meta } : {}),
      };

      // No idle marker is written here: its absence means "never touched", and
      // `get()` derives the first window from `createdAt`.
      await kv.put(sessionKey(sidHash), JSON.stringify(record), {
        expirationTtl: ttlSecondsUntil(absoluteExpiresAt, at),
      });

      return {
        sid,
        userId: record.userId,
        subjectType: record.subjectType,
        createdAt: at,
        lastSeenAt: at,
        idleExpiresAt,
        absoluteExpiresAt,
        ...(record.scope ? { scope: record.scope } : {}),
        ...(record.meta ? { meta: record.meta } : {}),
      };
    },

    async get(sid: string): Promise<Session | null> {
      const sidHash = await sha256Hex(sid);

      // Independent reads: issued together so the extra key costs an operation
      // but not a round trip.
      const [record, seen] = await Promise.all([
        kv.get<StoredSession>(sessionKey(sidHash), 'json'),
        kv.get<SeenMarker>(seenKey(sidHash), 'json'),
      ]);
      if (!record || record.v !== RECORD_VERSION) return null;

      const at = now();
      if (at >= record.absoluteExpiresAt) {
        await forget(sidHash);
        return null;
      }

      // A marker for a record that no longer exists is unreachable, and a
      // marker written before an absolute expiry is clamped here rather than at
      // write time — which is what lets `touch()` avoid reading the record.
      const derivedIdleExpiry = record.createdAt + record.idleTtlSec * 1000;
      const idleExpiresAt = Math.min(seen?.e ?? derivedIdleExpiry, record.absoluteExpiresAt);
      if (at >= idleExpiresAt) {
        await forget(sidHash);
        return null;
      }

      if (
        revocation &&
        (await revocation.isRevoked({ sidHash, userId: record.userId, createdAt: record.createdAt }))
      ) {
        return null;
      }

      return {
        sid,
        userId: record.userId,
        subjectType: record.subjectType,
        createdAt: record.createdAt,
        lastSeenAt: seen?.s ?? record.createdAt,
        idleExpiresAt,
        absoluteExpiresAt: record.absoluteExpiresAt,
        ...(record.scope ? { scope: record.scope } : {}),
        ...(record.meta ? { meta: record.meta } : {}),
      };
    },

    /**
     * A single blind write. It never reads, never touches the session record,
     * and therefore can never resurrect one.
     */
    async touch(sid: string, idleExpiresAt: number): Promise<void> {
      const at = now();
      if (idleExpiresAt <= at) return;

      const sidHash = await sha256Hex(sid);
      const key = seenKey(sidHash);

      const lastWrite = touchGuard.get(key);
      if (lastWrite !== undefined && at - lastWrite < touchThrottleMs) return;
      if (touchGuard.size >= TOUCH_GUARD_MAX) touchGuard.clear();
      touchGuard.set(key, at);

      const marker: SeenMarker = { e: idleExpiresAt, s: at };
      await kv.put(key, JSON.stringify(marker), {
        expirationTtl: ttlSecondsUntil(idleExpiresAt, at),
      });
    },

    async revoke(sid: string): Promise<void> {
      const sidHash = await sha256Hex(sid);
      const record = await kv.get<StoredSession>(sessionKey(sidHash), 'json');

      // Tombstone first: if the record is not visible yet (KV read-after-write
      // lag) we still must not let the session keep working.
      if (revocation) {
        const expiresAt = record?.absoluteExpiresAt ?? now() + tombstoneFallbackMs;
        await revocation.revoke(sidHash, expiresAt);
      }
      await forget(sidHash);
    },

    /**
     * Requires a revocation list, and says so loudly rather than doing the job
     * halfway.
     *
     * The obvious KV-only implementation — keep a `uidx:<userId>:*` index and
     * list it — cannot work: KV's listing is eventually consistent, so a
     * session created shortly before the revocation may not be in the listing
     * yet and would survive "log out everywhere" without a trace. There is no
     * KV-only construction that fixes that, so the store refuses instead.
     */
    async revokeAllForUser(userId: string): Promise<void> {
      if (!revocation) {
        throw new Error(
          'kvSessionStore: revokeAllForUser() requires a revocation list. ' +
            'KV listing is eventually consistent, so a KV-only sweep can silently miss a ' +
            'freshly created session. Pass `revocation: revocationList(env.DB)`, or use ' +
            'd1SessionStore.',
        );
      }
      // `now + 1` so a session created in the same millisecond is also caught.
      await revocation.revokeUser(userId, now() + 1);
    },
  };
}
