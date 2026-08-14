import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { sha256Hex } from '../src/crypto.js';
import { kvSessionStore } from '../src/store/kv.js';
import { revocationList } from '../src/store/revocation.js';
import type { SessionStore } from '../src/types.js';
import { resetStorage } from './helpers/reset.js';

const HOUR = 60 * 60;
const DAY = 24 * HOUR;

let now = 1_700_000_000_000;
const clock = () => now;

function makeStore(extra: Parameters<typeof kvSessionStore>[1] = {}): SessionStore {
  return kvSessionStore(env.KV, { clock, touchThrottleSec: 0, ...extra });
}

const NEW_SESSION = {
  userId: 'user_1',
  subjectType: 'user' as const,
  idleTtlSec: 7 * DAY,
  absoluteTtlSec: 30 * DAY,
};

/**
 * KV wrapper that can hold a `put` open, so a request already in flight can be
 * made to land its write after another request has finished.
 */
function gatedKv(kv: KVNamespace) {
  let gate: Promise<void> | null = null;
  let open: (() => void) | null = null;
  const call = (name: 'get' | 'put' | 'delete' | 'list', args: unknown[]) =>
    (kv[name] as never as (...x: unknown[]) => unknown)(...args);

  return {
    kv: {
      get: (...a: unknown[]) => call('get', a),
      list: (...a: unknown[]) => call('list', a),
      delete: (...a: unknown[]) => call('delete', a),
      put: async (...a: unknown[]) => {
        if (gate) await gate;
        return call('put', a);
      },
    } as unknown as KVNamespace,
    hold() {
      gate = new Promise<void>((r) => {
        open = r;
      });
    },
    release() {
      open?.();
      gate = null;
    },
  };
}

beforeEach(async () => {
  now = 1_700_000_000_000;
  await resetStorage();
});

describe('kvSessionStore', () => {
  it('runs the create -> get -> touch -> revoke lifecycle', async () => {
    const store = makeStore();

    const created = await store.create({ ...NEW_SESSION, meta: { email: 'a@example.com' } });
    expect(created.sid).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(created.userId).toBe('user_1');
    expect(created.absoluteExpiresAt).toBe(now + 30 * DAY * 1000);
    expect(created.idleExpiresAt).toBe(now + 7 * DAY * 1000);

    const fetched = await store.get(created.sid);
    expect(fetched).not.toBeNull();
    expect(fetched?.userId).toBe('user_1');
    expect(fetched?.meta).toEqual({ email: 'a@example.com' });

    now += HOUR * 1000;
    await store.touch(created.sid, now + 7 * DAY * 1000);
    const touched = await store.get(created.sid);
    expect(touched?.idleExpiresAt).toBe(now + 7 * DAY * 1000);
    expect(touched?.lastSeenAt).toBe(now);
    expect(touched?.absoluteExpiresAt).toBe(created.absoluteExpiresAt);

    await store.revoke(created.sid);
    expect(await store.get(created.sid)).toBeNull();
  });

  it('never writes the raw session id to any key or value', async () => {
    const store = makeStore();
    const created = await store.create(NEW_SESSION);
    await store.touch(created.sid, now + 7 * DAY * 1000);

    const hash = await sha256Hex(created.sid);
    const { keys } = await env.KV.list();
    expect(keys.map((k) => k.name).sort()).toEqual([`seen:${hash}`, `sess:${hash}`]);

    for (const key of keys) {
      expect(key.name).not.toContain(created.sid);
      expect((await env.KV.get(key.name)) ?? '').not.toContain(created.sid);
    }
  });

  it('writes one key per login (no reverse index)', async () => {
    const store = makeStore();
    await store.create(NEW_SESSION);
    const { keys } = await env.KV.list();
    expect(keys).toHaveLength(1);
    expect(keys[0]?.name.startsWith('sess:')).toBe(true);
  });

  it('returns null for an unknown session id', async () => {
    const store = makeStore();
    expect(await store.get('not-a-real-session-id')).toBeNull();
  });

  it('expires at the absolute deadline even while active', async () => {
    const store = makeStore();
    const created = await store.create({ ...NEW_SESSION, idleTtlSec: 30 * DAY, absoluteTtlSec: 30 * DAY });

    now = created.absoluteExpiresAt - 1;
    expect(await store.get(created.sid)).not.toBeNull();

    now = created.absoluteExpiresAt;
    expect(await store.get(created.sid)).toBeNull();
  });

  it('expires after the idle window', async () => {
    const store = makeStore();
    const created = await store.create(NEW_SESSION);

    now = created.idleExpiresAt - 1;
    expect(await store.get(created.sid)).not.toBeNull();

    now = created.idleExpiresAt;
    expect(await store.get(created.sid)).toBeNull();
  });

  it('derives the first idle window from createdAt when nothing has touched it', async () => {
    const store = makeStore();
    const created = await store.create(NEW_SESSION);
    const fetched = await store.get(created.sid);
    expect(fetched?.idleExpiresAt).toBe(created.createdAt + 7 * DAY * 1000);
    expect(fetched?.lastSeenAt).toBe(created.createdAt);
  });

  it('refuses to push the idle window past the absolute one', async () => {
    const store = makeStore();
    const created = await store.create(NEW_SESSION);

    await store.touch(created.sid, created.absoluteExpiresAt + 10 * DAY * 1000);
    const touched = await store.get(created.sid);
    expect(touched?.idleExpiresAt).toBe(created.absoluteExpiresAt);
  });

  it('rejects sessions without both TTLs', async () => {
    const store = makeStore();
    await expect(store.create({ ...NEW_SESSION, idleTtlSec: 0 })).rejects.toThrow(/idleTtlSec/);
    await expect(store.create({ ...NEW_SESSION, absoluteTtlSec: Number.NaN })).rejects.toThrow(
      /absoluteTtlSec/,
    );
  });

  it('throttles idle-marker writes to protect the KV per-key write limit', async () => {
    const store = kvSessionStore(env.KV, { clock, touchThrottleSec: 10 });
    const created = await store.create(NEW_SESSION);

    now += 1000;
    await store.touch(created.sid, now + 7 * DAY * 1000);
    const first = (await store.get(created.sid))?.lastSeenAt;

    now += 1000; // inside the throttle window: the write is skipped
    await store.touch(created.sid, now + 7 * DAY * 1000);
    expect((await store.get(created.sid))?.lastSeenAt).toBe(first);

    now += 10_000; // past it
    await store.touch(created.sid, now + 7 * DAY * 1000);
    expect((await store.get(created.sid))?.lastSeenAt).toBe(now);
  });
});

/** Regression: an in-flight request used to be able to undo a logout. */
describe('kvSessionStore: revoke cannot be undone by a concurrent touch', () => {
  it('keeps a revoked session dead when a touch lands afterwards', async () => {
    const g = gatedKv(env.KV);
    const store = kvSessionStore(g.kv, { clock, touchThrottleSec: 0 });
    const created = await store.create(NEW_SESSION);

    // Request A is mid-touch: its write is pending.
    g.hold();
    const inflight = store.touch(created.sid, now + 7 * DAY * 1000);
    await new Promise((r) => setTimeout(r, 0));

    // Request B logs the user out and completes.
    await store.revoke(created.sid);
    expect(await store.get(created.sid)).toBeNull();

    // Request A's write now lands. It must not bring the session back.
    g.release();
    await inflight;

    expect(await store.get(created.sid)).toBeNull();
  });

  it('holds even when the touch is the very first write for that session', async () => {
    const g = gatedKv(env.KV);
    const store = kvSessionStore(g.kv, { clock, touchThrottleSec: 0 });
    const created = await store.create(NEW_SESSION);

    g.hold();
    const inflight = store.touch(created.sid, now + 30 * DAY * 1000);
    await new Promise((r) => setTimeout(r, 0));
    await store.revoke(created.sid);
    g.release();
    await inflight;

    expect(await store.get(created.sid)).toBeNull();
    // The stray marker is inert; only the record grants access.
    const stray = await env.KV.get(`seen:${await sha256Hex(created.sid)}`);
    expect(stray).not.toBeNull();
    expect(await store.get(created.sid)).toBeNull();
  });

  it('leaves the session record untouched across touches', async () => {
    const store = makeStore();
    const created = await store.create(NEW_SESSION);
    const key = `sess:${await sha256Hex(created.sid)}`;
    const before = await env.KV.get(key);

    now += HOUR * 1000;
    await store.touch(created.sid, now + 7 * DAY * 1000);

    expect(await env.KV.get(key)).toBe(before);
  });
});

describe('kvSessionStore: revokeAllForUser', () => {
  it('refuses to run without a revocation list instead of half working', async () => {
    const store = makeStore();
    await store.create(NEW_SESSION);
    await expect(store.revokeAllForUser('user_1')).rejects.toThrow(/requires a revocation list/);
  });

  it('invalidates every session of the user, and only that user', async () => {
    const store = makeStore({ revocation: revocationList(env.DB, { clock }) });
    const a1 = await store.create(NEW_SESSION);
    const a2 = await store.create(NEW_SESSION);
    const b1 = await store.create({ ...NEW_SESSION, userId: 'user_2' });

    await store.revokeAllForUser('user_1');

    expect(await store.get(a1.sid)).toBeNull();
    expect(await store.get(a2.sid)).toBeNull();
    expect(await store.get(b1.sid)).not.toBeNull();
  });

  /**
   * Regression: the old implementation swept an eventually-consistent
   * `uidx:` listing, so a session missing from the listing survived.
   */
  it('does not depend on any listing being up to date', async () => {
    const store = makeStore({ revocation: revocationList(env.DB, { clock }) });
    const created = await store.create(NEW_SESSION);

    const listed = await env.KV.list();
    expect(listed.keys.some((k) => k.name.startsWith('uidx:'))).toBe(false);

    await store.revokeAllForUser('user_1');
    expect(await store.get(created.sid)).toBeNull();
  });

  it('catches a session created in the same millisecond as the revocation', async () => {
    const store = makeStore({ revocation: revocationList(env.DB, { clock }) });
    const created = await store.create(NEW_SESSION);
    // Clock does not advance: createdAt === revocation time.
    await store.revokeAllForUser('user_1');
    expect(await store.get(created.sid)).toBeNull();
  });

  it('lets a session created after the revocation through', async () => {
    const store = makeStore({ revocation: revocationList(env.DB, { clock }) });
    await store.revokeAllForUser('user_1');

    now += 1;
    const fresh = await store.create(NEW_SESSION);
    expect(await store.get(fresh.sid)).not.toBeNull();
  });
});

describe('kvSessionStore: single-session revocation list', () => {
  it('rejects a revoked session immediately', async () => {
    const store = makeStore({ revocation: revocationList(env.DB, { clock }) });
    const created = await store.create(NEW_SESSION);
    expect(await store.get(created.sid)).not.toBeNull();

    await store.revoke(created.sid);
    expect(await store.get(created.sid)).toBeNull();
  });

  it('still rejects when a stale KV replica serves the deleted record', async () => {
    const store = makeStore({ revocation: revocationList(env.DB, { clock }) });
    const created = await store.create(NEW_SESSION);

    const key = `sess:${await sha256Hex(created.sid)}`;
    const raw = (await env.KV.get(key)) as string;

    await store.revoke(created.sid);
    await env.KV.put(key, raw, { expirationTtl: 60 });

    expect(await store.get(created.sid)).toBeNull();
  });

  it('drops tombstones once the underlying session would have expired', async () => {
    const revocation = revocationList(env.DB, { clock });
    const store = makeStore({ revocation });
    const created = await store.create(NEW_SESSION);
    await store.revoke(created.sid);

    expect(await revocation.cleanup()).toBe(0);
    now = created.absoluteExpiresAt + 1;
    expect(await revocation.cleanup()).toBe(1);
  });

  it('keeps user markers until no session could predate them', async () => {
    const revocation = revocationList(env.DB, { clock, maxSessionLifetimeSec: 30 * DAY });
    const store = makeStore({ revocation });
    const created = await store.create(NEW_SESSION);
    await store.revokeAllForUser('user_1');

    // A premature cleanup would un-revoke the session.
    now += 29 * DAY * 1000;
    expect(await revocation.cleanup()).toBe(0);
    expect(await store.get(created.sid)).toBeNull();

    now += 2 * DAY * 1000;
    expect(await revocation.cleanup()).toBe(1);
  });
});
