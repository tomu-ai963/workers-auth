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
  return kvSessionStore(env.KV, { clock, ...extra });
}

const NEW_SESSION = {
  userId: 'user_1',
  subjectType: 'user' as const,
  idleTtlSec: 7 * DAY,
  absoluteTtlSec: 30 * DAY,
};

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

  it('never writes the raw session id to the store', async () => {
    const store = makeStore();
    const created = await store.create(NEW_SESSION);

    const hashedKey = `sess:${await sha256Hex(created.sid)}`;
    const stored = await env.KV.get(hashedKey);
    expect(stored).not.toBeNull();
    expect(stored).not.toContain(created.sid);

    const { keys } = await env.KV.list({ prefix: 'sess:' });
    expect(keys.map((k) => k.name)).toEqual([hashedKey]);
  });

  it('returns null for an unknown session id', async () => {
    const store = makeStore();
    expect(await store.get('not-a-real-session-id')).toBeNull();
  });

  it('revokes every session of one user and leaves others alone', async () => {
    const store = makeStore();
    const a1 = await store.create(NEW_SESSION);
    const a2 = await store.create(NEW_SESSION);
    const b1 = await store.create({ ...NEW_SESSION, userId: 'user_2' });

    await store.revokeAllForUser('user_1');

    expect(await store.get(a1.sid)).toBeNull();
    expect(await store.get(a2.sid)).toBeNull();
    expect(await store.get(b1.sid)).not.toBeNull();

    const index = await env.KV.list({ prefix: 'uidx:user_1:' });
    expect(index.keys).toHaveLength(0);
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

  it('refuses to push the idle window past the absolute one', async () => {
    const store = makeStore();
    const created = await store.create(NEW_SESSION);

    await store.touch(created.sid, created.absoluteExpiresAt + 10 * DAY * 1000);
    const touched = await store.get(created.sid);
    expect(touched?.idleExpiresAt).toBe(created.absoluteExpiresAt);
  });

  it('rejects sessions without both TTLs', async () => {
    const store = makeStore();
    await expect(
      store.create({ ...NEW_SESSION, idleTtlSec: 0 }),
    ).rejects.toThrow(/idleTtlSec/);
    await expect(
      store.create({ ...NEW_SESSION, absoluteTtlSec: Number.NaN }),
    ).rejects.toThrow(/absoluteTtlSec/);
  });

  describe('with a revocation list', () => {
    it('rejects a revoked session immediately', async () => {
      const store = makeStore({ revocation: revocationList(env.DB, { clock }) });
      const created = await store.create(NEW_SESSION);
      expect(await store.get(created.sid)).not.toBeNull();

      await store.revoke(created.sid);
      expect(await store.get(created.sid)).toBeNull();
    });

    it('still rejects when a stale KV replica serves the deleted record', async () => {
      const revocation = revocationList(env.DB, { clock });
      const store = makeStore({ revocation });
      const created = await store.create(NEW_SESSION);

      const key = `sess:${await sha256Hex(created.sid)}`;
      const raw = (await env.KV.get(key)) as string;

      await store.revoke(created.sid);
      // Simulate KV eventual consistency: the record reappears.
      await env.KV.put(key, raw, { expirationTtl: 60 });

      expect(await store.get(created.sid)).toBeNull();
    });

    it('tombstones every session on revokeAllForUser', async () => {
      const revocation = revocationList(env.DB, { clock });
      const store = makeStore({ revocation });
      const s1 = await store.create(NEW_SESSION);
      const s2 = await store.create(NEW_SESSION);

      const keys = await Promise.all([sha256Hex(s1.sid), sha256Hex(s2.sid)]);
      const raws = await Promise.all(keys.map((k) => env.KV.get(`sess:${k}`) as Promise<string>));

      await store.revokeAllForUser('user_1');
      await Promise.all(keys.map((k, i) => env.KV.put(`sess:${k}`, raws[i] as string, { expirationTtl: 60 })));

      expect(await store.get(s1.sid)).toBeNull();
      expect(await store.get(s2.sid)).toBeNull();
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
  });
});
