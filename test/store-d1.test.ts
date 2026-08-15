import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { sha256Hex } from '../src/crypto.js';
import { d1SessionStore } from '../src/store/d1.js';
import { kvSessionStore } from '../src/store/kv.js';
import { revocationList } from '../src/store/revocation.js';
import { resetStorage } from './helpers/reset.js';

const HOUR = 60 * 60;
const DAY = 24 * HOUR;

let now = 1_700_000_000_000;
const clock = () => now;

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

describe('d1SessionStore', () => {
  it('runs the create -> get -> touch -> revoke lifecycle', async () => {
    const store = d1SessionStore(env.DB, { clock });

    const created = await store.create({
      ...NEW_SESSION,
      scope: { orgId: 'org_1', role: 'admin' },
      meta: { email: 'a@example.com' },
    });
    expect(created.sid).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const fetched = await store.get(created.sid);
    expect(fetched?.userId).toBe('user_1');
    expect(fetched?.scope).toEqual({ orgId: 'org_1', role: 'admin' });
    expect(fetched?.meta).toEqual({ email: 'a@example.com' });

    now += HOUR * 1000;
    await store.touch(created.sid, now + 7 * DAY * 1000);
    const touched = await store.get(created.sid);
    expect(touched?.idleExpiresAt).toBe(now + 7 * DAY * 1000);
    expect(touched?.lastSeenAt).toBe(now);

    await store.revoke(created.sid);
    expect(await store.get(created.sid)).toBeNull();
  });

  it('stores only the hashed session id', async () => {
    const store = d1SessionStore(env.DB, { clock });
    const created = await store.create(NEW_SESSION);

    const row = await env.DB.prepare('SELECT sid_hash FROM auth_sessions').first<{ sid_hash: string }>();
    expect(row?.sid_hash).toBe(await sha256Hex(created.sid));
    expect(row?.sid_hash).not.toBe(created.sid);
  });

  it('revokes every session of one user and leaves others alone', async () => {
    const store = d1SessionStore(env.DB, { clock });
    const a1 = await store.create(NEW_SESSION);
    const a2 = await store.create(NEW_SESSION);
    const b1 = await store.create({ ...NEW_SESSION, userId: 'user_2' });

    await store.revokeAllForUser('user_1');

    expect(await store.get(a1.sid)).toBeNull();
    expect(await store.get(a2.sid)).toBeNull();
    expect(await store.get(b1.sid)).not.toBeNull();
  });

  it('expires at the absolute deadline', async () => {
    const store = d1SessionStore(env.DB, { clock });
    const created = await store.create({ ...NEW_SESSION, idleTtlSec: 30 * DAY, absoluteTtlSec: 30 * DAY });

    now = created.absoluteExpiresAt - 1;
    expect(await store.get(created.sid)).not.toBeNull();
    now = created.absoluteExpiresAt;
    expect(await store.get(created.sid)).toBeNull();
  });

  it('expires after the idle window', async () => {
    const store = d1SessionStore(env.DB, { clock });
    const created = await store.create(NEW_SESSION);

    now = created.idleExpiresAt - 1;
    expect(await store.get(created.sid)).not.toBeNull();
    now = created.idleExpiresAt;
    expect(await store.get(created.sid)).toBeNull();
  });

  it('refuses to push the idle window past the absolute one', async () => {
    const store = d1SessionStore(env.DB, { clock });
    const created = await store.create(NEW_SESSION);

    await store.touch(created.sid, created.absoluteExpiresAt + DAY * 1000);
    expect((await store.get(created.sid))?.idleExpiresAt).toBe(created.absoluteExpiresAt);
  });

  it('will not resurrect an expired session through touch', async () => {
    const store = d1SessionStore(env.DB, { clock });
    const created = await store.create(NEW_SESSION);

    now = created.idleExpiresAt + 1;
    await store.touch(created.sid, now + 7 * DAY * 1000);
    expect(await store.get(created.sid)).toBeNull();
  });

  it('cleans up expired rows', async () => {
    const store = d1SessionStore(env.DB, { clock });
    const created = await store.create(NEW_SESSION);
    await store.create({ ...NEW_SESSION, userId: 'user_2' });

    expect(await store.cleanup()).toBe(0);
    now = created.idleExpiresAt + 1;
    expect(await store.cleanup()).toBe(2);
  });

  it('rejects an unsafe table name', () => {
    expect(() => d1SessionStore(env.DB, { table: 'auth_sessions; DROP TABLE x' })).toThrow(
      /not a valid SQL identifier/,
    );
  });

  it('honours an attached revocation list', async () => {
    const revocation = revocationList(env.DB, { clock });
    const store = d1SessionStore(env.DB, { clock, revocation });
    const created = await store.create(NEW_SESSION);

    await store.revoke(created.sid);
    expect(
      await revocation.isRevoked({
        sidHash: await sha256Hex(created.sid),
        userId: created.userId,
        createdAt: created.createdAt,
      }),
    ).toBe(true);
    expect(await store.get(created.sid)).toBeNull();
  });

  it('revokes all sessions of a user without needing a revocation list', async () => {
    const store = d1SessionStore(env.DB, { clock });
    const created = await store.create(NEW_SESSION);
    await store.revokeAllForUser('user_1');
    expect(await store.get(created.sid)).toBeNull();
  });

  it('canRevokeAllForUser is always true, with or without an attached revocation list', () => {
    expect(d1SessionStore(env.DB, { clock }).canRevokeAllForUser).toBe(true);
    expect(
      d1SessionStore(env.DB, { clock, revocation: revocationList(env.DB, { clock }) }).canRevokeAllForUser,
    ).toBe(true);
  });
});

/**
 * The one thing `revocation` actually does for `d1SessionStore`: when the
 * same `RevocationList` is shared with a different `SessionStore`,
 * revoking through one reaches the other's sessions too. On its own,
 * `d1SessionStore` never needs this — its own `revoke()`/`revokeAllForUser()`
 * are already immediate DELETEs against its own table.
 */
describe('d1SessionStore: revocation shared with another store', () => {
  it("revokeAllForUser() on the D1 store also invalidates a KV store's sessions sharing the same list", async () => {
    const shared = revocationList(env.DB, { clock });
    const d1Store = d1SessionStore(env.DB, { clock, revocation: shared });
    const kvStore = kvSessionStore(env.KV, { clock, revocation: shared });

    const d1Session = await d1Store.create(NEW_SESSION);
    const kvSession = await kvStore.create(NEW_SESSION);

    await d1Store.revokeAllForUser('user_1');

    expect(await d1Store.get(d1Session.sid)).toBeNull();
    expect(await kvStore.get(kvSession.sid)).toBeNull();
  });

  it('revoke() (single session) on the D1 store does not affect the KV store — only revokeAllForUser() cascades', async () => {
    const shared = revocationList(env.DB, { clock });
    const d1Store = d1SessionStore(env.DB, { clock, revocation: shared });
    const kvStore = kvSessionStore(env.KV, { clock, revocation: shared });

    const d1Session = await d1Store.create(NEW_SESSION);
    const kvSession = await kvStore.create(NEW_SESSION);

    await d1Store.revoke(d1Session.sid);

    expect(await d1Store.get(d1Session.sid)).toBeNull();
    expect(await kvStore.get(kvSession.sid)).not.toBeNull();
  });

  it('without a shared revocation list, a D1 store revoking a user does not touch an unrelated KV store', async () => {
    const d1Store = d1SessionStore(env.DB, { clock });
    const kvStore = kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true });

    await d1Store.create(NEW_SESSION);
    const kvSession = await kvStore.create(NEW_SESSION);

    await d1Store.revokeAllForUser('user_1');

    expect(await kvStore.get(kvSession.sid)).not.toBeNull();
  });
});
