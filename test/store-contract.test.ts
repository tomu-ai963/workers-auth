/**
 * Store contract: one set of tests, run unchanged against D1 (project "d1")
 * and against Postgres through the Neon HTTP driver (project "pg"). The
 * backend comes from TEST_BACKEND; see test/helpers/backend.ts.
 *
 * Every method of SessionStore and DeviceAuthStore is pinned here, including
 * the conditional statements' behaviour at their limits and under concurrent
 * calls. The row-lock interleavings that need two held-open connections are in
 * test/pg-node/locks.test.ts.
 */
import { beforeEach, describe, expect, it } from 'vitest';

import type { CredentialRecord, DeviceAuthStore, DeviceAuthStoreCleanup, DeviceRecord } from '../src/device-auth/store.js';
import type { SessionStore } from '../src/types.js';
import { BACKEND, db, makeDeviceStore, makeSessionStore } from './helpers/backend.js';
import { HEAVY_TIMEOUT } from './helpers/device.js';
import { resetStorage } from './helpers/reset.js';

const NOW = 1_700_000_000_000;
const DAY = 86_400_000;

beforeEach(async () => {
  await resetStorage();
});

function device(overrides: Partial<DeviceRecord> = {}): DeviceRecord {
  return {
    deviceId: 'a'.repeat(32),
    accountId: 'acct',
    email: 'acct@example.com',
    secretHash: 'f'.repeat(64),
    label: 'Phone',
    createdAt: NOW,
    lastUsedAt: NOW,
    idleExpiresAt: NOW + 10 * DAY,
    absoluteExpiresAt: NOW + 30 * DAY,
    revokedAt: null,
    ...overrides,
  };
}

function credential(id: string, overrides: Partial<CredentialRecord> = {}): CredentialRecord {
  return {
    credentialId: id,
    accountId: 'acct',
    type: 'pin',
    deviceId: null,
    material: { alg: 'pbkdf2-sha256', iterations: 1000, salt: 's', hash: id },
    createdAt: NOW,
    updatedAt: NOW,
    lastUsedAt: null,
    ...overrides,
  };
}

function storeContract(name: string, make: () => DeviceAuthStore & DeviceAuthStoreCleanup) {
  describe(`DeviceAuthStore contract (${name})`, { timeout: HEAVY_TIMEOUT }, () => {
    it('declares atomic: true', () => {
      expect(make().atomic).toBe(true);
    });

    describe('rate limits', () => {
      it('hitRateLimit counts within a window and restarts after it', async () => {
        const s = make();
        expect(await s.hitRateLimit('h', 1000, NOW)).toEqual({ count: 1, windowStart: NOW });
        expect(await s.hitRateLimit('h', 1000, NOW + 999)).toEqual({ count: 2, windowStart: NOW });
        expect(await s.hitRateLimit('h', 1000, NOW + 1000)).toEqual({ count: 1, windowStart: NOW + 1000 });
      });

      it('readRateLimit reads without moving, and reads 0 for a lapsed window', async () => {
        const s = make();
        expect(await s.readRateLimit('r', 1000, NOW)).toEqual({ count: 0, windowStart: NOW });
        await s.hitRateLimit('r', 1000, NOW);
        await s.hitRateLimit('r', 1000, NOW);
        expect(await s.readRateLimit('r', 1000, NOW + 10)).toEqual({ count: 2, windowStart: NOW });
        expect(await s.readRateLimit('r', 1000, NOW + 10)).toEqual({ count: 2, windowStart: NOW });
        expect(await s.readRateLimit('r', 1000, NOW + 1000)).toEqual({ count: 0, windowStart: NOW + 1000 });
      });

      it('reserveRateLimit stops at max without moving the count; a refund frees one slot; a new window restarts', async () => {
        const s = make();
        expect(await s.reserveRateLimit('v', 1000, NOW, 2)).toEqual({ count: 1, windowStart: NOW });
        expect(await s.reserveRateLimit('v', 1000, NOW, 2)).toEqual({ count: 2, windowStart: NOW });
        expect(await s.reserveRateLimit('v', 1000, NOW, 2)).toBeNull();
        expect(await s.readRateLimit('v', 1000, NOW)).toMatchObject({ count: 2 });
        await s.refundRateLimit('v', NOW);
        expect(await s.reserveRateLimit('v', 1000, NOW, 2)).toEqual({ count: 2, windowStart: NOW });
        expect(await s.reserveRateLimit('v', 1000, NOW + 1000, 2)).toEqual({ count: 1, windowStart: NOW + 1000 });
      });

      it('refundRateLimit never goes below zero and never touches another window', async () => {
        const s = make();
        await s.hitRateLimit('f', 1000, NOW);
        await s.refundRateLimit('f', NOW);
        await s.refundRateLimit('f', NOW);
        expect(await s.readRateLimit('f', 1000, NOW)).toMatchObject({ count: 0 });
        await s.hitRateLimit('f', 1000, NOW + 1000);
        await s.refundRateLimit('f', NOW);
        expect(await s.readRateLimit('f', 1000, NOW + 1000)).toEqual({ count: 1, windowStart: NOW + 1000 });
      });

      it('25 concurrent reserveRateLimit calls for 10 slots get exactly 10', async () => {
        const s = make();
        const r = await Promise.all(Array.from({ length: 25 }, () => s.reserveRateLimit('c', DAY, NOW, 10)));
        expect(r.filter((x) => x !== null).map((x) => x!.count).sort((a, b) => a - b)).toEqual(
          Array.from({ length: 10 }, (_, i) => i + 1),
        );
        expect(r.filter((x) => x === null)).toHaveLength(15);
        expect(await s.readRateLimit('c', DAY, NOW)).toMatchObject({ count: 10 });
      });

      it('25 concurrent hitRateLimit calls count exactly 1..25', async () => {
        const s = make();
        const r = await Promise.all(Array.from({ length: 25 }, () => s.hitRateLimit('hc', DAY, NOW)));
        expect(r.map((x) => x.count).sort((a, b) => a - b)).toEqual(Array.from({ length: 25 }, (_, i) => i + 1));
      });
    });

    describe('circuit breaker', () => {
      it('counts attempts and failures in one row and one window', async () => {
        const s = make();
        expect(await s.readCircuitBreaker('cb', 1000, NOW)).toEqual({ attempts: 0, failures: 0, windowStart: NOW });
        expect(await s.hitCircuitBreaker('cb', 1000, NOW, true)).toEqual({ attempts: 1, failures: 1, windowStart: NOW });
        expect(await s.hitCircuitBreaker('cb', 1000, NOW + 1, false)).toEqual({ attempts: 2, failures: 1, windowStart: NOW });
        expect(await s.readCircuitBreaker('cb', 1000, NOW + 2)).toEqual({ attempts: 2, failures: 1, windowStart: NOW });
        expect(await s.hitCircuitBreaker('cb', 1000, NOW + 1000, false)).toEqual({
          attempts: 1,
          failures: 0,
          windowStart: NOW + 1000,
        });
      });

      it('20 concurrent hits are all counted', async () => {
        const s = make();
        await Promise.all(Array.from({ length: 20 }, (_, i) => s.hitCircuitBreaker('cbc', DAY, NOW, i % 2 === 0)));
        expect(await s.readCircuitBreaker('cbc', DAY, NOW)).toEqual({ attempts: 20, failures: 10, windowStart: NOW });
      });
    });

    describe('email codes', () => {
      const code = (hash: string, at: number, resetAt = at + 600_000) => ({
        email: 'e@example.com',
        codeHash: hash,
        keyId: 'k1',
        expiresAt: at + 600_000,
        createdAt: at,
        attemptsResetAt: resetAt,
      });

      it('reserves attempts up to max, then refuses; an expired code is refused', async () => {
        const s = make();
        expect(await s.reserveEmailCodeAttempt('e@example.com', NOW, 5)).toBeNull();
        await s.putEmailCode(code('h1', NOW));
        for (let i = 1; i <= 5; i++) {
          expect(await s.reserveEmailCodeAttempt('e@example.com', NOW, 5)).toEqual({ codeHash: 'h1', keyId: 'k1', attempts: i });
        }
        expect(await s.reserveEmailCodeAttempt('e@example.com', NOW, 5)).toBeNull();
        await s.putEmailCode(code('h2', NOW + DAY));
        expect(await s.reserveEmailCodeAttempt('e@example.com', NOW + DAY + 600_000, 5)).toBeNull();
      });

      it('a resend before attemptsResetAt keeps attempts and the deadline; after it, both reset', async () => {
        const s = make();
        await s.putEmailCode(code('h1', NOW));
        await s.reserveEmailCodeAttempt('e@example.com', NOW, 5);
        await s.reserveEmailCodeAttempt('e@example.com', NOW, 5);
        await s.putEmailCode(code('h2', NOW + 60_000));
        expect(await db.prepare('SELECT attempts, attempts_reset_at, code_hash FROM auth_email_codes').first()).toEqual({
          attempts: 2,
          attempts_reset_at: NOW + 600_000,
          code_hash: 'h2',
        });
        await s.putEmailCode(code('h3', NOW + 600_000));
        expect(await db.prepare('SELECT attempts, attempts_reset_at FROM auth_email_codes').first()).toEqual({
          attempts: 0,
          attempts_reset_at: NOW + 1_200_000,
        });
      });

      it('20 concurrent reservations on a 5-attempt code: exactly 5 succeed', async () => {
        const s = make();
        await s.putEmailCode(code('h1', NOW));
        const r = await Promise.all(Array.from({ length: 20 }, () => s.reserveEmailCodeAttempt('e@example.com', NOW, 5)));
        expect(r.filter((x) => x !== null).map((x) => x!.attempts).sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5]);
      });

      it('consumeEmailCode deletes only the matched code, exactly once under concurrency', async () => {
        const s = make();
        await s.putEmailCode(code('h1', NOW));
        expect(await s.consumeEmailCode('e@example.com', 'other')).toBe(false);
        const r = await Promise.all(Array.from({ length: 10 }, () => s.consumeEmailCode('e@example.com', 'h1')));
        expect(r.filter(Boolean)).toHaveLength(1);
        expect(await s.reserveEmailCodeAttempt('e@example.com', NOW, 5)).toBeNull();
      });
    });

    describe('devices', () => {
      it('create / find / list hide the secret hash, email and revocation', async () => {
        const s = make();
        await s.createDevice(device());
        await s.createDevice(device({ deviceId: 'b'.repeat(32), createdAt: NOW + 1 }));
        expect(await s.findDevice('a'.repeat(32))).toEqual(device());
        expect(await s.findDevice('c'.repeat(32))).toBeNull();
        const list = await s.listDevices('acct', NOW);
        expect(list.map((d) => d.deviceId)).toEqual(['a'.repeat(32), 'b'.repeat(32)]);
        expect(Object.keys(list[0]!).sort()).toEqual(
          ['absoluteExpiresAt', 'accountId', 'createdAt', 'deviceId', 'idleExpiresAt', 'label', 'lastUsedAt'].sort(),
        );
      });

      it('touchDevice slides the idle window but never past the absolute expiry, and refuses a dead device', async () => {
        const s = make();
        await s.createDevice(device());
        expect(await s.touchDevice('a'.repeat(32), NOW + DAY, NOW + 11 * DAY)).toBe(NOW + 11 * DAY);
        expect(await s.touchDevice('a'.repeat(32), NOW + 2 * DAY, NOW + 99 * DAY)).toBe(NOW + 30 * DAY);
        expect(await s.findDevice('a'.repeat(32))).toMatchObject({ lastUsedAt: NOW + 2 * DAY });
        expect(await s.touchDevice('a'.repeat(32), NOW + 30 * DAY, NOW + 40 * DAY)).toBeNull();
        expect(await s.touchDevice('missing'.padEnd(32, '0'), NOW, NOW + DAY)).toBeNull();
      });

      it('revokeDevice only revokes the owner’s live device; revokeAllDevices can spare one', async () => {
        const s = make();
        await s.createDevice(device());
        await s.createDevice(device({ deviceId: 'b'.repeat(32) }));
        await s.createDevice(device({ deviceId: 'c'.repeat(32) }));
        expect(await s.revokeDevice('someone-else', 'a'.repeat(32), NOW)).toBe(false);
        expect(await s.revokeDevice('acct', 'a'.repeat(32), NOW)).toBe(true);
        expect(await s.revokeDevice('acct', 'a'.repeat(32), NOW)).toBe(false);
        expect(await s.touchDevice('a'.repeat(32), NOW, NOW + DAY)).toBeNull();
        expect(await s.revokeAllDevices('acct', NOW, 'b'.repeat(32))).toBe(1);
        expect((await s.listDevices('acct', NOW)).map((d) => d.deviceId)).toEqual(['b'.repeat(32)]);
        expect(await s.revokeAllDevices('acct', NOW)).toBe(1);
        expect(await s.revokeAllDevices('acct', NOW, null)).toBe(0);
      });
    });

    describe('credentials', () => {
      it('replaceCredential keeps one live PIN and reports whether it replaced one', async () => {
        const s = make();
        expect(await s.getActiveCredential('acct', 'pin')).toBeNull();
        expect(await s.replaceCredential(credential('p1'))).toBe(false);
        expect(await s.replaceCredential(credential('p2', { createdAt: NOW + 1, updatedAt: NOW + 1 }))).toBe(true);
        expect(await s.getActiveCredential('acct', 'pin')).toEqual(credential('p2', { createdAt: NOW + 1, updatedAt: NOW + 1 }));
        expect(await db.prepare("SELECT COUNT(*) AS n FROM auth_credentials WHERE revoked_at IS NULL").first('n')).toBe(1);
      });

      it('the one-live-PIN rule is enforced by the schema, and passkeys are not limited by it', async () => {
        const s = make();
        await s.replaceCredential(credential('p1'));
        await expect(
          db
            .prepare(
              `INSERT INTO auth_credentials (credential_id, account_id, type, device_id, material, created_at, updated_at)
               VALUES ('dup', 'acct', 'pin', NULL, '{}', 1, 1)`,
            )
            .run(),
        ).rejects.toThrow();
        await s.replaceCredential(credential('k1', { type: 'passkey', deviceId: 'd1' }));
        await s.replaceCredential(credential('k2', { type: 'passkey', deviceId: 'd2' }));
        expect(await s.getActiveCredential('acct', 'pin')).toMatchObject({ credentialId: 'p1' });
      });

      it('markCredentialUsed sets last use, and swaps the material only when given one', async () => {
        const s = make();
        await s.replaceCredential(credential('p1'));
        await s.markCredentialUsed('p1', NOW + 5);
        expect(await s.getActiveCredential('acct', 'pin')).toMatchObject({ lastUsedAt: NOW + 5, updatedAt: NOW });
        await s.markCredentialUsed('p1', NOW + 6, { alg: 'pbkdf2-sha256', iterations: 2000 });
        expect(await s.getActiveCredential('acct', 'pin')).toMatchObject({
          lastUsedAt: NOW + 6,
          updatedAt: NOW + 6,
          material: { alg: 'pbkdf2-sha256', iterations: 2000 },
        });
      });
    });

    describe('login guard', () => {
      it('reserves up to max, refuses after, locks, and resets returning the state before', async () => {
        const s = make();
        expect(await s.readLoginGuard('acct')).toBeNull();
        expect(await s.resetLoginGuard('acct', NOW)).toBeNull();
        expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBe(1);
        expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBe(2);
        await s.lockAccount('acct', 3, NOW);
        expect(await s.readLoginGuard('acct')).toEqual({ failedCount: 2, lockedAt: null });
        expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBe(3);
        expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBeNull();
        await s.lockAccount('acct', 3, NOW + 1);
        await s.lockAccount('acct', 3, NOW + 2);
        expect(await s.readLoginGuard('acct')).toEqual({ failedCount: 3, lockedAt: NOW + 1 });
        expect(await s.resetLoginGuard('acct', NOW + 3)).toEqual({ failedCount: 3, lockedAt: NOW + 1 });
        expect(await s.readLoginGuard('acct')).toEqual({ failedCount: 0, lockedAt: null });
      });

      it('a locked account refuses even below max', async () => {
        const s = make();
        await s.reserveLoginAttempt('acct', 3, NOW);
        await db.prepare('UPDATE auth_login_guards SET locked_at = ?1').bind(NOW).run();
        expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBeNull();
      });

      it('20 concurrent reservations with max 3 get exactly 3', async () => {
        const s = make();
        const r = await Promise.all(Array.from({ length: 20 }, () => s.reserveLoginAttempt('acct', 3, NOW)));
        expect(r.filter((x) => x !== null).sort()).toEqual([1, 2, 3]);
      });
    });

    it('cleanup removes expired codes and devices, revoked rows and stale windows', async () => {
      const s = make();
      await s.putEmailCode({ email: 'x@example.com', codeHash: 'h', keyId: 'k', expiresAt: NOW, createdAt: NOW - 1, attemptsResetAt: NOW });
      await s.createDevice(device({ deviceId: '1'.repeat(32), absoluteExpiresAt: NOW, idleExpiresAt: NOW }));
      await s.createDevice(device({ deviceId: '2'.repeat(32) }));
      await s.revokeDevice('acct', '2'.repeat(32), NOW);
      await s.createDevice(device({ deviceId: '3'.repeat(32) }));
      await s.replaceCredential(credential('p1'));
      await s.replaceCredential(credential('p2'));
      await s.hitRateLimit('old', 1000, NOW - 2 * DAY);
      await s.hitRateLimit('new', 1000, NOW);
      expect(await s.cleanup(NOW)).toBe(5);
      expect(await s.findDevice('3'.repeat(32))).not.toBeNull();
      expect(await s.getActiveCredential('acct', 'pin')).toMatchObject({ credentialId: 'p2' });
      expect(await s.readRateLimit('new', 1000, NOW)).toMatchObject({ count: 1 });
    });
  });
}

type CleanableSessionStore = SessionStore & { cleanup(now?: number): Promise<number> };

function sessionContract(name: string, make: (clock: () => number) => CleanableSessionStore) {
  describe(`SessionStore contract (${name})`, { timeout: HEAVY_TIMEOUT }, () => {
    const input = { userId: 'u1', subjectType: 'user' as const, idleTtlSec: 60, absoluteTtlSec: 3600 };

    it('creates, reads back (scope and meta included) and stores only the hash', async () => {
      const s = make(() => NOW);
      const created = await s.create({ ...input, scope: { orgId: 'o', role: 'r' }, meta: { a: 1 } });
      expect(await s.get(created.sid)).toEqual(created);
      expect(JSON.stringify(await db.prepare('SELECT * FROM auth_sessions').all())).not.toContain(created.sid);
      expect(s.canRevokeAllForUser).toBe(true);
    });

    it('expires on idle and on absolute time, deleting the row', async () => {
      let now = NOW;
      const s = make(() => now);
      const a = await s.create(input);
      now = NOW + 60_000;
      expect(await s.get(a.sid)).toBeNull();
      expect(await db.prepare('SELECT COUNT(*) AS n FROM auth_sessions').first('n')).toBe(0);
    });

    it('touch slides the idle expiry, never past the absolute one, and ignores a dead session', async () => {
      let now = NOW;
      const s = make(() => now);
      const a = await s.create(input);
      now = NOW + 30_000;
      await s.touch(a.sid, NOW + 90_000);
      expect(await s.get(a.sid)).toMatchObject({ idleExpiresAt: NOW + 90_000, lastSeenAt: NOW + 30_000 });
      await s.touch(a.sid, NOW + 99 * 3600_000);
      expect(await s.get(a.sid)).toMatchObject({ idleExpiresAt: NOW + 3600_000 });
    });

    it('revoke and revokeAllForUser', async () => {
      const s = make(() => NOW);
      const a = await s.create(input);
      const b = await s.create(input);
      const c = await s.create({ ...input, userId: 'u2' });
      await s.revoke(a.sid);
      expect(await s.get(a.sid)).toBeNull();
      await s.revokeAllForUser('u1');
      expect(await s.get(b.sid)).toBeNull();
      expect(await s.get(c.sid)).not.toBeNull();
    });

    it('cleanup removes rows past either expiry', async () => {
      const s = make(() => NOW);
      await s.create(input);
      await s.create({ ...input, idleTtlSec: 7200, absoluteTtlSec: 7200 });
      expect(await s.cleanup(NOW + 60_000)).toBe(1);
    });
  });
}

storeContract(BACKEND, () => makeDeviceStore({ clock: () => NOW }));
sessionContract(BACKEND, (clock) => makeSessionStore({ clock }) as CleanableSessionStore);
