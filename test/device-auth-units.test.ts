import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { randomToken } from '../src/crypto.js';
import { isWeakPin, pinCredential } from '../src/device-auth/credentials.js';
import { d1DeviceAuthStore } from '../src/device-auth/index.js';
import { buildKeyRing } from '../src/device-auth/keys.js';
import { createAuth } from '../src/index.js';
import {
  bearerSessionToken,
  readBearerSessionId,
  revokeBearerSession,
  sessionBearer,
} from '../src/providers/session-bearer.js';
import { d1SessionStore } from '../src/store/d1.js';
import { extractEmailCodeFromEmail } from '../src/testing.js';
import { resetStorage } from './helpers/reset.js';

beforeEach(async () => {
  await resetStorage();
});

const NOW = 1_700_000_000_000;

describe('isWeakPin', () => {
  it.each(['000000', '999999', '123456', '456789', '012345', '987654', '543210', '121212', '909090', '123123', '456456', '112233', '998877', '111222', '147258', '123321'])(
    'flags %s',
    (pin) => expect(isWeakPin(pin)).toBe(true),
  );

  it.each(['482915', '739164', '205817', '613094', '880241'])('accepts %s', (pin) => expect(isWeakPin(pin)).toBe(false));
});

describe('pinCredential', () => {
  it('round-trips and rejects the wrong PIN', async () => {
    const keys = await buildKeyRing(randomToken());
    const kind = pinCredential({ iterations: 1_000 });
    const material = await kind.enroll('482915', { keys });
    expect((await kind.verify('482915', material, { keys })).ok).toBe(true);
    expect((await kind.verify('482916', material, { keys })).ok).toBe(false);
    expect(kind.requiresTrustedDevice).toBe(true);
  });

  it('asks for a re-hash when the configured cost changed', async () => {
    const keys = await buildKeyRing(randomToken());
    const material = await pinCredential({ iterations: 1_000 }).enroll('482915', { keys });
    const result = await pinCredential({ iterations: 2_000 }).verify('482915', material, { keys });
    expect(result.ok).toBe(true);
    expect(result.upgraded).toMatchObject({ iterations: 2_000 });
  });

  it('fails closed on malformed material', async () => {
    const keys = await buildKeyRing(randomToken());
    expect((await pinCredential({ iterations: 1_000 }).verify('482915', { alg: 'md5' }, { keys })).ok).toBe(false);
  });
});

describe('key ring', () => {
  it('derives a stable, secret-independent-looking keyId and keeps previous keys verify-only', async () => {
    const a = randomToken();
    const b = randomToken();
    const ringA = await buildKeyRing(a);
    const ringA2 = await buildKeyRing(a);
    expect(ringA.current.keyId).toBe(ringA2.current.keyId);
    expect(ringA.current.keyId).toMatch(/^[0-9a-f]{16}$/);
    expect(a).not.toContain(ringA.current.keyId);

    const rotated = await buildKeyRing(b, [a, b]);
    expect(rotated.byId.size).toBe(2);
    expect(rotated.current.keyId).not.toBe(ringA.current.keyId);
    expect(rotated.byId.has(ringA.current.keyId)).toBe(true);
  });
});

describe('d1DeviceAuthStore', () => {
  const store = () => d1DeviceAuthStore(env.DB, { clock: () => NOW });

  it('reserveLoginAttempt refuses past the limit and while locked', async () => {
    const s = store();
    expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBe(1);
    expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBe(2);
    expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBe(3);
    expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBeNull();
    await s.lockAccount('acct', 3, NOW);
    expect(await s.readLoginGuard('acct')).toEqual({ failedCount: 3, lockedAt: NOW });
    // Raising the limit does not quietly unlock a locked account.
    expect(await s.reserveLoginAttempt('acct', 10, NOW)).toBeNull();
    expect(await s.resetLoginGuard('acct', NOW)).toEqual({ failedCount: 3, lockedAt: NOW });
    expect(await s.reserveLoginAttempt('acct', 3, NOW)).toBe(1);
  });

  it('reserveLoginAttempt hands out exactly `max` reservations under concurrency', async () => {
    const s = store();
    const results = await Promise.all(Array.from({ length: 30 }, () => s.reserveLoginAttempt('acct', 3, NOW)));
    expect(results.filter((r) => r !== null).sort()).toEqual([1, 2, 3]);
  });

  it('hitRateLimit counts within a window and restarts after it', async () => {
    const s = store();
    expect(await s.hitRateLimit('b', 1000, NOW)).toEqual({ count: 1, windowStart: NOW });
    expect(await s.hitRateLimit('b', 1000, NOW + 999)).toEqual({ count: 2, windowStart: NOW });
    expect(await s.hitRateLimit('b', 1000, NOW + 1000)).toEqual({ count: 1, windowStart: NOW + 1000 });
  });

  it('hitRateLimit is exact under concurrency', async () => {
    const s = store();
    const results = await Promise.all(Array.from({ length: 25 }, () => s.hitRateLimit('c', 60_000, NOW)));
    expect(results.map((r) => r.count).sort((x, y) => x - y)).toEqual(Array.from({ length: 25 }, (_, i) => i + 1));
  });

  it('touchDevice never extends past the absolute expiry and refuses an expired device', async () => {
    const s = store();
    await s.createDevice({
      deviceId: 'd'.repeat(32),
      accountId: 'acct',
      email: 'a@example.com',
      secretHash: '0'.repeat(64),
      label: null,
      createdAt: NOW,
      lastUsedAt: NOW,
      idleExpiresAt: NOW + 100,
      absoluteExpiresAt: NOW + 150,
      revokedAt: null,
    });
    expect(await s.touchDevice('d'.repeat(32), NOW + 50, NOW + 500)).toBe(NOW + 150);
    expect(await s.touchDevice('d'.repeat(32), NOW + 150, NOW + 600)).toBeNull();
  });

  it('keeps one live PIN per account, and accepts passkey rows without a schema change', async () => {
    const s = store();
    const cred = (id: string, type: 'pin' | 'passkey') => ({
      credentialId: id,
      accountId: 'acct',
      type,
      deviceId: type === 'passkey' ? 'd'.repeat(32) : null,
      material: { v: id },
      createdAt: NOW,
      updatedAt: NOW,
      lastUsedAt: null,
    });
    expect(await s.replaceCredential(cred('p1', 'pin'))).toBe(false);
    expect(await s.replaceCredential(cred('p2', 'pin'))).toBe(true);
    expect((await s.getActiveCredential('acct', 'pin'))?.credentialId).toBe('p2');
    expect(await env.DB.prepare("SELECT COUNT(*) AS n FROM auth_credentials WHERE revoked_at IS NULL AND type = 'pin'").first('n')).toBe(1);

    await s.replaceCredential(cred('k1', 'passkey'));
    expect((await s.getActiveCredential('acct', 'passkey'))?.material).toEqual({ v: 'k1' });
    expect((await s.getActiveCredential('acct', 'pin'))?.credentialId).toBe('p2');
  });

  it('cleanup removes expired codes/devices, revoked rows and stale rate-limit windows', async () => {
    const s = store();
    await s.putEmailCode({ email: 'a@example.com', codeHash: 'h', keyId: 'k', expiresAt: NOW - 1, createdAt: NOW - 10, attemptsResetAt: NOW - 1 });
    await s.putEmailCode({ email: 'b@example.com', codeHash: 'h', keyId: 'k', expiresAt: NOW + 1000, createdAt: NOW, attemptsResetAt: NOW + 1000 });
    await s.hitRateLimit('old', 1000, NOW - 2 * 86_400_000);
    await s.hitRateLimit('new', 1000, NOW);
    expect(await s.cleanup(NOW)).toBe(2);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_email_codes').first('n')).toBe(1);
    expect(await env.DB.prepare('SELECT bucket FROM auth_rate_limits').first('bucket')).toBe('new');
  });
});

describe('sessionBearer', () => {
  it('reads only well-formed wsb_ tokens', () => {
    const req = (v: string) => new Request('https://x.example', { headers: { authorization: v } });
    const sid = randomToken();
    expect(readBearerSessionId(req(`Bearer ${bearerSessionToken(sid)}`))).toBe(sid);
    expect(readBearerSessionId(req(`bearer ${bearerSessionToken(sid)}`))).toBe(sid);
    expect(readBearerSessionId(req(`Bearer ${sid}`))).toBeNull();
    expect(readBearerSessionId(req(`Basic ${bearerSessionToken(sid)}`))).toBeNull();
    expect(readBearerSessionId(new Request('https://x.example'))).toBeNull();
  });

  it('verifies a bearer session, refuses a cookie session, and revokes', async () => {
    const store = d1SessionStore(env.DB);
    const auth = createAuth({ providers: [], store });
    const fakeContext = { req: { raw: new Request('https://x.example') }, header() {} } as never;
    const bearer = await auth.createSession(fakeContext, { id: 'u', subjectType: 'user', rateLimitId: 'u', claims: {} }, {
      transport: 'bearer',
      ttl: { idleTtlSec: 60, absoluteTtlSec: 60 },
    });
    const cookie = await store.create({ userId: 'u', subjectType: 'user', idleTtlSec: 60, absoluteTtlSec: 60 });

    const provider = sessionBearer({ store });
    const req = (sid: string) =>
      new Request('https://x.example', { headers: { authorization: `Bearer ${bearerSessionToken(sid)}` } });
    expect(await provider.verify(req(bearer.sid), {})).toMatchObject({ id: 'u', rateLimitId: 'u' });
    expect(await provider.verify(req(cookie.sid), {})).toBeNull();

    expect(await revokeBearerSession(store, req(bearer.sid))).toBe(true);
    expect(await provider.verify(req(bearer.sid), {})).toBeNull();
    expect(await revokeBearerSession(store, req(cookie.sid))).toBe(false);
    expect(await store.get(cookie.sid)).not.toBeNull();
  });
});

describe('extractEmailCodeFromEmail', () => {
  it('finds the code in plain text and HTML, ignoring markup and colours', () => {
    expect(extractEmailCodeFromEmail('Your code is 048213. It expires in 10 minutes.')).toBe('048213');
    expect(
      extractEmailCodeFromEmail(
        '<style>.a{color:#123456}</style><div style="color:#654321" data-x="999999"><b>048213</b></div>',
      ),
    ).toBe('048213');
  });

  it('ignores digits embedded in longer numbers', () => {
    expect(extractEmailCodeFromEmail('Order 12345678 — code 048213')).toBe('048213');
  });

  it('throws when ambiguous or absent, and honours a pattern', () => {
    expect(() => extractEmailCodeFromEmail('code 048213, ref 771234')).toThrow(/2 different/);
    expect(() => extractEmailCodeFromEmail('no code here')).toThrow(/no 6-digit/);
    expect(extractEmailCodeFromEmail('code 048213, ref 771234', { pattern: /code (\d{6})/g })).toBe('048213');
    expect(extractEmailCodeFromEmail('048213 again 048213')).toBe('048213');
  });
});
