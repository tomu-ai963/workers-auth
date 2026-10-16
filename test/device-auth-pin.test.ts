import { env } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { sha256Hex } from '../src/crypto.js';
import { resetStorage } from './helpers/reset.js';
import {
  call,
  client,
  DAY,
  enrolled,
  loginByEmail,
  MIN,
  pinLogin,
  SEC,
  setup,
  T0,
  time,
  type Harness,
} from './helpers/device.js';

beforeEach(async () => {
  time.now = T0;
  await resetStorage();
});

afterEach(() => {
  vi.restoreAllMocks();
});

const EMAIL = 'alice@example.com';
const PIN = '482915';
const WRONG = '739164';
const REQUIRED = { error: 'email_verification_required' };

/** Counts PBKDF2 derivations — i.e. how many PIN verifications actually ran. */
function countPbkdf2() {
  const original = crypto.subtle.deriveBits.bind(crypto.subtle);
  let n = 0;
  vi.spyOn(crypto.subtle, 'deriveBits').mockImplementation(((algorithm: any, key: CryptoKey, length: number) => {
    if (algorithm?.name === 'PBKDF2') n++;
    return original(algorithm, key, length);
  }) as typeof crypto.subtle.deriveBits);
  return () => n;
}

async function guard(accountId: string) {
  return env.DB.prepare('SELECT failed_count, locked_at FROM auth_login_guards WHERE account_id = ?1')
    .bind(accountId)
    .first<{ failed_count: number; locked_at: number | null }>();
}

describe('trusted devices', () => {
  it('stores only sha256 of the device secret', async () => {
    const h = setup({ transport: 'response' });
    const c = client();
    await loginByEmail(h, c, EMAIL);
    const [deviceId, secret] = (c.deviceToken as string).split('.') as [string, string];
    const row = await env.DB.prepare('SELECT * FROM auth_trusted_devices WHERE device_id = ?1').bind(deviceId).first();
    expect(JSON.stringify(row)).not.toContain(secret);
    expect(row?.['secret_hash']).toBe(await sha256Hex(secret));
  });

  it('cookie mode sets an HttpOnly / Secure / SameSite=Lax __Host- device cookie', async () => {
    const h = setup();
    const c = client();
    const res = await loginByEmail(h, c, EMAIL);
    const header = (res.res.headers as unknown as { getSetCookie(): string[] })
      .getSetCookie()
      .find((v) => v.startsWith('__Host-device='));
    expect(header).toBeDefined();
    expect(header).toContain('HttpOnly');
    expect(header).toContain('Secure');
    expect(header).toContain('SameSite=Lax');
    expect(header).toContain('Path=/');
    expect(header).toContain(`Max-Age=${90 * 24 * 60 * 60}`);
    expect(res.body).not.toHaveProperty('deviceToken');
    expect(res.body).not.toHaveProperty('sessionToken');
  });

  it('response mode sets no cookie at all and returns both tokens in the body', async () => {
    const h = setup({ transport: 'response' });
    const res = await loginByEmail(h, client(), EMAIL);
    expect((res.res.headers as unknown as { getSetCookie(): string[] }).getSetCookie()).toEqual([]);
    expect(res.body?.['deviceToken']).toMatch(/^[0-9a-f]{32}\.[A-Za-z0-9_-]{43}$/);
    expect(res.body?.['sessionToken']).toMatch(/^wsb_/);
  });

  it('reuses (and extends) the presented device on a repeat email login', async () => {
    const h = setup();
    const c = client();
    const first = await loginByEmail(h, c, EMAIL);
    time.now += 2 * MIN;
    const second = await loginByEmail(h, c, EMAIL);
    expect(second.body?.['device']?.['deviceId']).toBe(first.body?.['device']?.['deviceId']);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_trusted_devices').first('n')).toBe(1);
  });

  it('never reuses another account’s device token', async () => {
    const h = setup({ transport: 'response' });
    const a = await enrolled(h, EMAIL);
    const b = client({ deviceToken: a.deviceToken });
    const res = await loginByEmail(h, b, 'bob@example.com');
    const aId = (a.deviceToken as string).split('.')[0];
    expect(res.body?.['device']?.['deviceId']).not.toBe(aId);
    // Alice's token still only ever logs in as Alice.
    const pin = await pinLogin(h, client({ deviceToken: a.deviceToken }), PIN);
    expect(pin.body?.['user']?.['id']).toBe(EMAIL);
  });

  it('trustDevice: false registers nothing', async () => {
    const h = setup();
    const res = await loginByEmail(h, client(), EMAIL, { trustDevice: false });
    expect(res.body?.['device']).toBeNull();
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_trusted_devices').first('n')).toBe(0);
  });

  it('rejects a revoked device', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    const devices = await call(h, c, 'GET', '/auth/device/devices');
    const id = devices.body?.['devices'][0].deviceId as string;
    expect(devices.body?.['currentDeviceId']).toBe(id);
    expect((await call(h, c, 'POST', `/auth/device/devices/${id}/revoke`)).body).toEqual({ ok: true, revoked: true });
    const res = await pinLogin(h, c, PIN);
    expect(res.status).toBe(401);
    expect(res.body).toEqual(REQUIRED);
  });

  it('cannot revoke someone else’s device', async () => {
    const h = setup({ transport: 'response' });
    const a = await enrolled(h, EMAIL);
    const b = await enrolled(h, 'bob@example.com');
    const aId = (a.deviceToken as string).split('.')[0];
    expect((await call(h, b, 'POST', `/auth/device/devices/${aId}/revoke`)).body).toEqual({ ok: true, revoked: false });
    expect((await pinLogin(h, a, PIN)).status).toBe(200);
  });

  it('forget drops the device server-side and clears the cookie', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    const token = c.jar['__Host-device'];
    await call(h, c, 'POST', '/auth/device/device/forget');
    expect(c.jar['__Host-device']).toBeUndefined();
    const res = await pinLogin(h, client({ jar: { '__Host-device': token as string } }), PIN);
    expect(res.body).toEqual(REQUIRED);
  });

  it('revoke-all revokes every device of the account', async () => {
    const h = setup({ transport: 'response' });
    const one = await enrolled(h, EMAIL);
    const two = client();
    time.now += 61 * SEC; // resend cooldown
    await loginByEmail(h, two, EMAIL);
    const res = await call(h, two, 'POST', '/auth/device/devices/revoke-all');
    expect(res.body).toEqual({ ok: true, revoked: 2 });
    expect((await pinLogin(h, one, PIN)).body).toEqual(REQUIRED);
  });

  it('extends a device by 90 days from each use, and expires it 90 days after the last', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, EMAIL);
    time.now += 80 * DAY;
    const used = await pinLogin(h, c, PIN);
    expect(used.status).toBe(200);
    expect(used.body?.['device']?.['idleExpiresAt']).toBe(time.now + 90 * DAY);
    time.now += 89 * DAY; // day 169: within 90 of the last use (day 80)
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
    time.now += 90 * DAY + 1; // 90 days + 1 ms of silence
    expect((await pinLogin(h, c, PIN)).body).toEqual(REQUIRED);
  });

  it('expires a device 365 days after registration however often it is used', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, EMAIL);
    for (const day of [80, 160, 240, 320]) {
      time.now = T0 + day * DAY;
      const res = await pinLogin(h, c, PIN);
      expect(res.status).toBe(200);
      expect(res.body?.['device']?.['idleExpiresAt']).toBe(Math.min(time.now + 90 * DAY, T0 + 365 * DAY));
    }
    time.now = T0 + 365 * DAY - 1;
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
    time.now = T0 + 365 * DAY;
    expect((await pinLogin(h, c, PIN)).body).toEqual(REQUIRED);
  });

  it('honours configured device lifetimes', async () => {
    const h = setup({ transport: 'response', device: { idleTtlSec: 7 * 86400, absoluteTtlSec: 10 * 86400 } });
    const c = await enrolled(h, EMAIL);
    time.now += 6 * DAY;
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
    time.now = T0 + 10 * DAY;
    expect((await pinLogin(h, c, PIN)).body).toEqual(REQUIRED);
  });
});

describe('PIN enrolment', () => {
  it.each(['000000', '777777', '123456', '234567', '987654', '012345', '121212', '123123', '112233', '111222', '147258'])(
    'rejects the weak PIN %s',
    async (weak) => {
      const h = setup();
      const c = client();
      await loginByEmail(h, c, EMAIL);
      const res = await call(h, c, 'POST', '/auth/device/pin', { pin: weak });
      expect(res.status).toBe(400);
      expect(res.body).toEqual({ error: 'weak_pin' });
    },
  );

  it.each(['12345', '1234567', 'abcdef', '12 456', 482915])('rejects the malformed PIN %s', async (bad) => {
    const h = setup();
    const c = client();
    await loginByEmail(h, c, EMAIL);
    const res = await call(h, c, 'POST', '/auth/device/pin', { pin: bad });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'invalid_pin_format' });
  });

  it('applies an app-supplied weak-PIN rule on top of the built-in one', async () => {
    const h = setup({ pin: { iterations: 1_000, isWeakPin: (p) => p === PIN } });
    const c = client();
    await loginByEmail(h, c, EMAIL);
    expect((await call(h, c, 'POST', '/auth/device/pin', { pin: PIN })).body).toEqual({ error: 'weak_pin' });
    expect((await call(h, c, 'POST', '/auth/device/pin', { pin: '000000' })).body).toEqual({ error: 'weak_pin' });
  });

  it('salts every credential separately and stores no PIN', async () => {
    const h = setup();
    await enrolled(h, EMAIL);
    await enrolled(h, 'bob@example.com');
    const rows = (await env.DB.prepare("SELECT material FROM auth_credentials WHERE type = 'pin'").all<{ material: string }>()).results;
    expect(rows).toHaveLength(2);
    const [a, b] = rows.map((r) => JSON.parse(r.material));
    expect(a.salt).not.toBe(b.salt);
    expect(a.hash).not.toBe(b.hash);
    expect(rows.map((r) => r.material).join()).not.toContain(PIN);
  });

  it('uses 100,000 PBKDF2 iterations by default', async () => {
    const h = setup({ pin: {} });
    await enrolled(h, EMAIL);
    const row = await env.DB.prepare('SELECT material FROM auth_credentials').first<{ material: string }>();
    expect(JSON.parse(row?.material as string)).toMatchObject({ alg: 'pbkdf2-sha256', iterations: 100_000 });
  });

  it('requires a session', async () => {
    const h = setup();
    const res = await call(h, client(), 'POST', '/auth/device/pin', { pin: PIN });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'unauthenticated' });
  });

  it('requires a recent email verification — a PIN-login session cannot change the PIN', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
    const res = await call(h, c, 'POST', '/auth/device/pin', { pin: '913572' });
    expect(res.status).toBe(401);
    expect(res.body).toEqual(REQUIRED);
  });

  it('requires the email verification to be within 10 minutes', async () => {
    const h = setup();
    const c = client();
    await loginByEmail(h, c, EMAIL);
    time.now += 10 * MIN + 1;
    expect((await call(h, c, 'POST', '/auth/device/pin', { pin: PIN })).body).toEqual(REQUIRED);
  });

  it('a change keeps other devices by default', async () => {
    const h = setup({ transport: 'response' });
    const other = await enrolled(h, EMAIL);
    const here = client();
    time.now += 61 * SEC; // resend cooldown
    await loginByEmail(h, here, EMAIL);
    await call(h, here, 'POST', '/auth/device/pin', { pin: '913572' });
    expect((await pinLogin(h, other, '913572')).status).toBe(200);
    expect((await pinLogin(h, other, PIN)).status).toBe(401);
  });

  it('a change can revoke the other devices, keeping the current one', async () => {
    const h = setup({ transport: 'response', pin: { iterations: 1_000, revokeOtherDevicesOnChange: true } });
    const other = await enrolled(h, EMAIL);
    const here = client();
    time.now += 61 * SEC; // resend cooldown
    await loginByEmail(h, here, EMAIL);
    await call(h, here, 'POST', '/auth/device/pin', { pin: '913572' });
    expect((await pinLogin(h, other, '913572')).body).toEqual(REQUIRED);
    expect((await pinLogin(h, here, '913572')).status).toBe(200);
    expect(h.events).toContainEqual(expect.objectContaining({ type: 'device.revoked', reason: 'pin_changed', count: 1 }));
  });

  it('reports pinSet on email login and via /pin/status', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    expect((await call(h, c, 'GET', '/auth/device/pin/status')).body).toEqual({ pinSet: true });
    time.now += 2 * MIN;
    expect((await loginByEmail(h, c, EMAIL)).body?.['pinSet']).toBe(true);
  });
});

describe('PIN login', () => {
  it('logs in with device + PIN', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    await call(h, c, 'POST', '/auth/device/logout');
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(401);
    const res = await pinLogin(h, c, PIN);
    expect(res.status).toBe(200);
    expect(res.body?.['user']).toMatchObject({ id: EMAIL, claims: { provider: 'device-pin' } });
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(200);
  });

  it('refuses a correct PIN without a device, without counting or hashing', async () => {
    const h = setup();
    await enrolled(h, EMAIL);
    await call(h, client(), 'POST', '/auth/device/logout');
    const pbkdf2 = countPbkdf2();
    const res = await pinLogin(h, client(), PIN);
    expect(res.status).toBe(401);
    expect(res.body).toEqual(REQUIRED);
    expect(pbkdf2()).toBe(0);
    expect((await guard(EMAIL))?.failed_count ?? 0).toBe(0);
  });

  it('refuses a tampered device secret without hashing a PIN', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, EMAIL);
    const [id] = (c.deviceToken as string).split('.');
    const pbkdf2 = countPbkdf2();
    const res = await pinLogin(h, client({ deviceToken: `${id}.${'A'.repeat(43)}` }), PIN);
    expect(res.body).toEqual(REQUIRED);
    expect(pbkdf2()).toBe(0);
  });

  it('answers email_verification_required when no PIN is set', async () => {
    const h = setup();
    const c = client();
    await loginByEmail(h, c, EMAIL);
    expect((await pinLogin(h, c, PIN)).body).toEqual(REQUIRED);
  });

  it('rejects a malformed PIN as a client error without counting it', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    expect((await pinLogin(h, c, '12')).status).toBe(400);
    expect((await guard(EMAIL))?.failed_count ?? 0).toBe(0);
  });

  it('caps PIN logins per IP', async () => {
    const h = setup({ limits: { pinLoginsPerIpPerHour: 2 } });
    const c = await enrolled(h, EMAIL, PIN, { ip: '192.0.2.5' });
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
    expect((await pinLogin(h, c, PIN)).status).toBe(429);
  });
});

describe('failure counting and lockout', () => {
  async function lockOut(h: Harness, c: ReturnType<typeof client>) {
    const r1 = await pinLogin(h, c, WRONG);
    const r2 = await pinLogin(h, c, WRONG);
    const r3 = await pinLogin(h, c, WRONG);
    return [r1, r2, r3];
  }

  it('reports remaining attempts, then locks on the 3rd failure', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    const [r1, r2, r3] = await lockOut(h, c);
    expect(r1?.body).toEqual({ error: 'invalid_pin', attemptsRemaining: 2 });
    expect(r2?.body).toEqual({ error: 'invalid_pin', attemptsRemaining: 1 });
    expect(r3?.body).toEqual(REQUIRED);
    const g = await guard(EMAIL);
    expect(g?.failed_count).toBe(3);
    expect(g?.locked_at).toBe(time.now);
    expect(h.events).toContainEqual(expect.objectContaining({ type: 'pin.locked', userId: EMAIL }));
  });

  it('answers a locked account identically for right and wrong PINs, without hashing', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    await lockOut(h, c);
    const pbkdf2 = countPbkdf2();
    const right = await pinLogin(h, c, PIN);
    const wrong = await pinLogin(h, c, WRONG);
    expect(right.status).toBe(401);
    expect(wrong.status).toBe(401);
    expect(right.body).toEqual(REQUIRED);
    expect(wrong.body).toEqual(right.body);
    expect(pbkdf2()).toBe(0);
  });

  it('counts per account, across devices', async () => {
    const h = setup({ transport: 'response' });
    const one = await enrolled(h, EMAIL);
    const two = client();
    time.now += 61 * SEC; // resend cooldown
    await loginByEmail(h, two, EMAIL);
    await pinLogin(h, one, WRONG);
    await pinLogin(h, two, WRONG);
    expect((await pinLogin(h, one, WRONG)).body).toEqual(REQUIRED);
    expect((await pinLogin(h, two, PIN)).body).toEqual(REQUIRED);
  });

  it('resets the counter on success', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    await pinLogin(h, c, WRONG);
    await pinLogin(h, c, WRONG);
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
    expect((await pinLogin(h, c, WRONG)).body).toEqual({ error: 'invalid_pin', attemptsRemaining: 2 });
  });

  it('only an email code unlocks', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    await lockOut(h, c);
    time.now += 7 * DAY; // time alone does nothing
    expect((await pinLogin(h, c, PIN)).body).toEqual(REQUIRED);
    expect((await loginByEmail(h, c, EMAIL)).status).toBe(200);
    expect(h.events).toContainEqual({ type: 'pin.unlocked', userId: EMAIL });
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
  });

  it('20 concurrent wrong PINs: at most 3 verifications run, and the account locks', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, EMAIL);
    const pbkdf2 = countPbkdf2();
    const results = await Promise.all(Array.from({ length: 20 }, () => pinLogin(h, client({ deviceToken: c.deviceToken }), WRONG)));
    expect(pbkdf2()).toBeLessThanOrEqual(3);
    expect(results.filter((r) => r.body?.['error'] === 'invalid_pin')).toHaveLength(2);
    expect(results.filter((r) => r.body?.['error'] === 'email_verification_required')).toHaveLength(18);
    const g = await guard(EMAIL);
    expect(g?.failed_count).toBe(3);
    expect(g?.locked_at).not.toBeNull();
  });

  it('a correct PIN mixed into a concurrent burst cannot widen the guessing budget', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, EMAIL);
    const pbkdf2 = countPbkdf2();
    const pins = Array.from({ length: 20 }, (_, i) => (i === 10 ? PIN : WRONG));
    const results = await Promise.all(pins.map((p) => pinLogin(h, client({ deviceToken: c.deviceToken }), p)));
    const successes = results.filter((r) => r.status === 200).length;
    expect(successes).toBeLessThanOrEqual(1);
    // Every success refills the budget to 3; nothing else can.
    expect(pbkdf2()).toBeLessThanOrEqual(3 * (successes + 1));
    expect(results.filter((r) => r.body?.['error'] === 'invalid_pin').length).toBeLessThanOrEqual(2 * (successes + 1));
  });

  it('10 concurrent correct PINs on a locked account all get the locked answer', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, EMAIL);
    await lockOut(h, c);
    const results = await Promise.all(Array.from({ length: 10 }, () => pinLogin(h, client({ deviceToken: c.deviceToken }), PIN)));
    expect(results.every((r) => r.status === 401 && r.body?.['error'] === 'email_verification_required')).toBe(true);
  });

  it('honours a configured attempt limit', async () => {
    const h = setup({ pin: { iterations: 1_000, maxAttempts: 5 } });
    const c = await enrolled(h, EMAIL);
    for (let left = 4; left >= 1; left--) {
      expect((await pinLogin(h, c, WRONG)).body).toEqual({ error: 'invalid_pin', attemptsRemaining: left });
    }
    expect((await pinLogin(h, c, WRONG)).body).toEqual(REQUIRED);
  });
});

describe('requireFreshEmailAuth', () => {
  it('admits a session minted by an email code, within the window only', async () => {
    const h = setup();
    const c = client();
    await loginByEmail(h, c, EMAIL);
    expect((await call(h, c, 'POST', '/api/sensitive')).status).toBe(200);
    time.now += 10 * MIN + 1;
    expect((await call(h, c, 'POST', '/api/sensitive')).body).toEqual(REQUIRED);
  });

  it('refuses a PIN-login session', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    await pinLogin(h, c, PIN);
    expect((await call(h, c, 'POST', '/api/sensitive')).body).toEqual(REQUIRED);
  });
});
