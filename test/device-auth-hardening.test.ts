/**
 * Fixes from the 2026-10 security review of feat/device-auth (P0-1, P0-2, P1,
 * P2). The P0 reproductions themselves live in device-auth-p0-regression.test.ts.
 */
import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { randomToken } from '../src/crypto.js';
import { isWeakPin } from '../src/device-auth/credentials.js';
import {
  d1DeviceAuthStore,
  deviceAuth,
  deviceBoundSessionStore,
  estimateEntropyBits,
  generateEmailCode,
  ipRateLimitKey,
} from '../src/device-auth/index.js';
import { createAuth } from '../src/index.js';
import { sessionBearer } from '../src/providers/session-bearer.js';
import { d1SessionStore } from '../src/store/d1.js';
import { kvSessionStore } from '../src/store/kv.js';
import { extractEmailCodeFromEmail } from '../src/testing.js';
import { resetStorage } from './helpers/reset.js';
import {
  call,
  client,
  enrolled,
  HOUR,
  loginByEmail,
  MIN,
  ORIGIN,
  pinLogin,
  SEC,
  setup,
  T0,
  time,
} from './helpers/device.js';

beforeEach(async () => {
  time.now = T0;
  await resetStorage();
});

const PIN = '482915';
const REQUIRED = { error: 'email_verification_required' };

async function failVerify(h: ReturnType<typeof setup>, email: string, n: number) {
  for (let i = 0; i < n; i++) {
    await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: '000000' });
  }
}

// ---------------------------------------------------------------------------
// P0-1
// ---------------------------------------------------------------------------

describe('P0-1 (a): failures per address across codes', () => {
  it('blocks /email/start too once the cap is reached, and lifts after the window', async () => {
    const h = setup();
    const email = 'cap@example.com';
    await failVerify(h, email, 10);
    const start = await call(h, client(), 'POST', '/auth/device/email/start', { email });
    expect(start.status).toBe(429);
    expect(start.body).toMatchObject({ error: 'rate_limited' });
    expect(Number(start.res.headers.get('retry-after'))).toBeGreaterThan(23 * 3600);
    expect(h.sent).toHaveLength(0);
    expect(h.events).toContainEqual({ type: 'rate_limited', scope: 'email_failures' });

    time.now += 24 * HOUR;
    expect((await loginByEmail(h, client(), email)).status).toBe(200);
  });

  it('a success gives its own reservation back, and does not wipe earlier failures', async () => {
    const h = setup();
    const email = 'refund@example.com';
    await failVerify(h, email, 9);
    // Successes do not count: two in a row after 9 failures both pass.
    expect((await loginByEmail(h, client(), email)).status).toBe(200);
    time.now += 61 * SEC;
    expect((await loginByEmail(h, client(), email)).status).toBe(200);
    // ...but the 9 failures are still there: one more reaches the cap.
    await failVerify(h, email, 1);
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email })).status).toBe(429);
  });

  it('honours maxFailuresPerEmail / failureWindowSec', async () => {
    const h = setup({ emailCode: { maxFailuresPerEmail: 3, failureWindowSec: 3600 } });
    const email = 'small@example.com';
    await failVerify(h, email, 3);
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email })).status).toBe(429);
    time.now += HOUR;
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email })).status).toBe(200);
  });

  it('does not affect PIN login on a trusted device', async () => {
    const h = setup();
    const email = 'pin-ok@example.com';
    const c = await enrolled(h, email);
    await failVerify(h, email, 12);
    expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: '123456' })).status).toBe(429);
    expect((await pinLogin(h, c, PIN)).status).toBe(200);
  });

  it('counts concurrent failures exactly: 15 parallel guesses, at most 10 get checked', async () => {
    const h = setup();
    const email = 'burst@example.com';
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    const results = await Promise.all(
      Array.from({ length: 15 }, () => call(h, client(), 'POST', '/auth/device/email/verify', { email, code: '000000' })),
    );
    expect(results.filter((r) => r.status === 401)).toHaveLength(10);
    expect(results.filter((r) => r.status === 429)).toHaveLength(5);
  });
});

describe('P0-1 (b): a resend keeps used attempts while the window lasts', () => {
  it('refills only after the first code’s lifetime has passed', async () => {
    const h = setup();
    const email = 'carry@example.com';
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    await failVerify(h, email, 5);
    time.now += 9 * MIN; // still inside the first code's 10 minutes
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    expect(await env.DB.prepare('SELECT attempts FROM auth_email_codes').first('attempts')).toBe(5);
    expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: h.lastCode(email) })).status).toBe(401);

    time.now += 2 * MIN; // past T0 + 10 min
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    expect(await env.DB.prepare('SELECT attempts FROM auth_email_codes').first('attempts')).toBe(0);
    expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: h.lastCode(email) })).status).toBe(200);
  });

  it('a chain of resends cannot stretch the window', async () => {
    const h = setup();
    const email = 'chain@example.com';
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    const first = await env.DB.prepare('SELECT attempts_reset_at FROM auth_email_codes').first('attempts_reset_at');
    for (let i = 0; i < 3; i++) {
      time.now += 2 * MIN;
      await call(h, client(), 'POST', '/auth/device/email/start', { email });
    }
    expect(await env.DB.prepare('SELECT attempts_reset_at FROM auth_email_codes').first('attempts_reset_at')).toBe(first);
  });
});

describe('P0-1 (c): 8-digit codes', () => {
  it('sends 8 digits, verifies them, and refuses 6', async () => {
    const h = setup({ emailCode: { digits: 8 } });
    const email = 'eight@example.com';
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    const code = h.lastCode(email);
    expect(code).toMatch(/^\d{8}$/);
    expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: code.slice(0, 6) })).status).toBe(400);
    expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email, code })).status).toBe(200);
  });

  it('generates uniform 8-digit codes', () => {
    const counts = new Array<number>(10).fill(0);
    for (let i = 0; i < 5000; i++) {
      const code = generateEmailCode(8);
      expect(code).toMatch(/^\d{8}$/);
      for (const ch of code) (counts as number[])[Number(ch)]! += 1;
    }
    for (const n of counts) {
      expect(n).toBeGreaterThan(3600); // expected 4000, sd ~60
      expect(n).toBeLessThan(4400);
    }
  });

  it('rejects other lengths at construction', () => {
    expect(() => setup({ emailCode: { digits: 7 as 6 } })).toThrow(/digits/);
  });

  it('extractEmailCodeFromEmail reads 8 digits when told to', () => {
    expect(extractEmailCodeFromEmail('code 12345678, ref 123456', { digits: 8 })).toBe('12345678');
  });
});

// ---------------------------------------------------------------------------
// P0-2
// ---------------------------------------------------------------------------

describe('P0-2: device-bound sessions', () => {
  it('a revoked device’s bearer session dies at once, and its row is gone', async () => {
    const h = setup({ transport: 'response' });
    const owner = await enrolled(h, 'owner@example.com');
    const thief = client({ deviceToken: owner.deviceToken });
    await pinLogin(h, thief, PIN);
    const id = (owner.deviceToken as string).split('.')[0];
    const before = Number(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_sessions').first('n'));
    await call(h, owner, 'POST', `/auth/device/devices/${id}/revoke`);
    expect((await call(h, thief, 'GET', '/api/me')).status).toBe(401);
    expect((await call(h, owner, 'GET', '/api/me')).status).toBe(401); // owner's session was on that device too
    expect(Number(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_sessions').first('n'))).toBe(before - 2);
  });

  it('an expired device ends its sessions too', async () => {
    const h = setup({ transport: 'response', device: { idleTtlSec: 3600, absoluteTtlSec: 3600 }, bearerSessionTtlSec: 7200 });
    const c = await enrolled(h, 'exp@example.com');
    time.now += HOUR;
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(401);
  });

  it('a session without a device survives a single-device revoke but not revoke-all', async () => {
    const h = setup();
    const owner = await enrolled(h, 'mixed@example.com');
    const noDevice = client();
    time.now += 61 * SEC;
    await loginByEmail(h, noDevice, 'mixed@example.com', { trustDevice: false });
    const id = (await call(h, owner, 'GET', '/auth/device/devices')).body?.['devices'][0].deviceId;
    await call(h, owner, 'POST', `/auth/device/devices/${id}/revoke`);
    expect((await call(h, noDevice, 'GET', '/api/me')).status).toBe(200);
    await call(h, noDevice, 'POST', '/auth/device/devices/revoke-all');
    expect((await call(h, noDevice, 'GET', '/api/me')).status).toBe(401);
    expect(h.events).toContainEqual({ type: 'sessions.revoked_all', userId: 'mixed@example.com', reason: 'revoke_all' });
  });

  it('revoke-all clears the caller’s own session cookies', async () => {
    const h = setup();
    const c = await enrolled(h, 'clear@example.com');
    await call(h, c, 'POST', '/auth/device/devices/revoke-all');
    expect(c.jar['__Host-session']).toBeUndefined();
    expect(c.jar['__Host-device']).toBeUndefined();
  });

  it('PIN change with revokeOtherDevicesOnChange signs everyone out, keeping the current device', async () => {
    const h = setup({ pin: { iterations: 1000, revokeOtherDevicesOnChange: true } });
    const c = await enrolled(h, 'chg@example.com');
    time.now += 61 * SEC;
    await loginByEmail(h, c, 'chg@example.com');
    const res = await call(h, c, 'POST', '/auth/device/pin', { pin: '913572' });
    expect(res.body).toEqual({ ok: true, signedOut: true });
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(401);
    expect((await pinLogin(h, c, '913572')).status).toBe(200);
  });

  it('a first PIN set (nothing replaced) signs nobody out', async () => {
    const h = setup({ pin: { iterations: 1000, revokeOtherDevicesOnChange: true } });
    const c = client();
    await loginByEmail(h, c, 'first@example.com');
    expect((await call(h, c, 'POST', '/auth/device/pin', { pin: PIN })).body).toEqual({ ok: true });
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(200);
  });

  it('the programmatic revokeAllDevices ends sessions as well', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, 'prog@example.com');
    await h.device.revokeAllDevices('prog@example.com');
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(401);
  });

  it('refuses an Auth whose store is not device-bound', () => {
    const plain = d1SessionStore(env.DB);
    const auth = createAuth({ providers: [], store: plain });
    expect(() =>
      deviceAuth({ auth, store: d1DeviceAuthStore(env.DB), secret: randomToken(), transport: 'cookie', sendCode: async () => {} }),
    ).toThrow(/deviceBoundSessionStore/);
  });

  it('refuses a store that cannot revokeAllForUser', () => {
    const devices = d1DeviceAuthStore(env.DB);
    const store = deviceBoundSessionStore(kvSessionStore(env.KV, { allowUnrevocableSessions: true }), devices);
    const auth = createAuth({ providers: [], store });
    expect(() => deviceAuth({ auth, store: devices, secret: randomToken(), transport: 'cookie', sendCode: async () => {} })).toThrow(
      /revokeAllForUser/,
    );
  });

  it('refuses a sessionBearer provider reading an unwrapped store', () => {
    const devices = d1DeviceAuthStore(env.DB);
    const plain = d1SessionStore(env.DB);
    const auth = createAuth({ providers: [sessionBearer({ store: plain })], store: deviceBoundSessionStore(plain, devices) });
    expect(() => deviceAuth({ auth, store: devices, secret: randomToken(), transport: 'response', sendCode: async () => {} })).toThrow(
      /session-bearer/,
    );
  });

  it('the wrapper keeps the inner store’s other methods and does not double-wrap', async () => {
    const devices = d1DeviceAuthStore(env.DB);
    const inner = d1SessionStore(env.DB);
    const wrapped = deviceBoundSessionStore(inner, devices);
    expect(typeof wrapped.cleanup).toBe('function');
    expect(await wrapped.cleanup()).toBe(0);
    expect(deviceBoundSessionStore(wrapped, devices)).toBe(wrapped);
    expect(wrapped.canRevokeAllForUser).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// P1
// ---------------------------------------------------------------------------

describe('P1 (a): IPv6 is limited per /64', () => {
  it.each([
    ['203.0.113.7', '203.0.113.7'],
    ['2001:db8:1:2:3:4:5:6', '2001:db8:1:2::/64'],
    ['2001:db8:1:2::ffff', '2001:db8:1:2::/64'],
    ['2001:DB8:0001:0002:aaaa::1', '2001:db8:1:2::/64'],
    ['[2001:db8:1:2::1]', '2001:db8:1:2::/64'],
    ['fe80::1%eth0', 'fe80:0:0:0::/64'],
    ['::1', '0:0:0:0::/64'],
    ['::ffff:198.51.100.9', '198.51.100.9'],
    ['64:ff9b::198.51.100.9', '64:ff9b:0:0::/64'],
    ['not-an-ip', 'not-an-ip'],
    ['1:2:3:4:5:6:7:8:9', '1:2:3:4:5:6:7:8:9'],
  ])('%s -> %s', (ip, key) => expect(ipRateLimitKey(ip)).toBe(key));

  it('two addresses in one /64 share a bucket; another /64 does not', async () => {
    const h = setup({ limits: { startsPerIpPerHour: 1 } });
    expect((await call(h, client({ ip: '2001:db8::1' }), 'POST', '/auth/device/email/start', { email: 'a1@example.com' })).status).toBe(200);
    expect((await call(h, client({ ip: '2001:db8::2' }), 'POST', '/auth/device/email/start', { email: 'a2@example.com' })).status).toBe(429);
    expect((await call(h, client({ ip: '2001:db8:0:1::1' }), 'POST', '/auth/device/email/start', { email: 'a3@example.com' })).status).toBe(200);
  });

  it('ignores X-Forwarded-For', async () => {
    const h = setup({ limits: { startsPerIpPerHour: 1 } });
    const send = (email: string, xff: string) =>
      h.app.fetch(
        new Request(`${ORIGIN}/auth/device/email/start`, {
          method: 'POST',
          headers: { origin: ORIGIN, 'content-type': 'application/json', 'cf-connecting-ip': '198.51.100.9', 'x-forwarded-for': xff },
          body: JSON.stringify({ email }),
        }),
        env,
      );
    expect((await send('x1@example.com', '1.1.1.1')).status).toBe(200);
    expect((await send('x2@example.com', '2.2.2.2')).status).toBe(429);
  });
});

describe('P1 (b): circuit breaker', () => {
  it('is off by default', async () => {
    const h = setup({ emailCode: { maxFailuresPerEmail: 1000 } });
    for (let i = 0; i < 30; i++) {
      expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email: `cb${i}@example.com`, code: '000000' })).status).toBe(401);
    }
  });

  it('opens on enough failures at a high enough ratio, for everyone, and closes after the window', async () => {
    const h = setup({ circuitBreaker: { minFailures: 5, maxFailureRatio: 0.5, windowSec: 300 } });
    for (let i = 0; i < 5; i++) {
      await call(h, client(), 'POST', '/auth/device/email/verify', { email: `x${i}@example.com`, code: '000000' });
    }
    await call(h, client(), 'POST', '/auth/device/email/start', { email: 'victim@example.com' });
    const res = await call(h, client(), 'POST', '/auth/device/email/verify', { email: 'victim@example.com', code: h.lastCode('victim@example.com') });
    expect(res.status).toBe(503);
    expect(res.body).toMatchObject({ error: 'temporarily_unavailable' });
    expect(h.events).toContainEqual({ type: 'circuit_breaker.open', scope: 'email_verify' });

    time.now += 300 * SEC; // the breaker window, still inside the code's 10 minutes
    expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email: 'victim@example.com', code: h.lastCode('victim@example.com') })).status).toBe(200);
  });

  it('stays closed when failures are a small share of traffic', async () => {
    const h = setup({ circuitBreaker: { minFailures: 2, maxFailureRatio: 0.5, windowSec: 600 } });
    for (let i = 0; i < 4; i++) {
      time.now += 61 * SEC;
      expect((await loginByEmail(h, client(), `ok${i}@example.com`)).status).toBe(200);
    }
    for (let i = 0; i < 2; i++) {
      await call(h, client(), 'POST', '/auth/device/email/verify', { email: `bad${i}@example.com`, code: '000000' });
    }
    expect((await loginByEmail(h, client(), 'next@example.com')).status).toBe(200);
  });
});

describe('P1 (c): bot check hook', () => {
  it('refuses /email/start before sending and before counting, when the hook says no', async () => {
    const seen: string[] = [];
    const h = setup({
      botCheck: async (req, action) => {
        seen.push(action);
        return req.headers.get('x-turnstile') === 'ok';
      },
      limits: { startsPerIpPerHour: 1 },
    });
    const res = await call(h, client({ ip: '192.0.2.1' }), 'POST', '/auth/device/email/start', { email: 'b@example.com' });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'bot_check_failed' });
    expect(h.sent).toHaveLength(0);
    expect(seen).toEqual(['email_start']);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_rate_limits').first('n')).toBe(0);
  });

  it('admits when the hook says yes', async () => {
    const h = setup({ botCheck: (req) => req.headers.get('cf-connecting-ip') === '192.0.2.9' });
    expect((await call(h, client({ ip: '192.0.2.9' }), 'POST', '/auth/device/email/start', { email: 'b@example.com' })).status).toBe(200);
  });

  it('fails closed when the hook throws, and guards /pin/login before any PIN work', async () => {
    let calls = 0;
    const h = setup({
      botCheck: (_req, action) => {
        calls++;
        if (action === 'pin_login') throw new Error('turnstile down');
        return true;
      },
    });
    const c = await enrolled(h, 'bp@example.com');
    const res = await pinLogin(h, c, PIN);
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'bot_check_failed' });
    expect(calls).toBe(2);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_login_guards').first('n')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// P2
// ---------------------------------------------------------------------------

describe('P2-1: normalizeEmail', () => {
  const gmail = (raw: string) => {
    const [local, domain] = raw.trim().toLowerCase().split('@') as [string, string];
    return domain === 'gmail.com' ? `${local.split('+')[0]!.replace(/\./g, '')}@${domain}` : `${local}@${domain}`;
  };

  it('keys limits and resolveUser on the normalised address', async () => {
    const resolved: string[] = [];
    const h = setup({
      normalizeEmail: gmail,
      resolveUser: (email) => {
        resolved.push(email);
        return { id: email, subjectType: 'user', rateLimitId: email, email, claims: {} };
      },
    });
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email: 'victim@gmail.com' })).status).toBe(200);
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email: 'v.ic.tim+1@gmail.com' })).status).toBe(429);
    const ok = await call(h, client(), 'POST', '/auth/device/email/verify', { email: 'Victim+x@Gmail.com', code: h.lastCode('victim@gmail.com') });
    expect(ok.status).toBe(200);
    expect(resolved).toEqual(['victim@gmail.com']);
  });

  it('a normaliser that throws or returns a non-address means 400', async () => {
    const h = setup({ normalizeEmail: (raw) => (raw.startsWith('x') ? 'nope' : (() => { throw new Error('bad'); })()) });
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email: 'x@example.com' })).status).toBe(400);
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email: 'y@example.com' })).status).toBe(400);
  });
});

describe('P2-2: weak PINs', () => {
  it.each(['159357', '147369', '258456', '890123', '901234', '456654', '789987', '246810', '135790', '123654', '321654', '000001', '100000', '696969', '314159', '420420', '741852', '852456'])(
    'now flags %s',
    (p) => expect(isWeakPin(p)).toBe(true),
  );

  it.each(['482915', '739164', '205817', '613094', '880241'])('still accepts %s', (p) => expect(isWeakPin(p)).toBe(false));

  it('flags dates only when asked', () => {
    // DDMMYY, MMDDYY, YYMMDD, YYYYMM, MMYYYY — none weak by any other rule.
    for (const p of ['250394', '061287', '940325', '199507', '081994']) {
      expect(isWeakPin(p), p).toBe(false);
      expect(isWeakPin(p, { rejectDateLike: true }), p).toBe(true);
    }
    expect(isWeakPin('739164', { rejectDateLike: true })).toBe(false);
  });

  it('rejectDateLike is wired through deviceAuth', async () => {
    const h = setup({ pin: { iterations: 1000, rejectDateLike: true } });
    const c = client();
    await loginByEmail(h, c, 'date@example.com');
    expect((await call(h, c, 'POST', '/auth/device/pin', { pin: '250394' })).body).toEqual({ error: 'weak_pin' });
  });
});

describe('P2-3: a bearer session is refused on the cookie path', () => {
  it('presenting a bearer sid as the session cookie is unauthenticated', async () => {
    const h = setup({ transport: 'response' });
    const c = client();
    await loginByEmail(h, c, 'b3@example.com');
    const sid = (c.sessionToken as string).slice(4);
    expect((await call(h, client({ jar: { '__Host-session': sid } }), 'GET', '/api/me')).status).toBe(401);
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(200);
  });
});

describe('P2-4: emailVerifiedAt cannot be minted through the public API', () => {
  it('the old authMeta option and a meta __auth key both fail to grant PIN changes', async () => {
    const h = setup();
    h.app.post('/test/forge', async (c) => {
      const user = { id: 'forge@example.com', subjectType: 'user' as const, rateLimitId: 'forge@example.com', claims: {} };
      await h.auth.createSession(c, user, { authMeta: { emailVerifiedAt: Date.now() } } as never);
      return c.json({ ok: true });
    });
    const c = client();
    await call(h, c, 'POST', '/test/forge');
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(200);
    expect((await call(h, c, 'POST', '/auth/device/pin', { pin: PIN })).body).toEqual(REQUIRED);
  });
});

describe('P2-6: secret entropy', () => {
  it.each(['a'.repeat(40), 'abcd'.repeat(10), 'password'.repeat(4), 'changemechangemechangemechangeme'])('refuses %s', (s) => {
    let message = '';
    try {
      setup({ secret: s });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/low-entropy/);
    expect(message).not.toContain(s);
  });

  it('accepts generated secrets', () => {
    for (let i = 0; i < 50; i++) expect(() => setup({ secret: randomToken(32) })).not.toThrow();
    const hex = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
    expect(estimateEntropyBits(hex)).toBeGreaterThan(96);
  });
});

describe('P2-8: 4 KB body limit', () => {
  it('refuses a large declared body with 413', async () => {
    const h = setup();
    const res = await call(h, client(), 'POST', '/auth/device/email/start', { email: 'big@example.com', pad: 'x'.repeat(5000) });
    expect(res.status).toBe(413);
    expect(res.body).toEqual({ error: 'payload_too_large' });
    expect(h.sent).toHaveLength(0);
  });

  it('refuses a large streamed body without Content-Length', async () => {
    const h = setup();
    const big = new TextEncoder().encode(JSON.stringify({ pin: PIN, pad: 'y'.repeat(6000) }));
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let i = 0; i < big.length; i += 1000) controller.enqueue(big.slice(i, i + 1000));
        controller.close();
      },
    });
    const res = await h.app.fetch(
      new Request(`${ORIGIN}/auth/device/pin/login`, {
        method: 'POST',
        headers: { origin: ORIGIN, 'content-type': 'application/json' },
        body: stream,
      }),
      env,
    );
    expect(res.status).toBe(413);
  });

  it('still accepts a normal body', async () => {
    const h = setup();
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email: 'small@example.com', pad: 'x'.repeat(3000) })).status).toBe(200);
  });
});

describe('P2-10: requireClientIp', () => {
  it('refuses requests without an IP when set', async () => {
    const h = setup({ requireClientIp: true });
    const res = await call(h, client(), 'POST', '/auth/device/email/start', { email: 'ip@example.com' });
    expect(res.status).toBe(400);
    expect(res.body).toEqual({ error: 'client_ip_required' });
    expect((await call(h, client({ ip: '192.0.2.3' }), 'POST', '/auth/device/email/start', { email: 'ip@example.com' })).status).toBe(200);
  });

  it('skips per-IP limits without an IP by default', async () => {
    const h = setup({ limits: { startsPerIpPerHour: 1 } });
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email: 'n1@example.com' })).status).toBe(200);
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email: 'n2@example.com' })).status).toBe(200);
  });
});
