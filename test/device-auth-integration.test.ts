import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { randomToken } from '../src/crypto.js';
import {
  deviceAuth,
  deviceBoundSessionStore,
  type DeviceAuthStore,
} from '../src/device-auth/index.js';
import { createAuth } from '../src/index.js';
import { d1MagicLinkStore, magicLink } from '../src/providers/magic-link.js';
import { sessionBearer } from '../src/providers/session-bearer.js';
import { resetStorage } from './helpers/reset.js';
import {
  call,
  client,
  clock,
  enrolled,
  HOUR,
  loginByEmail,
  pinLogin,
  SECRET_A,
  SECRET_B,
  setup,
  T0,
  time,
} from './helpers/device.js';
import { db, makeDeviceStore, makeSessionStore } from './helpers/backend.js';

beforeEach(async () => {
  time.now = T0;
  await resetStorage();
});

const EMAIL = 'alice@example.com';
const PIN = '482915';
const REQUIRED = { error: 'email_verification_required' };

describe('bearer sessions (transport: response)', () => {
  it('logs in by email, authenticates by bearer, and revokes on logout', async () => {
    const h = setup({ transport: 'response' });
    const c = client({ origin: null });
    const res = await loginByEmail(h, c, EMAIL);
    expect(res.status).toBe(200);
    expect(res.body?.['sessionExpiresAt']).toBe(T0 + 12 * HOUR);

    expect((await call(h, c, 'GET', '/api/me')).body).toMatchObject({ id: EMAIL });
    expect((await call(h, c, 'POST', '/auth/device/logout')).status).toBe(200);
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(401);
  });

  it('logs in by PIN, authenticates by bearer, and revokes on logout', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, EMAIL, PIN, { origin: null });
    await call(h, c, 'POST', '/auth/device/logout');
    delete c.sessionToken;
    const res = await pinLogin(h, c, PIN);
    expect(res.status).toBe(200);
    expect(c.sessionToken).toMatch(/^wsb_/);
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(200);
    await call(h, c, 'POST', '/auth/device/logout');
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(401);
  });

  it('expires after 12 hours by default, with no sliding', async () => {
    const h = setup({ transport: 'response' });
    const c = client();
    await loginByEmail(h, c, EMAIL);
    time.now += 11 * HOUR;
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(200);
    time.now = T0 + 12 * HOUR;
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(401);
  });

  it('honours bearerSessionTtlSec', async () => {
    const h = setup({ transport: 'response', bearerSessionTtlSec: 3600 });
    const c = client();
    expect((await loginByEmail(h, c, EMAIL)).body?.['sessionExpiresAt']).toBe(T0 + HOUR);
  });

  it('does not accept a cookie session id as a bearer token', async () => {
    const h = setup();
    const c = client();
    await loginByEmail(h, c, EMAIL);
    const sid = c.jar['__Host-session'] as string;
    const res = await call(h, client({ sessionToken: `wsb_${sid}` }), 'GET', '/api/me');
    expect(res.status).toBe(401);
  });

  it('ignores non-bearer-session Authorization values', async () => {
    const h = setup({ transport: 'response' });
    for (const token of ['', 'wsb_', 'wsb_short', 'tk_live_abc.def', 'x'.repeat(200)]) {
      expect((await call(h, client({ sessionToken: token }), 'GET', '/api/me')).status).toBe(401);
    }
  });

  it('a bearer login does not rotate out a cookie session on the same request', async () => {
    const store = deviceBoundSessionStore(makeSessionStore({ clock }), makeDeviceStore(), { clock });
    const auth = createAuth({ providers: [sessionBearer({ store })], store, clock });
    const before = await db.prepare('SELECT COUNT(*) AS n FROM auth_sessions').first('n');
    const h = setup({ transport: 'response', auth });
    await loginByEmail(h, client(), EMAIL);
    expect(await db.prepare('SELECT COUNT(*) AS n FROM auth_sessions').first('n')).toBe(Number(before) + 1);
  });
});

describe('CSRF (transport: cookie)', () => {
  const EVIL = 'https://evil.example';

  it.each([
    ['/auth/device/email/start', { email: EMAIL }],
    ['/auth/device/email/verify', { email: EMAIL, code: '123456' }],
    ['/auth/device/pin/login', { pin: PIN }],
    ['/auth/device/pin', { pin: PIN }],
    ['/auth/device/device/forget', undefined],
    ['/auth/device/logout', undefined],
  ])('rejects a cross-origin POST to %s', async (path, body) => {
    const h = setup();
    const res = await call(h, client({ origin: EVIL }), 'POST', path, body);
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'csrf_failed' });
  });

  it('rejects a POST with no Origin at all', async () => {
    const h = setup();
    const res = await call(h, client({ origin: null }), 'POST', '/auth/device/email/start', { email: EMAIL });
    expect(res.status).toBe(403);
    expect(h.sent).toHaveLength(0);
  });

  it('a cross-origin PIN login with the victim’s device cookie neither logs in nor counts', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    const forged = await call(h, { ...c, origin: EVIL }, 'POST', '/auth/device/pin/login', { pin: '739164' });
    expect(forged.status).toBe(403);
    expect((await db.prepare('SELECT failed_count FROM auth_login_guards').first('failed_count')) ?? 0).toBe(0);
  });

  it('requires the double-submit header once a CSRF cookie exists', async () => {
    const h = setup();
    const c = await enrolled(h, EMAIL);
    const headers = { origin: 'https://app.example.com', 'content-type': 'application/json', cookie: `__Host-session=${c.jar['__Host-session']}; __Host-csrf=${c.jar['__Host-csrf']}; __Host-device=${c.jar['__Host-device']}` };
    const res = await h.app.fetch(
      new Request('https://app.example.com/auth/device/pin/login', { method: 'POST', headers, body: JSON.stringify({ pin: PIN }) }),
      env,
    );
    expect(res.status).toBe(403);
  });

  it('accepts a configured trusted origin', async () => {
    const h = setup({}, { csrf: { trustedOrigins: ['https://www.example.com'] } });
    const res = await call(h, client({ origin: 'https://www.example.com' }), 'POST', '/auth/device/email/start', { email: EMAIL });
    expect(res.status).toBe(200);
  });

  it('response mode needs no Origin (nothing ambient to forge)', async () => {
    const h = setup({ transport: 'response' });
    const res = await loginByEmail(h, client({ origin: null }), EMAIL);
    expect(res.status).toBe(200);
  });
});

describe('secret rotation (previousSecrets)', () => {
  it('verifies a PIN made with a previous secret, then re-hashes it under the current one', async () => {
    const old = setup({ transport: 'response', secret: SECRET_A });
    const c = await enrolled(old, EMAIL);
    const before = JSON.parse((await db.prepare('SELECT material FROM auth_credentials').first('material')) as string);

    const rotated = setup({ transport: 'response', secret: SECRET_B, previousSecrets: [SECRET_A] });
    expect((await pinLogin(rotated, c, PIN)).status).toBe(200);
    const after = JSON.parse((await db.prepare('SELECT material FROM auth_credentials').first('material')) as string);
    expect(after.pepperVer).not.toBe(before.pepperVer);
    expect(after.salt).not.toBe(before.salt);

    // Already migrated: works once the old secret is gone.
    const finished = setup({ transport: 'response', secret: SECRET_B });
    expect((await pinLogin(finished, c, PIN)).status).toBe(200);
  });

  it('without the previous secret, an unmigrated PIN no longer verifies', async () => {
    const old = setup({ transport: 'response', secret: SECRET_A });
    const c = await enrolled(old, EMAIL);
    const dropped = setup({ transport: 'response', secret: SECRET_B });
    expect((await pinLogin(dropped, c, PIN)).body).toEqual({ error: 'invalid_pin', attemptsRemaining: 2 });
  });

  it('verifies an email code issued under a previous secret', async () => {
    const old = setup({ secret: SECRET_A });
    await call(old, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    const code = old.lastCode(EMAIL);
    const rotated = setup({ secret: SECRET_B, previousSecrets: [SECRET_A] });
    expect((await call(rotated, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code })).status).toBe(200);
  });

  it('rejects an email code whose secret is no longer configured', async () => {
    const old = setup({ secret: SECRET_A });
    await call(old, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    const code = old.lastCode(EMAIL);
    const dropped = setup({ secret: SECRET_B });
    expect((await call(dropped, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code })).status).toBe(401);
  });

  it('refuses a short secret without echoing it', () => {
    const short = 'x'.repeat(31);
    let message = '';
    try {
      setup({ secret: short });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toMatch(/at least 32/);
    expect(message).not.toContain(short);
    expect(() => setup({ previousSecrets: ['too-short'] })).toThrow(/previousSecrets\[0\]/);
  });
});

describe('audit events', () => {
  it('covers the lifecycle and never carries a PIN, code, device secret or session id', async () => {
    const h = setup({
      transport: 'response',
      resolveUser: (email) => ({ id: 'user_1', subjectType: 'user', rateLimitId: 'user_1', email, claims: {} }),
    });
    const c = await enrolled(h, EMAIL);
    const code = h.lastCode(EMAIL);
    await pinLogin(h, c, '739164');
    await pinLogin(h, c, '739164');
    await pinLogin(h, c, '739164');
    await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code: '000000' });
    time.now += 61_000;
    await loginByEmail(h, c, EMAIL);
    await pinLogin(h, c, PIN);
    const id = (c.deviceToken as string).split('.')[0] as string;
    await call(h, c, 'POST', `/auth/device/devices/${id}/revoke`);

    const types = new Set(h.events.map((e) => e.type));
    for (const t of [
      'email_code.sent',
      'email_code.verified',
      'email_code.failed',
      'device.registered',
      'pin.set',
      'pin.login.failed',
      'pin.locked',
      'pin.unlocked',
      'pin.login.succeeded',
      'device.revoked',
      'session.created',
    ]) {
      expect(types, t).toContain(t);
    }

    const dump = JSON.stringify(h.events);
    const secret = (c.deviceToken as string).split('.')[1] as string;
    for (const raw of [PIN, '739164', code, h.lastCode(EMAIL), secret, (c.sessionToken as string).slice(4), EMAIL]) {
      expect(dump).not.toContain(raw);
    }
  });
});

describe('coexistence with magic links', () => {
  function withMagicLink() {
    const tokens: string[] = [];
    const sessionStore = deviceBoundSessionStore(makeSessionStore({ clock }), makeDeviceStore(), {
      clock,
    });
    const provider = magicLink({
      store: d1MagicLinkStore(env.DB, { clock }), // magic links have no Postgres store: D1 in both projects
      sendToken: async (_email, token) => {
        tokens.push(token);
      },
      clock,
    });
    const auth = createAuth({ providers: [provider, sessionBearer({ store: sessionStore })], store: sessionStore, clock });
    return { h: setup({ auth }), provider, tokens };
  }

  async function magicLogin(m: ReturnType<typeof withMagicLink>) {
    await m.provider.start(EMAIL);
    return m.h.app.fetch(
      new Request('https://app.example.com/auth/session', {
        method: 'POST',
        headers: { origin: 'https://app.example.com', 'x-magic-token': m.tokens.at(-1) as string },
      }),
      env,
    );
  }

  it('magic-link login keeps working alongside deviceAuth', async () => {
    const m = withMagicLink();
    await enrolled(m.h, EMAIL);
    expect((await magicLogin(m)).status).toBe(200);
  });

  it('a magic-link login does not lift a PIN lockout', async () => {
    const m = withMagicLink();
    const c = await enrolled(m.h, EMAIL);
    for (let i = 0; i < 3; i++) await pinLogin(m.h, c, '739164');
    expect((await magicLogin(m)).status).toBe(200);
    expect((await pinLogin(m.h, c, PIN)).body).toEqual(REQUIRED);
  });
});

describe('construction', () => {
  const base = () => {
    const store = deviceBoundSessionStore(makeSessionStore(), makeDeviceStore());
    return { auth: createAuth({ providers: [], store }), sendCode: async () => {}, secret: randomToken() };
  };

  it('refuses a store that cannot update counters atomically', () => {
    const fake = { ...makeDeviceStore(), atomic: false } as DeviceAuthStore;
    expect(() => deviceAuth({ ...base(), store: fake, transport: 'cookie' })).toThrow(/atomic/);
  });

  it('requires an explicit transport', () => {
    expect(() =>
      deviceAuth({ ...base(), store: makeDeviceStore(), transport: undefined as unknown as 'cookie' }),
    ).toThrow(/transport/);
  });

  it('bounds PBKDF2 iterations to what Workers supports', () => {
    const opts = { ...base(), store: makeDeviceStore(), transport: 'cookie' as const };
    expect(() => deviceAuth({ ...opts, pin: { iterations: 100_001 } })).toThrow(/iterations/);
    expect(() => deviceAuth({ ...opts, pin: { iterations: 999 } })).toThrow(/iterations/);
    expect(() => deviceAuth({ ...opts, pin: { iterations: 10_000 } })).not.toThrow();
  });

  it('rejects absoluteTtlSec < idleTtlSec for devices', () => {
    expect(() =>
      deviceAuth({
        ...base(),
        store: makeDeviceStore(),
        transport: 'cookie',
        device: { idleTtlSec: 100, absoluteTtlSec: 50 },
      }),
    ).toThrow(/absoluteTtlSec/);
  });
});
