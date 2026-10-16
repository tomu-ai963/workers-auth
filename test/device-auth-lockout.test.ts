/**
 * Re-review of feat/device-auth (2026-10): P1-A (lockout through the
 * per-address failure cap), P2-C (getting around the device-bound store) and
 * P2-D (circuit breaker counting).
 *
 * Verification test E: an attacker who knows only the victim's address uses up
 * that address's failure budget; the victim, whose PIN is locked, then has no
 * way back in for 24 hours. The fix counts requests that present a valid
 * trusted device of that address against a per-device budget instead.
 */
import { env } from 'cloudflare:test';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';

import packageJson from '../package.json?raw';
import readme from '../README.md?raw';
import security from '../SECURITY.md?raw';
import credentialsSource from '../src/device-auth/credentials.ts?raw';
import notices from '../THIRD_PARTY_NOTICES?raw';
import {
  d1DeviceAuthStore,
  deviceAuth,
  deviceBoundSessionStore,
  isDeviceBoundSessionStore,
} from '../src/device-auth/index.js';
import { createAuth, getUser, type Auth } from '../src/index.js';
import { sessionBearer } from '../src/providers/session-bearer.js';
import { d1SessionStore } from '../src/store/d1.js';
import type { SessionStore } from '../src/types.js';
import { resetStorage } from './helpers/reset.js';
import {
  HEAVY_TIMEOUT,
  call,
  clock,
  client,
  DAY,
  enrolled,
  HOUR,
  loginByEmail,
  MIN,
  ORIGIN,
  pinLogin,
  SEC,
  SECRET_A,
  setup,
  spendFailures,
  T0,
  time,
  wrongCode,
  type Client,
  type Harness,
} from './helpers/device.js';

beforeEach(async () => {
  time.now = T0;
  await resetStorage();
});

const PIN = '482915';
const START = '/auth/device/email/start';
const VERIFY = '/auth/device/email/verify';
const REQUIRED = { error: 'email_verification_required' };

async function lockPin(h: Harness, c: Client) {
  for (let i = 0; i < 3; i++) await pinLogin(h, c, '000000');
  expect((await pinLogin(h, c, PIN)).body).toEqual(REQUIRED);
}

async function bucketCount(prefix: string): Promise<number> {
  const n = await env.DB.prepare('SELECT COALESCE(SUM(count), 0) AS n FROM auth_rate_limits WHERE bucket LIKE ?1')
    .bind(`${prefix}%`)
    .first('n');
  return Number(n);
}

/** Enrolled owner (PIN locked) and an attacker who has spent the address budget. */
async function lockedOutOwner(h: Harness, email: string, init: Partial<Client> = {}) {
  const owner = await enrolled(h, email, PIN, init);
  await lockPin(h, owner);
  time.now += 61 * SEC; // past the enrolment code's resend cooldown
  const attacker = client({ ip: '198.51.100.66' });
  await spendFailures(h, attacker, email, 10);
  expect((await call(h, attacker, 'POST', START, { email })).status).toBe(429);
  expect((await call(h, attacker, 'POST', VERIFY, { email, code: '123456' })).status).toBe(429);
  return { owner, attacker };
}

// ---------------------------------------------------------------------------
// P1-A
// ---------------------------------------------------------------------------

describe('P1-A verification test E: a locked-out owner can recover', { timeout: HEAVY_TIMEOUT }, () => {
  it('the owner of a trusted device unlocks the PIN by email after an attacker spent the address budget', async () => {
    const h = setup();
    const email = 'victim@example.com';
    const { owner } = await lockedOutOwner(h, email);

    const start = await call(h, owner, 'POST', START, { email });
    expect(start.status).toBe(200);
    const verify = await call(h, owner, 'POST', VERIFY, { email, code: h.lastCode(email) });
    expect(verify.status).toBe(200);
    expect(h.events).toContainEqual({ type: 'pin.unlocked', userId: email });
    expect((await pinLogin(h, owner, PIN)).status).toBe(200);
  });

  it('same in response mode (x-device-token), including a fresh-email-auth route and a PIN change', async () => {
    const h = setup({ transport: 'response' });
    const email = 'resp@example.com';
    const { owner } = await lockedOutOwner(h, email);

    expect((await call(h, owner, 'POST', START, { email })).status).toBe(200);
    expect((await call(h, owner, 'POST', VERIFY, { email, code: h.lastCode(email) })).status).toBe(200);
    expect((await call(h, owner, 'POST', '/api/sensitive')).status).toBe(200);
    expect((await call(h, owner, 'POST', '/auth/device/pin', { pin: '739164' })).status).toBe(200);
    expect((await pinLogin(h, owner, '739164')).status).toBe(200);
  });

  it('the address budget stays exhausted for anyone without the device', async () => {
    const h = setup();
    const email = 'still@example.com';
    const { owner } = await lockedOutOwner(h, email);
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(200);
    // A new device (no token) is still refused, even with the code the owner was just sent.
    const res = await call(h, client(), 'POST', VERIFY, { email, code: h.lastCode(email) });
    expect(res.status).toBe(429);
    expect(h.events.at(-1)).toEqual({ type: 'rate_limited', scope: 'email_failures' });
  });

  it('exhausting the device budget stops that device too — and only that device', async () => {
    const h = setup();
    const email = 'thief@example.com';
    const owner = await enrolled(h, email, PIN);
    time.now += 61 * SEC;
    // Whoever holds the device gets 10 checked failures, then nothing.
    await spendFailures(h, owner, email, 10);
    const start = await call(h, owner, 'POST', START, { email });
    expect(start.status).toBe(429);
    expect(h.events.at(-1)).toEqual({ type: 'rate_limited', scope: 'device_failures' });
    const verify = await call(h, owner, 'POST', VERIFY, { email, code: '123456' });
    expect(verify.status).toBe(429);
    expect(h.events.at(-1)).toEqual({ type: 'rate_limited', scope: 'device_failures' });

    // The address budget was not touched, so a login without the device still works.
    // 10 checked failures; the refused verify above added nothing.
    expect(await bucketCount('otp-fail:device:')).toBe(10);
    expect(await bucketCount('otp-fail:')).toBe(10);
    expect((await loginByEmail(h, client(), email)).status).toBe(200);

    // ...and the device budget lifts after the window.
    time.now += DAY;
    expect((await loginByEmail(h, owner, email)).status).toBe(200);
  });

  it('a success on the device gives its reservation back to the device budget', async () => {
    const h = setup();
    const email = 'dev-success@example.com';
    const owner = await enrolled(h, email, PIN);
    time.now += 61 * SEC;
    await spendFailures(h, owner, email, 9);
    expect((await loginByEmail(h, owner, email)).status).toBe(200);
    expect(await bucketCount('otp-fail:device:')).toBe(9);
    // The 10th failure is still checked (not 429)...
    time.now += 61 * SEC;
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(200);
    expect((await call(h, owner, 'POST', VERIFY, { email, code: wrongCode(h, email) })).status).toBe(401);
    // ...and it is the one that reaches the cap.
    time.now += 61 * SEC;
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(429);
  });

  it('honours maxFailuresPerDevice and validates it', async () => {
    const h = setup({ emailCode: { maxFailuresPerDevice: 2 } });
    const email = 'small-dev@example.com';
    const owner = await enrolled(h, email, PIN);
    time.now += 61 * SEC;
    await spendFailures(h, owner, email, 2);
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(429);
    expect(() => setup({ emailCode: { maxFailuresPerDevice: 0 } })).toThrow(/maxFailuresPerDevice/);
    expect(() => setup({ emailCode: { maxFailuresPerDevice: 1.5 } })).toThrow(/maxFailuresPerDevice/);
  });

  it('a device registered to another address does not get the device budget', async () => {
    const h = setup();
    const email = 'target@example.com';
    await lockedOutOwner(h, email);
    const other = await enrolled(h, 'attacker-own@example.com', PIN);
    expect((await call(h, other, 'POST', START, { email })).status).toBe(429);
    expect((await call(h, other, 'POST', VERIFY, { email, code: '123456' })).status).toBe(429);
  });

  it('a revoked or expired device does not get the device budget', async () => {
    const h = setup({ device: { idleTtlSec: (2 * HOUR) / SEC, absoluteTtlSec: (2 * HOUR) / SEC } });
    const email = 'dead@example.com';
    const { owner } = await lockedOutOwner(h, email);
    const deviceId = (owner.jar['__Host-device'] as string).split('.')[0] as string;

    // Expired: lockedOutOwner took ~23 min; jump past the 2 h device lifetime.
    const t = time.now;
    time.now = T0 + 2 * HOUR;
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(429);
    time.now = t;

    // Revoked.
    await h.device.revokeDevice(email, deviceId);
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(429);
  });

  it('the address hourly send cap and cooldown do not hold back the device owner', async () => {
    const h = setup();
    const email = 'spam@example.com';
    const owner = await enrolled(h, email, PIN);
    const attacker = client({ ip: '198.51.100.7' });
    for (let i = 0; i < 4; i++) {
      time.now += 61 * SEC;
      expect((await call(h, attacker, 'POST', START, { email })).status).toBe(200);
    }
    time.now += 61 * SEC;
    expect((await call(h, attacker, 'POST', START, { email })).status).toBe(429); // 5 per hour per address
    expect(h.events.at(-1)).toEqual({ type: 'rate_limited', scope: 'email_hourly' });
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(200);
    // The device has a cooldown of its own.
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(429);
    expect(h.events.at(-1)).toEqual({ type: 'rate_limited', scope: 'device_cooldown' });
    // An attacker request right after does not touch the owner's cooldown or cap.
    time.now += 61 * SEC;
    expect((await call(h, attacker, 'POST', START, { email })).status).toBe(429);
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(200);
  });

  it('the device has its own hourly send cap', async () => {
    const h = setup();
    const email = 'devcap@example.com';
    const owner = await enrolled(h, email, PIN);
    for (let i = 0; i < 5; i++) {
      time.now += 61 * SEC;
      expect((await call(h, owner, 'POST', START, { email })).status).toBe(200);
    }
    time.now += 61 * SEC;
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(429);
    expect(h.events.at(-1)).toEqual({ type: 'rate_limited', scope: 'device_hourly' });
  });
});

/** Guesses that were actually compared against a live code. */
function comparedGuesses(h: Harness): number {
  return h.events.filter(
    (e) => e.type === 'email_code.failed' && ['mismatch', 'unknown_key', 'already_used'].includes(e.reason),
  ).length;
}

async function failureCount(bucketPattern: string): Promise<number> {
  const n = await env.DB.prepare('SELECT count FROM auth_rate_limits WHERE bucket LIKE ?1').bind(bucketPattern).first('count');
  return Number(n ?? 0);
}

describe('P1-A (a) under concurrency: a refused request leaves no reservation behind', { timeout: HEAVY_TIMEOUT }, () => {
  it.each([20, 40])('%i parallel no-code verifies (no device) do not spend the address budget', async (n) => {
    const h = setup();
    const email = `par${n}@example.com`;
    const attacker = client({ ip: '198.51.100.9' });
    await Promise.all(Array.from({ length: n }, () => call(h, attacker, 'POST', VERIFY, { email, code: '000000' })));
    expect(h.sent).toHaveLength(0);
    expect(comparedGuesses(h)).toBe(0);
    expect(await failureCount('otp-fail:%')).toBe(0);
    expect((await call(h, client(), 'POST', START, { email })).status).toBe(200);
  });

  it('parallel no-code verifies from a trusted device do not spend that device’s budget', async () => {
    const h = setup();
    const email = 'par-dev@example.com';
    const owner = await enrolled(h, email, PIN);
    await Promise.all(Array.from({ length: 40 }, () => call(h, owner, 'POST', VERIFY, { email, code: '000000' })));
    expect(await failureCount('otp-fail:device:%')).toBe(0);
    time.now += 61 * SEC;
    expect((await call(h, owner, 'POST', START, { email })).status).toBe(200);
  });

  it('with 2 slots left, 20 parallel wrong guesses compare exactly 2; the rest get 429; the count stays at the cap', async () => {
    const h = setup();
    const email = 'two-left@example.com';
    await spendFailures(h, client(), email, 8);
    await call(h, client(), 'POST', START, { email });
    const before = comparedGuesses(h);
    const wrong = wrongCode(h, email);
    const results = await Promise.all(Array.from({ length: 20 }, () => call(h, client(), 'POST', VERIFY, { email, code: wrong })));
    expect(comparedGuesses(h) - before).toBe(2);
    expect(results.filter((r) => r.status === 401)).toHaveLength(2);
    expect(results.filter((r) => r.status === 429)).toHaveLength(18);
    expect(await failureCount('otp-fail:%')).toBe(10);
  });

  it('the same, on the device budget', async () => {
    const h = setup();
    const email = 'two-left-dev@example.com';
    const owner = await enrolled(h, email, PIN);
    time.now += 61 * SEC;
    await spendFailures(h, owner, email, 8);
    await call(h, owner, 'POST', START, { email });
    const before = comparedGuesses(h);
    const wrong = wrongCode(h, email);
    const results = await Promise.all(Array.from({ length: 20 }, () => call(h, owner, 'POST', VERIFY, { email, code: wrong })));
    expect(comparedGuesses(h) - before).toBe(2);
    expect(results.filter((r) => r.status === 429)).toHaveLength(18);
    expect(await failureCount('otp-fail:device:%')).toBe(10);
  });

  it('a refused verify still reports retry-after for the current window', async () => {
    const h = setup();
    const email = 'retry@example.com';
    await spendFailures(h, client(), email, 10);
    const res = await call(h, client(), 'POST', VERIFY, { email, code: '123456' });
    expect(res.status).toBe(429);
    expect(Number(res.res.headers.get('retry-after'))).toBeGreaterThan(23 * 3600);
    expect(await failureCount('otp-fail:%')).toBe(10);
  });
});

describe('P1-A (a): verifying without a live code costs nothing', { timeout: HEAVY_TIMEOUT }, () => {
  it('no code at all: the address budget is untouched', async () => {
    const h = setup();
    const email = 'nocode@example.com';
    for (let i = 0; i < 25; i++) {
      const res = await call(h, client(), 'POST', VERIFY, { email, code: '000000' });
      expect(res.status).toBe(401);
      expect(res.body).toEqual({ error: 'invalid_code' });
    }
    expect(await bucketCount('otp-fail:')).toBe(0);
    const reasons = h.events.flatMap((e) => (e.type === 'email_code.failed' ? [e.reason] : []));
    expect(reasons).toEqual(Array(25).fill('no_live_code'));
    expect((await loginByEmail(h, client(), email)).status).toBe(200);
  });

  it('a code with its attempts used up: only the 5 checked guesses are charged', async () => {
    const h = setup();
    const email = 'used@example.com';
    await call(h, client(), 'POST', START, { email });
    for (let i = 0; i < 12; i++) {
      expect((await call(h, client(), 'POST', VERIFY, { email, code: wrongCode(h, email) })).status).toBe(401);
    }
    expect(await bucketCount('otp-fail:')).toBe(5);
  });

  it('an expired code is not charged either', async () => {
    const h = setup();
    const email = 'expired@example.com';
    await call(h, client(), 'POST', START, { email });
    time.now += 10 * MIN;
    expect((await call(h, client(), 'POST', VERIFY, { email, code: h.lastCode(email) })).status).toBe(401);
    expect(await bucketCount('otp-fail:')).toBe(0);
  });

  it('the device budget gets its reservation back the same way', async () => {
    const h = setup();
    const email = 'dev-refund@example.com';
    const owner = await enrolled(h, email, PIN);
    for (let i = 0; i < 15; i++) await call(h, owner, 'POST', VERIFY, { email, code: '000000' });
    expect(await bucketCount('otp-fail:')).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// P1-A (c): botCheck on /email/verify
// ---------------------------------------------------------------------------

describe('P1-A (c): botCheck covers /email/verify', { timeout: HEAVY_TIMEOUT }, () => {
  it('refuses before any budget, attempt or breaker count is taken', async () => {
    const seen: string[] = [];
    const h = setup({
      botCheck: (req, action) => {
        seen.push(action);
        return action !== 'email_verify' || req.headers.get('cf-connecting-ip') === '192.0.2.50';
      },
      circuitBreaker: { minFailures: 100 },
    });
    const email = 'bot@example.com';
    await call(h, client(), 'POST', START, { email });
    const before = Number(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_rate_limits').first('n'));
    const res = await call(h, client({ ip: '192.0.2.1' }), 'POST', VERIFY, { email, code: h.lastCode(email) });
    expect(res.status).toBe(403);
    expect(res.body).toEqual({ error: 'bot_check_failed' });
    expect(h.events).toContainEqual({ type: 'bot_check.failed', action: 'email_verify' });
    expect(Number(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_rate_limits').first('n'))).toBe(before);
    expect(await env.DB.prepare('SELECT attempts FROM auth_email_codes').first('attempts')).toBe(0);
    expect(seen).toEqual(['email_start', 'email_verify']);

    expect((await call(h, client({ ip: '192.0.2.50' }), 'POST', VERIFY, { email, code: h.lastCode(email) })).status).toBe(200);
  });

  it('fails closed when the hook throws on verify', async () => {
    const h = setup({
      botCheck: (_req, action) => {
        if (action === 'email_verify') throw new Error('turnstile down');
        return true;
      },
    });
    const email = 'bot2@example.com';
    await call(h, client(), 'POST', START, { email });
    expect((await call(h, client(), 'POST', VERIFY, { email, code: h.lastCode(email) })).status).toBe(403);
  });
});

// ---------------------------------------------------------------------------
// P2-D: circuit breaker counting
// ---------------------------------------------------------------------------

describe('P2-D: circuit breaker', { timeout: HEAVY_TIMEOUT }, () => {
  const breakerRow = () =>
    env.DB.prepare("SELECT count, failures, window_start FROM auth_rate_limits WHERE bucket = 'cb:email-verify'").first<{
      count: number;
      failures: number;
      window_start: number;
    }>();

  it('verifies with no live code count neither as attempts nor as failures', async () => {
    const h = setup({ circuitBreaker: { minFailures: 3, maxFailureRatio: 0.5, windowSec: 600 } });
    for (let i = 0; i < 20; i++) {
      await call(h, client(), 'POST', VERIFY, { email: `none${i}@example.com`, code: '000000' });
    }
    expect(await breakerRow()).toBeNull();
    expect((await loginByEmail(h, client(), 'ok@example.com')).status).toBe(200);
    expect(await breakerRow()).toMatchObject({ count: 1, failures: 0 });
  });

  it('keeps attempts and failures in one row, and a new window resets both together', async () => {
    const h = setup({ circuitBreaker: { minFailures: 3, maxFailureRatio: 0.5, windowSec: 600 } });
    await call(h, client(), 'POST', START, { email: 'a@example.com' });
    await call(h, client(), 'POST', VERIFY, { email: 'a@example.com', code: wrongCode(h, 'a@example.com') });
    await call(h, client(), 'POST', VERIFY, { email: 'a@example.com', code: wrongCode(h, 'a@example.com') });
    expect(await breakerRow()).toEqual({ count: 2, failures: 2, window_start: T0 });

    time.now += 600 * SEC;
    expect((await loginByEmail(h, client(), 'b@example.com')).status).toBe(200);
    expect(await breakerRow()).toEqual({ count: 1, failures: 0, window_start: T0 + 600 * SEC });

    // Two failures in this window: 2 of 3 is over the ratio but under minFailures.
    for (const e of ['c@example.com', 'd@example.com']) {
      await call(h, client(), 'POST', START, { email: e });
      await call(h, client(), 'POST', VERIFY, { email: e, code: wrongCode(h, e) });
    }
    expect(await breakerRow()).toMatchObject({ count: 3, failures: 2 });
    expect((await loginByEmail(h, client(), 'e@example.com')).status).toBe(200);
  });

  it('opens when failures are exactly maxFailureRatio of attempts', async () => {
    const h = setup({ circuitBreaker: { minFailures: 2, maxFailureRatio: 0.5, windowSec: 600 } });
    for (const e of ['s1@example.com', 's2@example.com']) {
      expect((await loginByEmail(h, client(), e)).status).toBe(200);
    }
    for (const e of ['w1@example.com', 'w2@example.com']) {
      await call(h, client(), 'POST', START, { email: e });
      await call(h, client(), 'POST', VERIFY, { email: e, code: wrongCode(h, e) });
    }
    expect(await breakerRow()).toMatchObject({ count: 4, failures: 2 });
    await call(h, client(), 'POST', START, { email: 'w3@example.com' });
    expect((await call(h, client(), 'POST', VERIFY, { email: 'w3@example.com', code: h.lastCode('w3@example.com') })).status).toBe(503);
  });

  it('opens exactly at minFailures when the ratio is met', async () => {
    const h = setup({ circuitBreaker: { minFailures: 3, maxFailureRatio: 0.5, windowSec: 600 } });
    for (const e of ['f1@example.com', 'f2@example.com']) {
      await call(h, client(), 'POST', START, { email: e });
      await call(h, client(), 'POST', VERIFY, { email: e, code: wrongCode(h, e) });
    }
    await call(h, client(), 'POST', START, { email: 'f3@example.com' });
    expect((await call(h, client(), 'POST', VERIFY, { email: 'f3@example.com', code: wrongCode(h, 'f3@example.com') })).status).toBe(401);
    const res = await call(h, client(), 'POST', VERIFY, { email: 'f3@example.com', code: h.lastCode('f3@example.com') });
    expect(res.status).toBe(503);
    expect(Number(res.res.headers.get('retry-after'))).toBe(600);
  });
});

// ---------------------------------------------------------------------------
// P2-C: the device check cannot be stepped around
// ---------------------------------------------------------------------------

/** A second app over the same session table, reading through `store`. */
function sideApp(store: SessionStore) {
  const auth: Auth = createAuth({ providers: [sessionBearer({ store })], store, clock });
  const app = new Hono();
  app.use('/api/*', auth.middleware());
  app.get('/api/me', (c) => c.json(getUser(c)));
  return (headers: Record<string, string>) => app.fetch(new Request(`${ORIGIN}/api/me`, { headers }), env);
}

/** Inherits from the device-bound store but reads the raw store. */
function prototypeWrapper(wrapped: SessionStore, raw: SessionStore): SessionStore {
  const sub = Object.create(wrapped) as SessionStore;
  Object.defineProperty(sub, 'get', { value: (sid: string) => raw.get(sid) });
  return sub;
}

/** An app's own wrapper (logging, say) around a store. */
function appWrapper(inner: SessionStore): SessionStore {
  const wrapper: SessionStore = {
    get: (sid) => inner.get(sid),
    create: (input) => inner.create(input),
    touch: (sid, idleExpiresAt) => inner.touch(sid, idleExpiresAt),
    revoke: (sid) => inner.revoke(sid),
    revokeAllForUser: (userId) => inner.revokeAllForUser(userId),
    get canRevokeAllForUser() {
      return inner.canRevokeAllForUser;
    },
  };
  return wrapper;
}

const WRAPPERS = [
  ['prototype-inherited', prototypeWrapper],
  ['app-specific', (wrapped: SessionStore) => appWrapper(wrapped)],
] as const;

describe('P2-C: device binding holds through wrappers', { timeout: HEAVY_TIMEOUT }, () => {
  it('only the object deviceBoundSessionStore() returned is recognised', () => {
    const devices = d1DeviceAuthStore(env.DB);
    const raw = d1SessionStore(env.DB);
    const wrapped = deviceBoundSessionStore(raw, devices);
    expect(isDeviceBoundSessionStore(wrapped)).toBe(true);
    expect(isDeviceBoundSessionStore(Object.create(wrapped))).toBe(false);
    expect(isDeviceBoundSessionStore(prototypeWrapper(wrapped, raw))).toBe(false);
    expect(isDeviceBoundSessionStore(appWrapper(wrapped))).toBe(false);
    expect(isDeviceBoundSessionStore({ ...wrapped })).toBe(false);
  });

  it.each(WRAPPERS)('deviceAuth refuses an Auth over a %s wrapper', (_name, make) => {
    const devices = d1DeviceAuthStore(env.DB);
    const raw = d1SessionStore(env.DB);
    const store = make(deviceBoundSessionStore(raw, devices), raw);
    const auth = createAuth({ providers: [], store });
    expect(() =>
      deviceAuth({ auth, store: devices, secret: SECRET_A, transport: 'cookie', sendCode: async () => {} }),
    ).toThrow(/deviceBoundSessionStore/);
    const bearerOnly = createAuth({ providers: [sessionBearer({ store })], store: deviceBoundSessionStore(raw, devices) });
    expect(() =>
      deviceAuth({ auth: bearerOnly, store: devices, secret: SECRET_A, transport: 'response', sendCode: async () => {} }),
    ).toThrow(/session-bearer/);
  });

  it.each(WRAPPERS)('a device-bound cookie session read through a %s wrapper is refused', async (_name, make) => {
    const h = setup();
    const c = await enrolled(h, 'cookie-wrap@example.com', PIN);
    const cookie = `__Host-session=${c.jar['__Host-session']}`;
    const raw = d1SessionStore(env.DB, { clock });
    const read = sideApp(make(h.sessionStore, raw));
    const good = sideApp(h.sessionStore);

    expect((await good({ cookie })).status).toBe(200);
    expect((await read({ cookie })).status).toBe(401);

    // After the device is revoked: refused everywhere.
    await call(h, c, 'POST', '/auth/device/device/forget');
    expect((await read({ cookie })).status).toBe(401);
    expect((await good({ cookie })).status).toBe(401);
  });

  it.each(WRAPPERS)('a device-bound bearer session read through a %s wrapper is refused', async (_name, make) => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, 'bearer-wrap@example.com', PIN);
    const authorization = `Bearer ${c.sessionToken}`;
    const raw = d1SessionStore(env.DB, { clock });
    const read = sideApp(make(h.sessionStore, raw));
    const good = sideApp(h.sessionStore);

    expect((await good({ authorization })).status).toBe(200);
    expect((await read({ authorization })).status).toBe(401);

    const deviceId = (c.deviceToken as string).split('.')[0] as string;
    await h.device.revokeDevice('bearer-wrap@example.com', deviceId);
    expect((await read({ authorization })).status).toBe(401);
    expect((await good({ authorization })).status).toBe(401);
  });

  it('sessions with no device pass through any store; an app wrapper inside the device-bound one works', async () => {
    const h = setup({ transport: 'response' });
    const c = client();
    await loginByEmail(h, c, 'nodev@example.com', { trustDevice: false });
    const raw = d1SessionStore(env.DB, { clock });
    expect((await sideApp(appWrapper(raw))({ authorization: `Bearer ${c.sessionToken}` })).status).toBe(200);

    const owner = await enrolled(h, 'inside@example.com', PIN);
    const inside = deviceBoundSessionStore(appWrapper(raw), d1DeviceAuthStore(env.DB), { clock });
    expect((await sideApp(inside)({ authorization: `Bearer ${owner.sessionToken}` })).status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// P2-B / P2-E: what ships matches what is embedded and implemented
// ---------------------------------------------------------------------------

describe('P2-E: SecLists attribution ships with the package', () => {
  it('THIRD_PARTY_NOTICES carries the MIT notice and is in package.json files', () => {
    expect(notices).toContain('SecLists');
    expect(notices).toContain('Copyright (c) 2018 Daniel Miessler');
    expect(notices).toContain('The above copyright notice and this permission notice shall be included in all');
    expect((JSON.parse(packageJson) as { files: string[] }).files).toContain('THIRD_PARTY_NOTICES');
    expect(credentialsSource).toContain('THIRD_PARTY_NOTICES');
  });
});

describe('P2-B: fixed-window wording', () => {
  it('README and SECURITY.md state the per-window cap and the boundary maximum', () => {
    expect(readme).toContain('up to 20 within 24 hours');
    expect(security).toContain('up to 20 within 24 h');
    expect(readme).not.toContain('Ten failed verifications\nfor one address within 24 hours');
  });
});
