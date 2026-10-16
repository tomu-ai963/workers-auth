import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { generateEmailCode } from '../src/device-auth/index.js';
import { resetStorage } from './helpers/reset.js';
import { call, client, loginByEmail, MIN, SEC, setup, T0, time } from './helpers/device.js';

beforeEach(async () => {
  time.now = T0;
  await resetStorage();
});

const EMAIL = 'alice@example.com';

describe('email code generation', () => {
  it('always produces 6 digits, leading zeros included, uniformly per position', () => {
    const N = 10_000;
    const counts = Array.from({ length: 6 }, () => new Array<number>(10).fill(0));
    let leadingZero = 0;
    for (let i = 0; i < N; i++) {
      const code = generateEmailCode();
      expect(code).toMatch(/^\d{6}$/);
      if (code[0] === '0') leadingZero++;
      for (let p = 0; p < 6; p++) (counts[p] as number[])[Number(code[p])]! += 1;
    }
    expect(leadingZero).toBeGreaterThan(0);
    // Expected 1,000 per digit per position, sd ≈ 30. ±200 is > 6 sd.
    for (const position of counts) {
      for (const n of position) {
        expect(n).toBeGreaterThan(800);
        expect(n).toBeLessThan(1200);
      }
    }
  });
});

describe('POST /email/start', () => {
  it('stores only an HMAC of the code', async () => {
    const h = setup();
    await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    const code = h.lastCode(EMAIL);
    const rows = (await env.DB.prepare('SELECT * FROM auth_email_codes').all()).results;
    expect(rows).toHaveLength(1);
    const row = rows[0] as Record<string, unknown>;
    expect(JSON.stringify(row)).not.toContain(code);
    expect(row['code_hash']).toMatch(/^[0-9a-f]{64}$/);
  });

  it('answers a known and an unknown address identically, and sends to both', async () => {
    const h = setup({ resolveUser: (email) => (email === EMAIL ? { id: 'u1', subjectType: 'user', rateLimitId: 'u1', claims: {} } : null) });
    const known = await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    const unknown = await call(h, client(), 'POST', '/auth/device/email/start', { email: 'nobody@example.com' });
    expect(known.status).toBe(200);
    expect(unknown.status).toBe(known.status);
    expect(unknown.body).toEqual(known.body);
    expect(h.sent.map((m) => m.email)).toEqual([EMAIL, 'nobody@example.com']);
  });

  it('swallows delivery failures into onSendError', async () => {
    const errors: unknown[] = [];
    const h = setup({
      sendCode: async () => {
        throw new Error('smtp down');
      },
      onSendError: (e) => errors.push(e),
    });
    const res = await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    expect(res.status).toBe(200);
    expect(errors).toHaveLength(1);
  });

  it('rejects a malformed address as a client error', async () => {
    const h = setup();
    const res = await call(h, client(), 'POST', '/auth/device/email/start', { email: 'not-an-email' });
    expect(res.status).toBe(400);
    expect(h.sent).toHaveLength(0);
  });

  it('enforces the resend cooldown', async () => {
    const h = setup();
    const c = client();
    expect((await call(h, c, 'POST', '/auth/device/email/start', { email: EMAIL })).status).toBe(200);
    const again = await call(h, c, 'POST', '/auth/device/email/start', { email: EMAIL });
    expect(again.status).toBe(429);
    expect(again.body).toMatchObject({ error: 'rate_limited' });
    expect(Number(again.res.headers.get('retry-after'))).toBeGreaterThan(0);
    time.now += 61 * SEC;
    expect((await call(h, c, 'POST', '/auth/device/email/start', { email: EMAIL })).status).toBe(200);
    expect(h.sent).toHaveLength(2);
  });

  it('caps codes per address per hour', async () => {
    const h = setup();
    const c = client();
    for (let i = 0; i < 5; i++) {
      expect((await call(h, c, 'POST', '/auth/device/email/start', { email: EMAIL })).status).toBe(200);
      time.now += 61 * SEC;
    }
    expect((await call(h, c, 'POST', '/auth/device/email/start', { email: EMAIL })).status).toBe(429);
    time.now += 60 * MIN;
    expect((await call(h, c, 'POST', '/auth/device/email/start', { email: EMAIL })).status).toBe(200);
  });

  it('caps starts per IP per hour, across addresses', async () => {
    const h = setup();
    const c = client({ ip: '203.0.113.7' });
    for (let i = 0; i < 20; i++) {
      expect((await call(h, c, 'POST', '/auth/device/email/start', { email: `u${i}@example.com` })).status).toBe(200);
    }
    expect((await call(h, c, 'POST', '/auth/device/email/start', { email: 'u20@example.com' })).status).toBe(429);
    const other = client({ ip: '203.0.113.8' });
    expect((await call(h, other, 'POST', '/auth/device/email/start', { email: 'u20@example.com' })).status).toBe(200);
    expect(h.events.some((e) => e.type === 'rate_limited' && e.scope === 'email_start_ip')).toBe(true);
  });
});

describe('POST /email/verify', () => {
  it('accepts the delivered code once and mints a session', async () => {
    const h = setup();
    const c = client();
    const ok = await loginByEmail(h, c, EMAIL);
    expect(ok.status).toBe(200);
    expect(ok.body).toMatchObject({ ok: true, pinSet: false, user: { id: EMAIL } });

    const me = await call(h, c, 'GET', '/api/me');
    expect(me.status).toBe(200);

    const replay = await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code: h.lastCode(EMAIL) });
    expect(replay.status).toBe(401);
    expect(replay.body).toEqual({ error: 'invalid_code' });
  });

  it('expires a code after 10 minutes', async () => {
    const h = setup();
    await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    time.now += 10 * MIN + 1;
    const res = await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code: h.lastCode(EMAIL) });
    expect(res.status).toBe(401);
  });

  it('burns a code after 5 wrong attempts — the right code fails on the 6th', async () => {
    const h = setup();
    await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    const code = h.lastCode(EMAIL);
    const wrong = code === '000000' ? '000001' : '000000';
    for (let i = 0; i < 5; i++) {
      expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code: wrong })).status).toBe(401);
    }
    const res = await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code });
    expect(res.status).toBe(401);
    expect(await env.DB.prepare('SELECT COUNT(*) AS n FROM auth_email_codes').first('n')).toBe(0);
  });

  it('counts concurrent wrong guesses: 10 in parallel still exhaust the code', async () => {
    const h = setup();
    await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    const code = h.lastCode(EMAIL);
    const wrong = code === '999999' ? '999998' : '999999';
    const results = await Promise.all(
      Array.from({ length: 10 }, () => call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code: wrong })),
    );
    expect(results.every((r) => r.status === 401)).toBe(true);
    const res = await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code });
    expect(res.status).toBe(401);
  });

  it('lets exactly one of two concurrent correct submissions through', async () => {
    const h = setup();
    await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    const code = h.lastCode(EMAIL);
    const results = await Promise.all([
      call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code }),
      call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code }),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });

  it('invalidates the previous code on resend', async () => {
    const h = setup();
    await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
    let first = h.lastCode(EMAIL);
    let second = first;
    // A 1-in-a-million repeat would make the assertion meaningless; resend until different.
    while (second === first) {
      time.now += 61 * SEC;
      await call(h, client(), 'POST', '/auth/device/email/start', { email: EMAIL });
      second = h.lastCode(EMAIL);
    }
    expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code: first })).status).toBe(401);
    first = second;
    expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code: first })).status).toBe(200);
  });

  it('refuses when resolveUser refuses', async () => {
    const h = setup({ resolveUser: () => null });
    const res = await loginByEmail(h, client(), EMAIL);
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid_code' });
  });

  it('caps verifies per IP per hour', async () => {
    const h = setup({ limits: { verifiesPerIpPerHour: 3 } });
    const c = client({ ip: '198.51.100.1' });
    for (let i = 0; i < 3; i++) {
      expect((await call(h, c, 'POST', '/auth/device/email/verify', { email: EMAIL, code: '123456' })).status).toBe(401);
    }
    expect((await call(h, c, 'POST', '/auth/device/email/verify', { email: EMAIL, code: '123456' })).status).toBe(429);
  });

  it('rejects a non-6-digit code before touching the store', async () => {
    const h = setup();
    const res = await call(h, client(), 'POST', '/auth/device/email/verify', { email: EMAIL, code: '12345' });
    expect(res.status).toBe(400);
  });
});
