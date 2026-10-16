/**
 * Regression tests for the two P0 findings of the 2026-10 review of
 * feat/device-auth. Each test is the exact reproduction used in the review.
 */
import { beforeEach, describe, expect, it } from 'vitest';

import { resetStorage } from './helpers/reset.js';
import { HEAVY_TIMEOUT, call, client, enrolled, loginByEmail, MIN, pinLogin, SEC, setup, T0, time } from './helpers/device.js';

beforeEach(async () => {
  time.now = T0;
  await resetStorage();
});

describe('P0-1: email codes cannot be brute-forced across resends', { timeout: HEAVY_TIMEOUT }, () => {
  it('10 wrong guesses spread over two codes block the next correct code', async () => {
    const h = setup();
    const email = 'v@example.com';
    const statuses: number[] = [];
    for (let round = 0; round < 2; round++) {
      await call(h, client(), 'POST', '/auth/device/email/start', { email });
      const code = h.lastCode(email);
      for (let i = 0; i < 5; i++) {
        const wrong = String((Number(code) + 1 + i) % 1_000_000).padStart(6, '0');
        statuses.push((await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: wrong })).status);
      }
      time.now += 61 * SEC;
    }
    expect(statuses).toEqual(Array(10).fill(401));

    // The resend inherited the 5 used attempts, so the second round was never
    // checked (and, since the re-review, never charged). The correct code of a
    // third resend is still refused.
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    const res = await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: h.lastCode(email) });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid_code' });
  });

  it('10 checked wrong guesses over two attempt windows block the next correct code', async () => {
    const h = setup();
    const email = 'v2@example.com';
    for (let round = 0; round < 2; round++) {
      await call(h, client(), 'POST', '/auth/device/email/start', { email });
      const code = h.lastCode(email);
      for (let i = 0; i < 5; i++) {
        const wrong = String((Number(code) + 1 + i) % 1_000_000).padStart(6, '0');
        expect((await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: wrong })).status).toBe(401);
      }
      time.now += 11 * MIN; // past the attempt window: the next code has 5 fresh attempts
    }
    expect((await call(h, client(), 'POST', '/auth/device/email/start', { email })).status).toBe(429);
    const res = await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: h.lastCode(email) });
    expect(res.status).toBe(429);
    expect(res.body).toMatchObject({ error: 'rate_limited' });
  });

  it('a resend while the code is still valid keeps its used attempts', async () => {
    const h = setup();
    const email = 'w@example.com';
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    const first = h.lastCode(email);
    for (let i = 0; i < 5; i++) {
      const wrong = String((Number(first) + 1 + i) % 1_000_000).padStart(6, '0');
      await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: wrong });
    }
    time.now += 61 * SEC; // within the 10-minute validity
    await call(h, client(), 'POST', '/auth/device/email/start', { email });
    const res = await call(h, client(), 'POST', '/auth/device/email/verify', { email, code: h.lastCode(email) });
    expect(res.status).toBe(401);
    expect(res.body).toEqual({ error: 'invalid_code' });
  });
});

describe('P0-2: revoking a device ends the sessions minted on it', { timeout: HEAVY_TIMEOUT }, () => {
  it('a thief’s cookie session dies on /devices/:id/revoke and stays dead after revoke-all', async () => {
    const h = setup();
    const owner = await enrolled(h, 'a@example.com');
    const id = (await call(h, owner, 'GET', '/auth/device/devices')).body?.['devices'][0].deviceId;
    const thief = client({ jar: { '__Host-device': owner.jar['__Host-device'] as string } });
    expect((await pinLogin(h, thief, '482915')).status).toBe(200);
    expect((await call(h, thief, 'GET', '/api/me')).status).toBe(200);

    await call(h, owner, 'POST', `/auth/device/devices/${id}/revoke`);
    expect((await call(h, thief, 'GET', '/api/me')).status).toBe(401);
    await call(h, owner, 'POST', '/auth/device/devices/revoke-all');
    expect((await call(h, thief, 'GET', '/api/me')).status).toBe(401);
  });

  it('revokeOtherDevicesOnChange ends the other devices’ bearer sessions', async () => {
    const h = setup({ transport: 'response', pin: { iterations: 1000, revokeOtherDevicesOnChange: true } });
    const other = await enrolled(h, 'c@example.com');
    expect((await call(h, other, 'GET', '/api/me')).status).toBe(200);
    const here = client();
    time.now += 61 * SEC;
    await loginByEmail(h, here, 'c@example.com');
    await call(h, here, 'POST', '/auth/device/pin', { pin: '913572' });
    expect((await call(h, other, 'GET', '/api/me')).status).toBe(401);
  });

  it('/device/forget ends that device’s session immediately', async () => {
    const h = setup({ transport: 'response' });
    const c = await enrolled(h, 'd@example.com');
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(200);
    await call(h, client({ deviceToken: c.deviceToken }), 'POST', '/auth/device/device/forget');
    expect((await call(h, c, 'GET', '/api/me')).status).toBe(401);
  });
});
