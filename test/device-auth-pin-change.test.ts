/**
 * PIN change with `revokeOtherDevicesOnChange` (security review of
 * feat/pg-store, F1 and F3), on both backends.
 *
 * F3: replacing the PIN and revoking the other devices are one transaction
 * (D1: one batch). If the revocation fails, the PIN is not replaced either.
 * Ending the sessions stays a separate step (a KV session store cannot join a
 * transaction); if that step fails, the other devices' sessions are dead
 * anyway, because their devices are.
 *
 * F1 (Postgres): "was a PIN replaced?" comes from RETURNING rows, so an
 * executor whose driver reports no rowCount cannot silently turn a PIN change
 * into "nothing replaced, nobody signed out".
 */
import { beforeEach, describe, expect, it } from 'vitest';

import { BACKEND, failDeviceRevocation, makeDeviceStore, neonExecutor, nullRowCount } from './helpers/backend.js';
import { resetStorage } from './helpers/reset.js';
import {
  call,
  client,
  clock,
  enrolled,
  HEAVY_TIMEOUT,
  loginByEmail,
  pinLogin,
  SEC,
  setup,
  T0,
  time,
  type StoreOverrides,
} from './helpers/device.js';

beforeEach(async () => {
  time.now = T0;
  await resetStorage();
});

const OLD_PIN = '482915';
const NEW_PIN = '739164';
const EMAIL = 'changer@example.com';
const REQUIRED = { error: 'email_verification_required' };

/** Owner on device A (PIN set, fresh email session) and a second device B of the same account. */
async function twoDevices(stores: StoreOverrides = {}) {
  const h = setup({ pin: { iterations: 1000, revokeOtherDevicesOnChange: true } }, {}, stores);
  const a = await enrolled(h, EMAIL, OLD_PIN);
  time.now += 61 * SEC;
  const b = client();
  expect((await loginByEmail(h, b, EMAIL)).status).toBe(200);
  expect((await call(h, b, 'GET', '/api/me')).status).toBe(200);
  time.now += 61 * SEC;
  expect((await loginByEmail(h, a, EMAIL)).status).toBe(200); // a fresh email session on A
  return { h, a, b };
}

describe('PIN change with revokeOtherDevicesOnChange', { timeout: HEAVY_TIMEOUT }, () => {
  it('normally: the PIN is replaced and the other device is revoked, its session with it', async () => {
    const { h, a, b } = await twoDevices();
    expect((await call(h, a, 'POST', '/auth/device/pin', { pin: NEW_PIN })).body).toEqual({ ok: true, signedOut: true });
    expect((await call(h, b, 'GET', '/api/me')).status).toBe(401);
    expect((await pinLogin(h, b, NEW_PIN)).body).toEqual(REQUIRED); // device B is gone
    expect((await pinLogin(h, a, OLD_PIN)).status).toBe(401);
    expect((await pinLogin(h, a, NEW_PIN)).status).toBe(200);
  });

  it('F3: if revoking the other devices fails, the PIN is not replaced either', async () => {
    const { h, a, b } = await twoDevices();
    const restore = await failDeviceRevocation();
    let status: number;
    try {
      status = (await call(h, a, 'POST', '/auth/device/pin', { pin: NEW_PIN })).status;
    } finally {
      await restore();
    }
    expect(status).toBe(500);
    // All or nothing: the old PIN still logs in, the new one does not, B is untouched.
    expect((await pinLogin(h, a, OLD_PIN)).status).toBe(200);
    expect((await pinLogin(h, a, NEW_PIN)).status).toBe(401);
    expect((await call(h, b, 'GET', '/api/me')).status).toBe(200);
  });

  it('if ending the sessions fails afterwards, the other device’s session is still refused', async () => {
    const { h, a, b } = await twoDevices({
      wrapSessionStore: (inner) =>
        Object.assign(Object.create(inner) as typeof inner, {
          revokeAllForUser: async () => {
            throw new Error('injected: revokeAllForUser fails');
          },
        }),
    });
    expect((await call(h, a, 'POST', '/auth/device/pin', { pin: NEW_PIN })).status).toBe(500);
    expect((await call(h, b, 'GET', '/api/me')).status).toBe(401); // its device is revoked
    expect((await pinLogin(h, b, NEW_PIN)).body).toEqual(REQUIRED);
    expect((await pinLogin(h, a, NEW_PIN)).status).toBe(200); // the change itself stood
  });
});

describe.runIf(BACKEND === 'pg')('F1: an executor that reports no rowCount', { timeout: HEAVY_TIMEOUT }, () => {
  it('a PIN change still signs the other device out', async () => {
    const deviceStore = makeDeviceStore({ clock, executor: nullRowCount(neonExecutor()) });
    const { h, a, b } = await twoDevices({ deviceStore });
    expect((await call(h, a, 'POST', '/auth/device/pin', { pin: NEW_PIN })).body).toEqual({ ok: true, signedOut: true });
    expect((await call(h, b, 'GET', '/api/me')).status).toBe(401);
    expect((await pinLogin(h, b, NEW_PIN)).body).toEqual(REQUIRED);
  });
});
