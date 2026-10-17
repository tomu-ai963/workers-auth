/**
 * Concurrent requests that D1's single writer serialises for free and
 * Postgres does not: two PIN changes on one account at the same moment must
 * both succeed, leaving exactly one live PIN (the store serialises them with
 * an advisory lock on Postgres; see src/store/pg/device-auth.ts). The
 * deterministic interleaving is in test/pg-node/races.test.ts; this drives the
 * real routes, several rounds, against whichever backend the project runs.
 */
import { beforeEach, describe, expect, it } from 'vitest';

import { db } from './helpers/backend.js';
import { resetStorage } from './helpers/reset.js';
import { call, client, HEAVY_TIMEOUT, loginByEmail, SEC, setup, T0, time } from './helpers/device.js';

beforeEach(async () => {
  time.now = T0;
  await resetStorage();
});

const livePins = async () =>
  Number(await db.prepare("SELECT COUNT(*) AS n FROM auth_credentials WHERE type = 'pin' AND revoked_at IS NULL").first('n'));

describe('concurrent PIN changes on one account', { timeout: HEAVY_TIMEOUT }, () => {
  it.each([
    ['the first PIN (nothing to revoke yet)', false],
    ['replacing an existing PIN', true],
  ])('%s: both requests succeed and one PIN stays live', async (_name, existing) => {
    const h = setup();
    const email = 'race@example.com';
    const sessions = [];
    for (let i = 0; i < 4; i++) {
      const c = client();
      expect((await loginByEmail(h, c, email)).status).toBe(200);
      sessions.push(c);
      time.now += 61 * SEC;
    }
    if (existing) expect((await call(h, sessions[0]!, 'POST', '/auth/device/pin', { pin: '482915' })).status).toBe(200);

    for (const [x, y, pins] of [
      [0, 1, ['739164', '205817']],
      [2, 3, ['613094', '880241']],
    ] as const) {
      const results = await Promise.all([
        call(h, sessions[x]!, 'POST', '/auth/device/pin', { pin: pins[0] }),
        call(h, sessions[y]!, 'POST', '/auth/device/pin', { pin: pins[1] }),
      ]);
      expect(results.map((r) => r.status)).toEqual([200, 200]);
      expect(await livePins()).toBe(1);
    }
  });
});
