/**
 * Round trips and time per request on the main routes, against the real Neon
 * test project (pnpm test:neon only). Measured from the machine running the
 * tests to aws-ap-southeast-1 — NOT from a Cloudflare Worker, whose distance
 * to the database (and so every number here) is different.
 *
 * Every store call goes through a counting executor: one `query()` or one
 * `transaction()` is one HTTPS request to Neon. Nothing is asserted beyond the
 * routes succeeding; the numbers are printed for the report.
 */
import { describe, expect, it } from 'vitest';

import type { PgExecutor } from '../../src/store/pg/index.js';
import { makeDeviceStore, makeSessionStore, neonExecutor } from '../helpers/backend.js';
import { resetStorage } from '../helpers/reset.js';
import { call, client, clock, HEAVY_TIMEOUT, pinLogin, SEC, setup, T0, time } from '../helpers/device.js';

type Tally = { requests: number; statements: number };

function counting(executor: PgExecutor, tally: Tally): PgExecutor {
  return {
    query: (text, params) => {
      tally.requests++;
      tally.statements++;
      return executor.query(text, params);
    },
    transaction: (statements) => {
      tally.requests++;
      tally.statements += statements.length;
      return executor.transaction(statements);
    },
  };
}

const RUNS = 5;

describe('latency per route against Neon', { timeout: HEAVY_TIMEOUT * 4 }, () => {
  it('measures round trips and wall time', async () => {
    time.now = T0;
    await resetStorage();
    const tally: Tally = { requests: 0, statements: 0 };
    const executor = counting(neonExecutor(), tally);
    const h = setup({}, {}, {
      deviceStore: makeDeviceStore({ clock, executor }),
      sessionStore: makeSessionStore({ clock, executor }),
    });

    const samples: Record<string, Array<{ ms: number } & Tally>> = {};
    async function measure<T extends { status: number }>(name: string, run: () => Promise<T>): Promise<T> {
      const before = { ...tally };
      const t = performance.now();
      const result = await run();
      const ms = performance.now() - t;
      (samples[name] ??= []).push({ ms, requests: tally.requests - before.requests, statements: tally.statements - before.statements });
      return result;
    }

    for (let i = 0; i < RUNS; i++) {
      const email = `latency${i}@example.com`;
      const c = client();
      time.now += 61 * SEC;
      expect((await measure('email/start', () => call(h, c, 'POST', '/auth/device/email/start', { email }))).status).toBe(200);
      expect(
        (await measure('email/verify', () => call(h, c, 'POST', '/auth/device/email/verify', { email, code: h.lastCode(email) }))).status,
      ).toBe(200);
      expect((await measure('session read (GET /api/me)', () => call(h, c, 'GET', '/api/me'))).status).toBe(200);
      expect((await measure('PIN set (first)', () => call(h, c, 'POST', '/auth/device/pin', { pin: '482915' }))).status).toBe(200);
      expect((await measure('PIN change', () => call(h, c, 'POST', '/auth/device/pin', { pin: '739164' }))).status).toBe(200);
      expect((await measure('PIN login', () => pinLogin(h, c, '739164'))).status).toBe(200);
    }

    const rows = Object.entries(samples).map(([route, s]) => {
      const ms = s.map((x) => x.ms).sort((x, y) => x - y);
      return {
        route,
        requests: [...new Set(s.map((x) => x.requests))].join('/'),
        statements: [...new Set(s.map((x) => x.statements))].join('/'),
        median_ms: Math.round(ms[Math.floor(ms.length / 2)]!),
        min_ms: Math.round(ms[0]!),
        max_ms: Math.round(ms[ms.length - 1]!),
      };
    });
    console.log('[neon latency]\n' + rows.map((r) => JSON.stringify(r)).join('\n'));
  });
});
