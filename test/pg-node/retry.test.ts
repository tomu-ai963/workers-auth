/**
 * The Postgres stores retry exactly once, and only on SQLSTATE 40001
 * (serialization failure) or 40P01 (deadlock) — both reported after Postgres
 * rolled the transaction back. A network error or timeout may have committed,
 * and a reservation run twice would be charged twice: never retried.
 * No database needed.
 */
import { describe, expect, it } from 'vitest';

import type { PgExecutor, PgQueryResult } from '../../src/store/pg/index.js';
import { pgDeviceAuthStore, pgSessionStore } from '../../src/store/pg/index.js';
import { retryOnce } from '../../src/store/pg/executor.js';

const ok: PgQueryResult = { rows: [{ count: '1', window_start: '5' }], rowCount: 1 };
const sqlError = (code: string) => Object.assign(new Error(`sqlstate ${code}`), { code });

/** Fails with `errors` in turn, then succeeds; counts calls. */
function flaky(errors: unknown[]) {
  let calls = 0;
  const next = async () => {
    const e = errors[calls++];
    if (e !== undefined) throw e;
    return ok;
  };
  const executor: PgExecutor = { query: next as PgExecutor['query'], transaction: async () => [await next(), await next(), await next()] };
  return { executor, calls: () => calls };
}

describe('retryOnce', () => {
  it.each(['40001', '40P01'])('retries %s once and returns the second result', async (code) => {
    let n = 0;
    expect(await retryOnce(async () => (n++ === 0 ? Promise.reject(sqlError(code)) : 'second'))).toBe('second');
    expect(n).toBe(2);
  });

  it.each(['40001', '40P01'])('does not retry %s a second time', async (code) => {
    let n = 0;
    await expect(retryOnce(async () => Promise.reject(sqlError(code)))).rejects.toMatchObject({ code });
    await expect(
      retryOnce(async () => {
        n++;
        throw sqlError(code);
      }),
    ).rejects.toThrow();
    expect(n).toBe(2);
  });

  it.each([
    ['a unique violation', sqlError('23505')],
    ['a lock timeout', sqlError('55P03')],
    ['a statement timeout', sqlError('57014')],
    ['a network error', new TypeError('fetch failed')],
    ['an error with a numeric code', Object.assign(new Error('x'), { code: 40001 })],
    ['a thrown string', 'boom'],
  ])('never retries %s', async (_name, error) => {
    let n = 0;
    await expect(
      retryOnce(async () => {
        n++;
        throw error;
      }),
    ).rejects.toBe(error);
    expect(n).toBe(1);
  });
});

describe('the stores route every call through it', () => {
  it('a reservation hit by a deadlock is retried once', async () => {
    const f = flaky([sqlError('40P01')]);
    expect(await pgDeviceAuthStore(f.executor).reserveRateLimit('b', 1000, 0, 10)).toEqual({ count: 1, windowStart: 5 });
    expect(f.calls()).toBe(2);
  });

  it('a reservation that fails on the network is not retried', async () => {
    const f = flaky([new TypeError('fetch failed')]);
    await expect(pgDeviceAuthStore(f.executor).reserveRateLimit('b', 1000, 0, 10)).rejects.toThrow('fetch failed');
    expect(f.calls()).toBe(1);
  });

  it('a transaction hit by a serialization failure is retried once, as a whole', async () => {
    const f = flaky([sqlError('40001')]);
    await pgDeviceAuthStore(f.executor).replaceCredential({
      credentialId: 'p',
      accountId: 'a',
      type: 'pin',
      deviceId: null,
      material: {},
      createdAt: 0,
      updatedAt: 0,
      lastUsedAt: null,
    });
    expect(f.calls()).toBe(4); // one failed attempt, then a full transaction of three
  });

  it('the session store retries too', async () => {
    const f = flaky([sqlError('40001')]);
    await pgSessionStore(f.executor).revokeAllForUser('u');
    expect(f.calls()).toBe(2);
  });
});
