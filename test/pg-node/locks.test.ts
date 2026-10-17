/**
 * Row-lock interleavings for the seven conditional statements of
 * pgDeviceAuthStore, on real Postgres connections.
 *
 * For each: connection A opens a transaction and UPDATEs (or DELETEs) the row
 * so that the statement's condition no longer holds — or holds with different
 * values — and keeps the row locked. Connection B, the store, runs the
 * statement, which must block on the lock (checked in pg_stat_activity, not
 * assumed). A commits; B must then decide on the row *as A left it*, not on
 * the version it saw when it started. That re-evaluation is what makes "check
 * the limit and move the counter" one decision under READ COMMITTED.
 *
 * Runs in its own database (workers_auth_locks) so it never shares rows with
 * the workerd "pg" project. Fails, rather than skips, without `pnpm pg:up`.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import pg from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { pgDeviceAuthStore, type PgExecutor } from '../../src/store/pg/index.js';

const NOW = 1_700_000_000_000;
const DAY = 86_400_000;
const LOCK_DB = 'workers_auth_locks';

function url(database: string): string {
  const base = process.env['WA_TEST_PG_URL'];
  if (!base) throw new Error('Postgres is not configured: run `pnpm pg:up` (test/pg/.env is missing)');
  const u = new URL(base);
  u.pathname = `/${database}`;
  return u.toString();
}

/** The README's adapter for a `pg` Client (Hyperdrive), verbatim. */
function clientExecutor(client: pg.Client): PgExecutor {
  return {
    query: (text, params) => client.query(text, [...params]),
    async transaction(statements) {
      await client.query('BEGIN');
      try {
        const results = [];
        for (const s of statements) results.push(await client.query(s.text, [...s.params]));
        await client.query('COMMIT');
        return results;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      }
    },
  };
}

let a: pg.Client; // holds the lock
let b: pg.Client; // runs the store
let monitor: pg.Client;
let bPid: number;
let store: ReturnType<typeof pgDeviceAuthStore>;

beforeAll(async () => {
  const admin = new pg.Client({ connectionString: url('workers_auth_test') });
  await admin.connect();
  const exists = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [LOCK_DB]);
  if (exists.rowCount === 0) await admin.query(`CREATE DATABASE ${LOCK_DB}`);
  await admin.end();

  [a, b, monitor] = [0, 1, 2].map(() => new pg.Client({ connectionString: url(LOCK_DB) })) as [pg.Client, pg.Client, pg.Client];
  await Promise.all([a.connect(), b.connect(), monitor.connect()]);
  const dir = join(process.cwd(), 'migrations', 'pg');
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.sql')).sort()) {
    await monitor.query(readFileSync(join(dir, name), 'utf8'));
  }
  bPid = (await b.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;
  store = pgDeviceAuthStore(clientExecutor(b), { clock: () => NOW });
});

afterAll(async () => {
  await Promise.all([a?.end(), b?.end(), monitor?.end()]);
});

beforeEach(async () => {
  await monitor.query('TRUNCATE auth_rate_limits, auth_login_guards, auth_email_codes, auth_trusted_devices');
});

/** Resolves once B is waiting on a lock — so the interleaving is real, not hoped for. */
async function blockedOnLock(): Promise<void> {
  for (let i = 0; i < 200; i++) {
    const r = await monitor.query<{ wait_event_type: string | null }>(
      'SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1',
      [bPid],
    );
    if (r.rows[0]?.wait_event_type === 'Lock') return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('B never blocked on the row lock');
}

/** A changes the row inside an open transaction; B runs; A commits; B's answer is returned. */
async function interleave<T>(change: string, params: unknown[], run: () => Promise<T>): Promise<T> {
  await a.query('BEGIN');
  const result = await a.query(change, params);
  expect(result.rowCount).toBe(1); // A really holds that row
  const pending = run();
  try {
    await blockedOnLock();
  } finally {
    await a.query('COMMIT');
  }
  return pending;
}

const one = async (sql: string, params: unknown[] = []) => (await monitor.query(sql, params)).rows[0] as Record<string, unknown>;

describe('reserveRateLimit', () => {
  beforeEach(async () => {
    await monitor.query(`INSERT INTO auth_rate_limits (bucket, window_start, count) VALUES ('b', $1, 9)`, [NOW]);
  });

  it('A fills the last slot: B, waiting at 9 of 10, is refused and the count stays 10', async () => {
    const r = await interleave(`UPDATE auth_rate_limits SET count = 10 WHERE bucket = 'b'`, [], () =>
      store.reserveRateLimit('b', DAY, NOW, 10),
    );
    expect(r).toBeNull();
    expect(await one(`SELECT count FROM auth_rate_limits WHERE bucket = 'b'`)).toEqual({ count: 10 });
  });

  it('A frees slots: B counts on from A’s value, not the one it first saw', async () => {
    const r = await interleave(`UPDATE auth_rate_limits SET count = 3 WHERE bucket = 'b'`, [], () =>
      store.reserveRateLimit('b', DAY, NOW, 10),
    );
    expect(r).toEqual({ count: 4, windowStart: NOW });
  });

  it('A moves the row into a lapsed window: B restarts it at 1 even though A left it at the cap', async () => {
    const r = await interleave(
      `UPDATE auth_rate_limits SET count = 10, window_start = $1 WHERE bucket = 'b'`,
      [NOW - 2 * DAY],
      () => store.reserveRateLimit('b', DAY, NOW, 10),
    );
    expect(r).toEqual({ count: 1, windowStart: NOW });
  });
});

describe('reserveLoginAttempt', () => {
  it('A reaches max: B, waiting at 2 of 3, is refused', async () => {
    await monitor.query(`INSERT INTO auth_login_guards (account_id, failed_count, locked_at, updated_at) VALUES ('acct', 2, NULL, 0)`);
    const r = await interleave(`UPDATE auth_login_guards SET failed_count = 3 WHERE account_id = 'acct'`, [], () =>
      store.reserveLoginAttempt('acct', 3, NOW),
    );
    expect(r).toBeNull();
    expect(await one(`SELECT failed_count FROM auth_login_guards`)).toEqual({ failed_count: 3 });
  });

  it('A locks the account below max: B is refused', async () => {
    await monitor.query(`INSERT INTO auth_login_guards (account_id, failed_count, locked_at, updated_at) VALUES ('acct', 0, NULL, 0)`);
    const r = await interleave(`UPDATE auth_login_guards SET locked_at = $1 WHERE account_id = 'acct'`, [NOW], () =>
      store.reserveLoginAttempt('acct', 3, NOW),
    );
    expect(r).toBeNull();
  });

  it('A resets the guard: B counts from 0', async () => {
    await monitor.query(`INSERT INTO auth_login_guards (account_id, failed_count, locked_at, updated_at) VALUES ('acct', 2, NULL, 0)`);
    const r = await interleave(`UPDATE auth_login_guards SET failed_count = 0 WHERE account_id = 'acct'`, [], () =>
      store.reserveLoginAttempt('acct', 3, NOW),
    );
    expect(r).toBe(1);
  });
});

describe('reserveEmailCodeAttempt', () => {
  beforeEach(async () => {
    await monitor.query(
      `INSERT INTO auth_email_codes (email, code_hash, key_id, attempts, attempts_reset_at, expires_at, created_at)
       VALUES ('e@example.com', 'h1', 'k', 4, $1, $1, $2)`,
      [NOW + 600_000, NOW],
    );
  });

  it('A uses the last attempt: B, waiting at 4 of 5, is refused', async () => {
    const r = await interleave(`UPDATE auth_email_codes SET attempts = 5`, [], () =>
      store.reserveEmailCodeAttempt('e@example.com', NOW, 5),
    );
    expect(r).toBeNull();
    expect(await one(`SELECT attempts FROM auth_email_codes`)).toEqual({ attempts: 5 });
  });

  it('A expires the code: B is refused', async () => {
    const r = await interleave(`UPDATE auth_email_codes SET expires_at = $1`, [NOW], () =>
      store.reserveEmailCodeAttempt('e@example.com', NOW, 5),
    );
    expect(r).toBeNull();
  });

  it('A replaces the code (resend, attempts reset): B reserves on the new one', async () => {
    const r = await interleave(`UPDATE auth_email_codes SET code_hash = 'h2', attempts = 0`, [], () =>
      store.reserveEmailCodeAttempt('e@example.com', NOW, 5),
    );
    expect(r).toEqual({ codeHash: 'h2', keyId: 'k', attempts: 1 });
  });
});

describe('refundRateLimit', () => {
  beforeEach(async () => {
    await monitor.query(`INSERT INTO auth_rate_limits (bucket, window_start, count) VALUES ('b', $1, 1)`, [NOW]);
  });

  it('A brings the count to 0: B’s refund does nothing (no -1)', async () => {
    await interleave(`UPDATE auth_rate_limits SET count = 0 WHERE bucket = 'b'`, [], () => store.refundRateLimit('b', NOW));
    expect(await one(`SELECT count FROM auth_rate_limits`)).toEqual({ count: 0 });
  });

  it('A starts a new window: B’s refund for the old window does not reach it', async () => {
    await interleave(`UPDATE auth_rate_limits SET window_start = $1, count = 1 WHERE bucket = 'b'`, [NOW + DAY], () =>
      store.refundRateLimit('b', NOW),
    );
    expect(await one(`SELECT count, window_start FROM auth_rate_limits`)).toEqual({ count: 1, window_start: String(NOW + DAY) });
  });
});

describe('consumeEmailCode', () => {
  beforeEach(async () => {
    await monitor.query(
      `INSERT INTO auth_email_codes (email, code_hash, key_id, attempts, attempts_reset_at, expires_at, created_at)
       VALUES ('e@example.com', 'h1', 'k', 1, $1, $1, $2)`,
      [NOW + 600_000, NOW],
    );
  });

  it('A consumes the code first: B gets false', async () => {
    const r = await interleave(`DELETE FROM auth_email_codes WHERE email = 'e@example.com'`, [], () =>
      store.consumeEmailCode('e@example.com', 'h1'),
    );
    expect(r).toBe(false);
  });

  it('A resends (new hash): B, matched against the old code, gets false and the new code survives', async () => {
    const r = await interleave(`UPDATE auth_email_codes SET code_hash = 'h2'`, [], () => store.consumeEmailCode('e@example.com', 'h1'));
    expect(r).toBe(false);
    expect(await one(`SELECT code_hash FROM auth_email_codes`)).toEqual({ code_hash: 'h2' });
  });
});

describe('touchDevice', () => {
  beforeEach(async () => {
    await monitor.query(
      `INSERT INTO auth_trusted_devices
         (device_id, account_id, email, secret_hash, label, created_at, last_used_at, idle_expires_at, absolute_expires_at, revoked_at)
       VALUES ('d1', 'acct', 'e@example.com', 'h', NULL, $1, $1, $2, $3, NULL)`,
      [NOW - DAY, NOW + DAY, NOW + 30 * DAY],
    );
  });

  it('A revokes the device: B’s touch is refused and does not extend it', async () => {
    const r = await interleave(`UPDATE auth_trusted_devices SET revoked_at = $1`, [NOW], () =>
      store.touchDevice('d1', NOW, NOW + 10 * DAY),
    );
    expect(r).toBeNull();
    expect(await one(`SELECT last_used_at, idle_expires_at FROM auth_trusted_devices`)).toEqual({
      last_used_at: String(NOW - DAY),
      idle_expires_at: String(NOW + DAY),
    });
  });

  it('A shortens the absolute expiry: B’s new idle expiry is capped by A’s value', async () => {
    const r = await interleave(`UPDATE auth_trusted_devices SET absolute_expires_at = $1`, [NOW + 2 * DAY], () =>
      store.touchDevice('d1', NOW, NOW + 10 * DAY),
    );
    expect(r).toBe(NOW + 2 * DAY);
  });
});

describe('lockAccount', () => {
  beforeEach(async () => {
    await monitor.query(`INSERT INTO auth_login_guards (account_id, failed_count, locked_at, updated_at) VALUES ('acct', 3, NULL, 0)`);
  });

  it('A resets the guard (a correct email code): B’s lock no longer applies', async () => {
    await interleave(`UPDATE auth_login_guards SET failed_count = 0 WHERE account_id = 'acct'`, [], () =>
      store.lockAccount('acct', 3, NOW),
    );
    expect(await one(`SELECT failed_count, locked_at FROM auth_login_guards`)).toEqual({ failed_count: 0, locked_at: null });
  });

  it('A locks first: B keeps A’s lock time', async () => {
    await interleave(`UPDATE auth_login_guards SET locked_at = $1 WHERE account_id = 'acct'`, [NOW - 5], () =>
      store.lockAccount('acct', 3, NOW),
    );
    expect(await one(`SELECT locked_at FROM auth_login_guards`)).toEqual({ locked_at: String(NOW - 5) });
  });
});
