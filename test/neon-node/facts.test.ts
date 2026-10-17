/**
 * What the Postgres stores assume of the database and of Neon's HTTP endpoint,
 * checked against the real Neon test project (pnpm test:neon only):
 *
 *   - default isolation is READ COMMITTED; the server is PostgreSQL >= 14
 *   - errors raised over HTTP carry the SQLSTATE in `code`, for the three the
 *     stores care about (40001 / 40P01 are retried once, 23505 must surface) —
 *     each provoked for real, with a direct TCP connection holding the locks
 *   - sql.transaction with fullResults returns a numeric rowCount per statement
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { neon } from '@neondatabase/serverless';
import pg from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { assertOnlyAuthTables } from '../neon/guard.js';

const url = process.env['WA_TEST_PG_URL'] ?? '';
if (process.env['WA_TEST_PG_TARGET'] !== 'neon' || !url) throw new Error('run with pnpm test:neon');

const sql = neon(url, { fullResults: true });
let a: pg.Client;
let monitor: pg.Client;
let aPid: number;

beforeAll(async () => {
  [a, monitor] = [new pg.Client({ connectionString: url }), new pg.Client({ connectionString: url })];
  await Promise.all([a.connect(), monitor.connect()]);
  await assertOnlyAuthTables(async (text) => (await monitor.query<{ name: unknown }>(text)).rows, 'facts');
  const dir = join(process.cwd(), 'migrations', 'pg');
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.sql')).sort()) {
    await monitor.query(readFileSync(join(dir, name), 'utf8'));
  }
  aPid = (await a.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;
});

afterAll(async () => {
  await Promise.all([a?.end(), monitor?.end()]);
});

beforeEach(async () => {
  await monitor.query(`DELETE FROM auth_rate_limits WHERE bucket LIKE 'neon-facts:%'`);
  await monitor.query(
    `INSERT INTO auth_rate_limits (bucket, window_start, count) VALUES ('neon-facts:r1', 0, 0), ('neon-facts:r2', 0, 0)`,
  );
});

/** Resolves once some other session of this database waits on a lock (the HTTP request's). */
async function someoneBlocked(): Promise<void> {
  for (let i = 0; i < 500; i++) {
    const r = await monitor.query(
      `SELECT 1 FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock' AND pid <> $1 AND pid <> pg_backend_pid()`,
      [aPid],
    );
    if (r.rowCount) return;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error('the HTTP transaction never blocked');
}

const codeOf = (p: Promise<unknown>) =>
  p.then(
    () => 'no error',
    (e: { code?: unknown }) => e?.code,
  );

describe('database settings', () => {
  it('default_transaction_isolation is read committed (HTTP and TCP)', async () => {
    const http = (await sql.query('SHOW default_transaction_isolation', [])).rows[0];
    const tcp = (await monitor.query('SHOW default_transaction_isolation')).rows[0];
    console.log('[neon] default_transaction_isolation:', JSON.stringify(http), '(tcp:', JSON.stringify(tcp), ')');
    expect(http).toEqual({ default_transaction_isolation: 'read committed' });
    expect(tcp).toEqual({ default_transaction_isolation: 'read committed' });
  });

  it('version() is PostgreSQL 14 or later', async () => {
    const r = (await sql.query('SELECT version() AS v, current_setting($1)::int AS n', ['server_version_num'])).rows[0] as {
      v: string;
      n: number;
    };
    console.log('[neon] version():', r.v);
    expect(r.n).toBeGreaterThanOrEqual(140000);
  });
});

describe('errors over Neon HTTP carry their SQLSTATE', () => {
  it('23505 unique violation', async () => {
    expect(
      await codeOf(sql.query(`INSERT INTO auth_rate_limits (bucket, window_start, count) VALUES ('neon-facts:r1', 0, 0)`, [])),
    ).toBe('23505');
  });

  it('40001 serialization failure (REPEATABLE READ update after a concurrent commit)', async () => {
    await a.query('BEGIN');
    await a.query(`UPDATE auth_rate_limits SET count = count + 1 WHERE bucket = 'neon-facts:r1'`);
    const pending = codeOf(
      sql.transaction([sql.query(`UPDATE auth_rate_limits SET count = count + 1 WHERE bucket = 'neon-facts:r1'`, [])], {
        isolationLevel: 'RepeatableRead',
      }),
    );
    try {
      await someoneBlocked();
    } finally {
      await a.query('COMMIT');
    }
    expect(await pending).toBe('40001');
  });

  it('40P01 deadlock', async () => {
    await a.query('BEGIN');
    await a.query(`UPDATE auth_rate_limits SET count = count + 1 WHERE bucket = 'neon-facts:r1'`);
    // HTTP side: locks r2, then waits for r1 (held by A).
    const pending = codeOf(
      sql.transaction([
        sql.query(`UPDATE auth_rate_limits SET count = count + 1 WHERE bucket = 'neon-facts:r2'`, []),
        sql.query(`UPDATE auth_rate_limits SET count = count + 1 WHERE bucket = 'neon-facts:r1'`, []),
      ]),
    );
    await someoneBlocked();
    // A now waits for r2: a cycle. The HTTP side has waited longer, so its
    // deadlock check (deadlock_timeout after it began waiting) fires first.
    const aSide = codeOf(a.query(`UPDATE auth_rate_limits SET count = count + 1 WHERE bucket = 'neon-facts:r2'`));
    const httpCode = await pending;
    const aCode = await aSide;
    await a.query(aCode === 'no error' ? 'COMMIT' : 'ROLLBACK');
    console.log('[neon] deadlock: http side ->', httpCode, '| tcp side ->', aCode);
    expect([httpCode, aCode]).toContain('40P01');
    expect(httpCode).toBe('40P01');
  });
});

describe('sql.transaction results', () => {
  it('fullResults gives a numeric rowCount for every statement', async () => {
    const results = await sql.transaction(
      [
        sql.query(`INSERT INTO auth_rate_limits (bucket, window_start, count) VALUES ('neon-facts:r3', 0, 0)`, []),
        sql.query(`UPDATE auth_rate_limits SET count = 5 WHERE bucket LIKE 'neon-facts:%'`, []),
        sql.query(`SELECT bucket FROM auth_rate_limits WHERE bucket LIKE 'neon-facts:%' ORDER BY bucket`, []),
        sql.query(`DELETE FROM auth_rate_limits WHERE bucket = 'neon-facts:r3' RETURNING bucket`, []),
        sql.query(`UPDATE auth_rate_limits SET count = 0 WHERE bucket = 'no-such-bucket'`, []),
      ],
      { isolationLevel: 'ReadCommitted' },
    );
    const counts = results.map((r) => (r as { rowCount: unknown }).rowCount);
    console.log('[neon] transaction rowCounts:', JSON.stringify(counts));
    expect(counts).toEqual([1, 3, 3, 1, 0]);
  });
});
