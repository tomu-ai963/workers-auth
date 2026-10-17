/**
 * Real Postgres connections for the interleaving tests: A holds locks inside
 * an open transaction, B runs the store, the monitor watches B in
 * pg_stat_activity. Own database (workers_auth_locks), so nothing here shares
 * rows with the workerd "pg" project. Throws — never skips — without
 * `pnpm pg:up`.
 */
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import pg from 'pg';
import { expect } from 'vitest';

import type { PgExecutor } from '../../src/store/pg/index.js';

export const NOW = 1_700_000_000_000;
export const DAY = 86_400_000;
const LOCK_DB = 'workers_auth_locks';

function url(database: string): string {
  const base = process.env['WA_TEST_PG_URL'];
  if (!base) throw new Error('Postgres is not configured: run `pnpm pg:up` (test/pg/.env is missing)');
  const u = new URL(base);
  u.pathname = `/${database}`;
  return u.toString();
}

/** pg reports `rowCount: null` for commands without a count; the stores need a number. */
function counted<R extends pg.QueryResultRow>(r: pg.QueryResult<R>) {
  if (r.rowCount === null) throw new Error(`pg: no row count for ${r.command}`);
  return { rows: r.rows, rowCount: r.rowCount };
}

/** The README's adapter for a `pg` Client (Hyperdrive), verbatim. */
export function clientExecutor(client: pg.Client): PgExecutor {
  return {
    query: async (text, params) => counted(await client.query(text, [...params])),
    async transaction(statements) {
      await client.query('BEGIN');
      try {
        const results = [];
        for (const s of statements) results.push(counted(await client.query(s.text, [...s.params])));
        await client.query('COMMIT');
        return results;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      }
    },
  };
}

export type Connections = { a: pg.Client; b: pg.Client; monitor: pg.Client; bPid: number };

export async function connect(): Promise<Connections> {
  const admin = new pg.Client({ connectionString: url('workers_auth_test') });
  await admin.connect();
  const exists = await admin.query('SELECT 1 FROM pg_database WHERE datname = $1', [LOCK_DB]);
  if (exists.rowCount === 0) await admin.query(`CREATE DATABASE ${LOCK_DB}`);
  await admin.end();

  const [a, b, monitor] = [0, 1, 2].map(() => new pg.Client({ connectionString: url(LOCK_DB) })) as [pg.Client, pg.Client, pg.Client];
  await Promise.all([a.connect(), b.connect(), monitor.connect()]);
  const dir = join(process.cwd(), 'migrations', 'pg');
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.sql')).sort()) {
    await monitor.query(readFileSync(join(dir, name), 'utf8'));
  }
  const bPid = (await b.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).rows[0]!.pid;
  return { a, b, monitor, bPid };
}

export async function disconnect(c: Connections | undefined): Promise<void> {
  await Promise.all([c?.a.end(), c?.b.end(), c?.monitor.end()]);
}

/** Resolves once B is waiting on a lock — so the interleaving is real, not hoped for. */
export async function blockedOnLock(c: Connections): Promise<void> {
  for (let i = 0; i < 200; i++) {
    const r = await c.monitor.query<{ wait_event_type: string | null }>(
      'SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1',
      [c.bPid],
    );
    if (r.rows[0]?.wait_event_type === 'Lock') return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error('B never blocked on a lock');
}

/**
 * A runs `statements` inside an open transaction (so it holds their locks), B
 * runs `run()`, which must block; then A commits and B's outcome is returned
 * (or its error rethrown).
 */
export async function interleave<T>(
  c: Connections,
  statements: Array<{ text: string; params?: unknown[]; rowCount?: number }>,
  run: () => Promise<T>,
): Promise<T> {
  await c.a.query('BEGIN');
  for (const s of statements) {
    const result = await c.a.query(s.text, s.params ?? []);
    if (s.rowCount !== undefined) expect(result.rowCount).toBe(s.rowCount); // A really holds that row
  }
  const pending = run();
  pending.catch(() => {}); // observed below, after A commits
  try {
    await blockedOnLock(c);
  } finally {
    await c.a.query('COMMIT');
  }
  return pending;
}
