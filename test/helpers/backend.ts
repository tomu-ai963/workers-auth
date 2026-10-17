/**
 * Which database the device-auth suites run against: D1 (project "d1") or
 * Postgres through the Neon HTTP driver (project "pg"). Chosen by the
 * TEST_BACKEND binding in vitest.config.ts — never by whether Postgres
 * happens to be reachable: in the "pg" project an unreachable server fails
 * every test instead of quietly falling back to D1.
 */
import { neon, neonConfig } from '@neondatabase/serverless';
import { env } from 'cloudflare:test';

import { d1DeviceAuthStore, type D1DeviceAuthStoreOptions } from '../../src/device-auth/store.js';
import { d1SessionStore } from '../../src/store/d1.js';
import { pgDeviceAuthStore, pgSessionStore, type PgExecutor, type PgQueryResult } from '../../src/store/pg/index.js';
import type { Clock } from '../../src/types.js';

export type Backend = 'd1' | 'pg';
export const BACKEND: Backend = env.TEST_BACKEND === 'pg' ? 'pg' : 'd1';

function pgUrl(): string {
  if (!env.PG_URL) {
    throw new Error('TEST_BACKEND=pg but Postgres is not configured: run `pnpm pg:up` (test/pg/.env is missing)');
  }
  return env.PG_URL;
}

let neonClient: ReturnType<typeof neon<false, true>> | undefined;
function sql() {
  if (!neonClient) {
    neonConfig.fetchEndpoint = env.PG_HTTP_ENDPOINT;
    neonClient = neon(pgUrl(), { fullResults: true });
  }
  return neonClient;
}

/** The README's Neon HTTP adapter, verbatim apart from the local endpoint. */
export function neonExecutor(): PgExecutor {
  const s = sql();
  return {
    query: (text, params) => s.query(text, [...params]) as unknown as Promise<PgQueryResult<any>>,
    transaction: (statements) =>
      s.transaction(
        statements.map((st) => s.query(st.text, [...st.params])),
        { isolationLevel: 'ReadCommitted' },
      ) as unknown as Promise<PgQueryResult[]>,
  };
}

export function makeSessionStore(options: { clock?: Clock } = {}) {
  return BACKEND === 'pg' ? pgSessionStore(neonExecutor(), options) : d1SessionStore(env.DB, options);
}

export function makeDeviceStore(options: D1DeviceAuthStoreOptions = {}) {
  return BACKEND === 'pg' ? pgDeviceAuthStore(neonExecutor(), { clock: options.clock }) : d1DeviceAuthStore(env.DB, options);
}

// ---------------------------------------------------------------------------
// Direct SQL from the tests (assertions on rows, setting up odd states)
// ---------------------------------------------------------------------------

type Stmt = {
  bind(...args: unknown[]): Stmt;
  first<T = any>(column?: string): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  run(): Promise<{ meta: { changes: number } }>;
};

const INT8 = 20;
const NUMERIC = 1700;

/** pg's text results, with int8/numeric turned into numbers as D1 would return them. */
function toD1Row(row: Record<string, unknown>, fields: Array<{ name: string; dataTypeID: number }>) {
  const out: Record<string, unknown> = { ...row };
  for (const f of fields) {
    const v = out[f.name];
    if ((f.dataTypeID === INT8 || f.dataTypeID === NUMERIC) && typeof v === 'string') out[f.name] = Number(v);
  }
  return out;
}

function pgStmt(query: string, args: unknown[] = []): Stmt {
  // The tests write SQLite-style ?1; the SQL itself is portable.
  const text = query.replace(/\?(\d+)/g, '$$$1');
  const exec = async () => {
    const r = (await sql().query(text, args)) as unknown as {
      rows: Record<string, unknown>[];
      rowCount: number | null;
      fields: Array<{ name: string; dataTypeID: number }>;
    };
    return { rows: r.rows.map((row) => toD1Row(row, r.fields)), rowCount: r.rowCount ?? 0 };
  };
  return {
    bind: (...next) => pgStmt(query, next),
    async first<T>(column?: string) {
      const row = (await exec()).rows[0];
      if (!row) return null;
      return (column === undefined ? row : (row[column] ?? null)) as T;
    },
    async all<T>() {
      return { results: (await exec()).rows as T[] };
    },
    async run() {
      return { meta: { changes: (await exec()).rowCount } };
    },
  };
}

/** `env.DB` on D1; the same calling shape over Postgres on pg. */
export const db: { prepare(query: string): Stmt } = {
  prepare(query) {
    return BACKEND === 'pg' ? pgStmt(query) : (env.DB.prepare(query) as unknown as Stmt);
  },
};

export const AUTH_TABLES = [
  'auth_sessions',
  'auth_revocations',
  'auth_user_revocations',
  'auth_magic_link_tokens',
  'auth_api_keys',
  'auth_email_codes',
  'auth_trusted_devices',
  'auth_credentials',
  'auth_login_guards',
  'auth_rate_limits',
];

export async function resetDatabase(): Promise<void> {
  if (BACKEND === 'pg') {
    await sql().query(`TRUNCATE ${AUTH_TABLES.join(', ')}`);
  }
  // D1 is reset either way: some suites use D1-only stores (revocation list, magic links).
  await env.DB.batch(AUTH_TABLES.map((table) => env.DB.prepare(`DELETE FROM ${table}`)));
}
