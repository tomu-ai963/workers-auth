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
import type { Clock, WaitUntilContext } from '../../src/types.js';
import { deleteGate } from './defer.js';

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
    // Local runs go through the Neon HTTP proxy; against real Neon (PG_HTTP_ENDPOINT
    // empty) the driver derives the endpoint from the URL's host as in production.
    if (env.PG_HTTP_ENDPOINT) neonConfig.fetchEndpoint = env.PG_HTTP_ENDPOINT;
    neonClient = neon(pgUrl(), { fullResults: true });
  }
  return neonClient;
}

/** Raw driver access for test plumbing (DDL has no row count, so it bypasses the adapter). */
export async function rawSql(text: string): Promise<void> {
  await sql().query(text, []);
}

export async function rawRows(text: string): Promise<Array<Record<string, unknown>>> {
  return ((await sql().query(text, [])) as unknown as { rows: Array<Record<string, unknown>> }).rows;
}

/** A result with a numeric rowCount, or an error — never a null passed through as "0 rows". */
function counted(r: { rows: Record<string, unknown>[]; rowCount: number | null }): PgQueryResult<any> {
  if (typeof r.rowCount !== 'number') throw new Error('neon: no row count in the result');
  return { rows: r.rows, rowCount: r.rowCount };
}

/** The README's Neon HTTP adapter, verbatim apart from the local endpoint. */
export function neonExecutor(): PgExecutor {
  const s = sql();
  return {
    query: async (text, params) => counted(await s.query(text, [...params])),
    transaction: async (statements) =>
      (
        await s.transaction(
          statements.map((st) => s.query(st.text, [...st.params])),
          { isolationLevel: 'ReadCommitted' },
        )
      ).map(counted),
  };
}

export function makeSessionStore(
  options: { clock?: Clock; executor?: PgExecutor; db?: D1Database; executionCtx?: WaitUntilContext } = {},
) {
  const { clock, executionCtx } = options;
  return BACKEND === 'pg'
    ? pgSessionStore(options.executor ?? neonExecutor(), { clock, executionCtx })
    : d1SessionStore(options.db ?? env.DB, { clock, executionCtx });
}

/**
 * A session store whose `DELETE` statements wait on the returned gate (see
 * `deleteGate()`); every other statement runs straight through.
 */
export function gatedSessionStore(options: { clock?: Clock; executionCtx?: WaitUntilContext } = {}) {
  const gate = deleteGate();
  const isDelete = (text: string) => /^\s*DELETE\b/i.test(text);
  if (BACKEND === 'pg') {
    const inner = neonExecutor();
    const executor: PgExecutor = {
      query: (text, params) => (isDelete(text) ? gate.hold(() => inner.query(text, params)) : inner.query(text, params)),
      transaction: (statements) => inner.transaction(statements),
    };
    return { gate, store: makeSessionStore({ ...options, executor }) };
  }
  const real = env.DB;
  const db = {
    prepare(query: string) {
      const stmt = real.prepare(query);
      if (!isDelete(query)) return stmt;
      return {
        bind: (...args: unknown[]) => ({ run: () => gate.hold(() => stmt.bind(...args).run()) }),
      };
    },
    batch: (statements: D1PreparedStatement[]) => real.batch(statements),
  } as unknown as D1Database;
  return { gate, store: makeSessionStore({ ...options, db }) };
}

export function makeDeviceStore(options: D1DeviceAuthStoreOptions & { executor?: PgExecutor } = {}) {
  return BACKEND === 'pg'
    ? pgDeviceAuthStore(options.executor ?? neonExecutor(), { clock: options.clock })
    : d1DeviceAuthStore(env.DB, options);
}

/** An executor whose driver reports no row counts — what a careless adapter might return. */
export function nullRowCount(executor: PgExecutor): PgExecutor {
  const strip = (r: PgQueryResult) => ({ ...r, rowCount: null as unknown as number });
  return {
    query: async (text, params) => strip(await executor.query(text, params)) as never,
    transaction: async (statements) => (await executor.transaction(statements)).map(strip),
  };
}

/**
 * Makes every UPDATE that revokes a trusted device fail inside the database —
 * the statement errors, so whatever transaction or batch it is part of rolls
 * back. Returns the function that removes it again.
 */
export async function failDeviceRevocation(): Promise<() => Promise<void>> {
  if (BACKEND === 'pg') {
    await sql().query(
      `CREATE OR REPLACE FUNCTION wa_test_fail_revoke() RETURNS trigger LANGUAGE plpgsql AS
       $$ BEGIN RAISE EXCEPTION 'injected: device revocation fails'; END $$`,
    );
    await sql().query(
      `CREATE TRIGGER wa_test_fail_revoke BEFORE UPDATE ON auth_trusted_devices FOR EACH ROW
       WHEN (NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL) EXECUTE FUNCTION wa_test_fail_revoke()`,
    );
    return async () => {
      await sql().query('DROP TRIGGER IF EXISTS wa_test_fail_revoke ON auth_trusted_devices');
    };
  }
  await env.DB.prepare(
    `CREATE TRIGGER wa_test_fail_revoke BEFORE UPDATE OF revoked_at ON auth_trusted_devices
     WHEN NEW.revoked_at IS NOT NULL AND OLD.revoked_at IS NULL
     BEGIN SELECT RAISE(ABORT, 'injected: device revocation fails'); END`,
  ).run();
  return async () => {
    await env.DB.prepare('DROP TRIGGER IF EXISTS wa_test_fail_revoke').run();
  };
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
