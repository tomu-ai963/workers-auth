/**
 * The `schema` option: interpolated into SQL as an identifier, so it is
 * validated when the store is built, and a valid one really routes every
 * statement to that schema.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { pgDeviceAuthStore, pgSessionStore, type PgExecutor } from '../../src/store/pg/index.js';
import { clientExecutor, connect, disconnect, NOW, type Connections } from './harness.js';

const neverCalled: PgExecutor = {
  query: () => {
    throw new Error('no query may run for an invalid schema');
  },
  transaction: () => {
    throw new Error('no query may run for an invalid schema');
  },
};

const INVALID: unknown[] = [
  '',
  'Public',
  'WORKERS_AUTH',
  '1schema',
  'workers-auth',
  'workers auth',
  ' public',
  'public ',
  'public.auth',
  '"public"',
  'public;DROP TABLE auth_sessions',
  "public'--",
  'päblic',
  'a'.repeat(64),
  'public\n',
  null,
  123,
  {},
];

describe('schema option validation', () => {
  it.each(INVALID.map((v) => [JSON.stringify(v) ?? String(v), v]))('refuses %s at construction, for both stores', (_label, value) => {
    expect(() => pgSessionStore(neverCalled, { schema: value as string })).toThrow(/pgSessionStore: schema: must match/);
    expect(() => pgDeviceAuthStore(neverCalled, { schema: value as string })).toThrow(/pgDeviceAuthStore: schema: must match/);
  });

  it.each(['public', 'workers_auth', '_x', 'a1_b2', 'a'.repeat(63)])('accepts %s', (value) => {
    expect(() => pgSessionStore(neverCalled, { schema: value })).not.toThrow();
    expect(() => pgDeviceAuthStore(neverCalled, { schema: value })).not.toThrow();
  });

  it('defaults to public', async () => {
    const seen: string[] = [];
    const recording: PgExecutor = {
      query: async (text) => {
        seen.push(text);
        return { rows: [], rowCount: 0 };
      },
      transaction: async (statements) => {
        seen.push(...statements.map((s) => s.text));
        return statements.map(() => ({ rows: [], rowCount: 0 }));
      },
    };
    await pgSessionStore(recording).revokeAllForUser('u');
    await pgDeviceAuthStore(recording).readLoginGuard('a');
    expect(seen.join('\n')).toMatch(/public\.auth_sessions[\s\S]*public\.auth_login_guards/);
  });
});

describe('schema option in use', () => {
  let c: Connections;

  beforeAll(async () => {
    c = await connect();
    await c.monitor.query('DROP SCHEMA IF EXISTS wa_custom CASCADE');
    await c.monitor.query('CREATE SCHEMA wa_custom');
    // The migration files have unqualified names: applied with a search path, as the README says.
    const { readFileSync, readdirSync } = await import('node:fs');
    const { join } = await import('node:path');
    const dir = join(process.cwd(), 'migrations', 'pg');
    await c.monitor.query('SET search_path TO wa_custom');
    for (const name of readdirSync(dir).filter((n) => n.endsWith('.sql')).sort()) {
      await c.monitor.query(readFileSync(join(dir, name), 'utf8'));
    }
    await c.monitor.query('SET search_path TO public');
    await c.monitor.query('TRUNCATE public.auth_sessions, public.auth_login_guards, public.auth_credentials');
  });

  afterAll(async () => {
    await c?.monitor.query('DROP SCHEMA IF EXISTS wa_custom CASCADE');
    await disconnect(c);
  });

  it('every statement of both stores lands in that schema and none in public', async () => {
    const executor = clientExecutor(c.b);
    const sessions = pgSessionStore(executor, { schema: 'wa_custom', clock: () => NOW });
    const devices = pgDeviceAuthStore(executor, { schema: 'wa_custom', clock: () => NOW });

    const s = await sessions.create({ userId: 'u1', subjectType: 'user', idleTtlSec: 60, absoluteTtlSec: 60 });
    expect(await sessions.get(s.sid)).toMatchObject({ userId: 'u1' });
    expect(await devices.reserveLoginAttempt('acct', 3, NOW)).toBe(1);
    expect(await devices.resetLoginGuard('acct', NOW)).toEqual({ failedCount: 1, lockedAt: null });
    await devices.replaceCredential({
      credentialId: 'p1',
      accountId: 'acct',
      type: 'pin',
      deviceId: null,
      material: {},
      createdAt: NOW,
      updatedAt: NOW,
      lastUsedAt: null,
    });
    expect(await devices.reserveRateLimit('b', 1000, NOW, 1)).toEqual({ count: 1, windowStart: NOW });

    const count = async (table: string) =>
      Number((await c.monitor.query<{ n: string }>(`SELECT COUNT(*) AS n FROM ${table}`)).rows[0]!.n);
    expect(await count('wa_custom.auth_sessions')).toBe(1);
    expect(await count('wa_custom.auth_login_guards')).toBe(1);
    expect(await count('wa_custom.auth_credentials')).toBe(1);
    expect(await count('wa_custom.auth_rate_limits')).toBe(1);
    expect(await count('public.auth_sessions')).toBe(0);
    expect(await count('public.auth_login_guards')).toBe(0);
    expect(await count('public.auth_credentials')).toBe(0);
  });
});
