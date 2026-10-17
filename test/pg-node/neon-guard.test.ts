/**
 * The Neon safety catch (test/neon/guard.ts), exercised on the local server:
 * a database holding anything but auth_* tables must be refused before any
 * test touches it.
 */
import pg from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { assertOnlyAuthTables, FOREIGN_TABLES_SQL } from '../neon/guard.js';
import { connect, disconnect, type Connections } from './harness.js';

let c: Connections;
const query = async (text: string) => (await c.monitor.query<{ name: unknown }>(text)).rows;

beforeAll(async () => {
  c = await connect();
});

afterAll(async () => {
  await c?.monitor.query('DROP TABLE IF EXISTS public.app_users, public.auth_users_backup_view_src');
  await c?.monitor.query('DROP VIEW IF EXISTS public.app_view');
  await c?.monitor.query('DROP SCHEMA IF EXISTS app_schema CASCADE');
  await disconnect(c);
});

describe.skipIf(process.env['WA_TEST_PG_TARGET'] === 'neon')('neon guard', () => {
  it('passes a database holding only auth_* tables', async () => {
    await expect(assertOnlyAuthTables(query, 'test')).resolves.toBeUndefined();
  });

  it('refuses an app table in public, naming it but nothing else', async () => {
    await c.monitor.query('CREATE TABLE public.app_users (id int)');
    try {
      const error = await assertOnlyAuthTables(query, 'test').then(() => null, (e: Error) => e);
      expect(error?.message).toMatch(/tables other than auth_\* \(public\.app_users\)/);
      expect(error?.message).toMatch(/Nothing was truncated or created/);
    } finally {
      await c.monitor.query('DROP TABLE public.app_users');
    }
  });

  it('refuses a view, and a table in another schema even if its name is not auth_*', async () => {
    await c.monitor.query('CREATE VIEW public.app_view AS SELECT 1 AS x');
    await c.monitor.query('CREATE SCHEMA app_schema');
    await c.monitor.query('CREATE TABLE app_schema.orders (id int)');
    try {
      const rows = (await query(FOREIGN_TABLES_SQL)).map((r) => r.name);
      expect(rows).toEqual(['app_schema.orders', 'public.app_view']);
      await expect(assertOnlyAuthTables(query, 'test')).rejects.toThrow(/app_schema\.orders, public\.app_view/);
    } finally {
      await c.monitor.query('DROP VIEW public.app_view');
      await c.monitor.query('DROP SCHEMA app_schema CASCADE');
    }
  });

  it('a name that merely contains "auth" is not exempt', async () => {
    await c.monitor.query('CREATE TABLE public.myauth_users (id int)');
    try {
      await expect(assertOnlyAuthTables(query, 'test')).rejects.toThrow(/public\.myauth_users/);
    } finally {
      await c.monitor.query('DROP TABLE public.myauth_users');
    }
  });

  it('the guard SQL is read-only', () => {
    expect(FOREIGN_TABLES_SQL.trim()).toMatch(/^SELECT\b/);
    expect(FOREIGN_TABLES_SQL).not.toMatch(/\b(INSERT|UPDATE|DELETE|TRUNCATE|CREATE|DROP|ALTER)\b/i);
    void pg;
  });
});
