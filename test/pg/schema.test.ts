/**
 * migrations/*.sql (D1) and migrations/pg/*.sql must describe the same tables:
 * same columns with the same nullability and primary keys, same indexes over
 * the same columns with the same uniqueness and partial-ness. Types are
 * compared by class: D1 TEXT ↔ text; D1 INTEGER ↔ bigint, except the counters,
 * which are integer on Postgres. A column or index added to one side only
 * fails here.
 */
import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

import { AUTH_TABLES, neonExecutor } from '../helpers/backend.js';

const COUNTERS = new Set(['attempts', 'failed_count', 'count', 'failures']);

type Column = { name: string; type: string; notNull: boolean; pk: number };
type Index = { name: string; unique: boolean; partial: boolean; columns: string[] };

async function d1Tables(): Promise<string[]> {
  const { results } = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'auth\\_%' ESCAPE '\\' ORDER BY name",
  ).all<{ name: string }>();
  return results.map((r) => r.name);
}

async function d1Columns(table: string): Promise<Column[]> {
  const { results } = await env.DB.prepare('SELECT name, type, "notnull" AS nn, pk FROM pragma_table_info(?1) ORDER BY cid')
    .bind(table)
    .all<{ name: string; type: string; nn: number; pk: number }>();
  return results.map((c) => ({
    name: c.name,
    type: c.type === 'TEXT' ? 'text' : c.type === 'INTEGER' ? (COUNTERS.has(c.name) ? 'integer' : 'bigint') : `?${c.type}`,
    // SQLite does not imply NOT NULL for a TEXT PRIMARY KEY; Postgres does.
    notNull: c.nn === 1 || c.pk > 0,
    pk: c.pk,
  }));
}

async function d1Indexes(table: string): Promise<Index[]> {
  const { results } = await env.DB.prepare('SELECT name, "unique" AS u, partial FROM pragma_index_list(?1)')
    .bind(table)
    .all<{ name: string; u: number; partial: number }>();
  const out: Index[] = [];
  for (const idx of results.filter((i) => !i.name.startsWith('sqlite_autoindex_'))) {
    const cols = await env.DB.prepare('SELECT name FROM pragma_index_info(?1) ORDER BY seqno').bind(idx.name).all<{ name: string }>();
    out.push({ name: idx.name, unique: idx.u === 1, partial: idx.partial === 1, columns: cols.results.map((c) => c.name) });
  }
  return out.sort((x, y) => x.name.localeCompare(y.name));
}

const pg = () => neonExecutor();

async function pgTables(): Promise<string[]> {
  const { rows } = await pg().query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
      WHERE table_schema = 'public' AND table_name LIKE 'auth\\_%' ORDER BY table_name`,
    [],
  );
  return rows.map((r) => r.table_name);
}

async function pgColumns(table: string): Promise<Column[]> {
  const { rows } = await pg().query<{ column_name: string; data_type: string; is_nullable: string; pk: unknown }>(
    `SELECT c.column_name, c.data_type, c.is_nullable,
            COALESCE((SELECT k.ordinal_position
                        FROM information_schema.table_constraints t
                        JOIN information_schema.key_column_usage k
                          ON k.constraint_name = t.constraint_name AND k.table_schema = t.table_schema
                       WHERE t.table_schema = 'public' AND t.table_name = c.table_name
                         AND t.constraint_type = 'PRIMARY KEY' AND k.column_name = c.column_name), 0) AS pk
       FROM information_schema.columns c
      WHERE c.table_schema = 'public' AND c.table_name = $1
      ORDER BY c.ordinal_position`,
    [table],
  );
  return rows.map((c) => ({ name: c.column_name, type: c.data_type, notNull: c.is_nullable === 'NO', pk: Number(c.pk) }));
}

async function pgIndexes(table: string): Promise<Index[]> {
  const { rows } = await pg().query<{ name: string; unique: boolean; partial: boolean; columns: string[] }>(
    `SELECT i.relname AS name, x.indisunique AS unique, x.indpred IS NOT NULL AS partial,
            ARRAY(SELECT a.attname FROM unnest(x.indkey) WITH ORDINALITY AS k(attnum, ord)
                    JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = k.attnum
                   ORDER BY k.ord)::text[] AS columns
       FROM pg_index x
       JOIN pg_class i ON i.oid = x.indexrelid
       JOIN pg_class t ON t.oid = x.indrelid
       JOIN pg_namespace n ON n.oid = t.relnamespace
      WHERE n.nspname = 'public' AND t.relname = $1 AND NOT x.indisprimary`,
    [table],
  );
  return rows.map((r) => ({ name: r.name, unique: r.unique, partial: r.partial, columns: r.columns })).sort((x, y) => x.name.localeCompare(y.name));
}

describe('D1 and Postgres migrations describe the same schema', () => {
  it('the same auth_* tables exist on both, and the test reset covers all of them', async () => {
    const [d1, pgt] = await Promise.all([d1Tables(), pgTables()]);
    expect(pgt).toEqual(d1);
    expect([...AUTH_TABLES].sort()).toEqual(d1);
  });

  it.each(AUTH_TABLES)('%s: same columns, types (by class), nullability and primary key', async (table) => {
    expect(await pgColumns(table)).toEqual(await d1Columns(table));
  });

  it.each(AUTH_TABLES)('%s: same indexes over the same columns', async (table) => {
    expect(await pgIndexes(table)).toEqual(await d1Indexes(table));
  });

  it('every time column is bigint on Postgres (epoch milliseconds overflow integer)', async () => {
    for (const table of AUTH_TABLES) {
      for (const c of await pgColumns(table)) {
        if (/_at$/.test(c.name) || c.name === 'window_start') expect([table, c.name, c.type]).toEqual([table, c.name, 'bigint']);
      }
    }
  });
});
