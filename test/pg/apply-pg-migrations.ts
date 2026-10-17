// pg project: applies migrations/pg/*.sql (idempotent: CREATE … IF NOT EXISTS).
// Fails — rather than skips — when Postgres is not configured or not reachable.
import { env } from 'cloudflare:test';

import { rawRows, rawSql } from '../helpers/backend.js';
import { assertOnlyAuthTables } from '../neon/guard.js';

// Against real Neon: refuse to touch a database holding anything but auth_*
// tables — before any CREATE here, and before any test's TRUNCATE.
if (env.PG_GUARD === 'only-auth-tables') {
  await assertOnlyAuthTables((text) => rawRows(text) as Promise<Array<{ name: unknown }>>, 'workerd setup');
}

for (const migration of env.PG_MIGRATIONS) {
  const statements = migration.sql
    .split(/\r?\n/)
    .map((line) => line.replace(/--.*$/, ''))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const statement of statements) await rawSql(statement);
}
