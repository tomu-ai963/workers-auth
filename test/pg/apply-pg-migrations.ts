// pg project: applies migrations/pg/*.sql (idempotent: CREATE … IF NOT EXISTS).
// Fails — rather than skips — when Postgres is not configured or not reachable.
import { env } from 'cloudflare:test';

import { neonExecutor } from '../helpers/backend.js';

const executor = neonExecutor();
for (const migration of env.PG_MIGRATIONS) {
  const statements = migration.sql
    .split(/\r?\n/)
    .map((line) => line.replace(/--.*$/, ''))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);
  for (const statement of statements) await executor.query(statement, []);
}
