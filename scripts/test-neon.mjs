#!/usr/bin/env node
/**
 * Runs the Postgres suites against the real Neon test project.
 *
 *   pnpm test:neon                 everything (projects "neon" and "neon-node")
 *   pnpm test:neon -- <filters>    passed on to vitest
 *
 * Only this script targets Neon: it sets WA_TEST_TARGET=neon, which is what
 * makes vitest.config.ts define the neon projects; plain `pnpm test` never
 * reads test/pg/.env.neon. Before vitest starts, the guard (test/neon/guard.ts)
 * checks over Neon HTTP that the database holds nothing but auth_* tables, and
 * aborts otherwise. The connection string is read from test/pg/.env.neon
 * (gitignored) and never printed.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { neon } from '@neondatabase/serverless';

import { assertOnlyAuthTables } from '../test/neon/guard.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const envFile = join(root, 'test', 'pg', '.env.neon');

if (!existsSync(envFile)) {
  console.error('test/pg/.env.neon is missing (NEON_TEST_DATABASE_URL=...)');
  process.exit(2);
}
const match = /^NEON_TEST_DATABASE_URL=(.+)$/m.exec(readFileSync(envFile, 'utf8'));
const url = match?.[1]?.trim();
if (!url || !url.startsWith('postgresql://') || new URL(url).hostname.includes('-pooler')) {
  console.error('test/pg/.env.neon must hold one direct (non-pooler) postgresql:// URL as NEON_TEST_DATABASE_URL');
  process.exit(2);
}

const sql = neon(url, { fullResults: true });
try {
  await assertOnlyAuthTables(async (text) => (await sql.query(text, [])).rows, 'pre-flight');
} catch (error) {
  console.error(error instanceof Error ? error.message : 'neon guard failed');
  process.exit(3);
}
console.log('[neon guard] only auth_* tables (or none) in the target database: proceeding');

const r = spawnSync('npx', ['vitest', 'run', '--project', 'neon', '--project', 'neon-node', ...process.argv.slice(2)], {
  stdio: 'inherit',
  shell: process.platform === 'win32',
  env: { ...process.env, WA_TEST_TARGET: 'neon', NEON_TEST_DATABASE_URL: url },
});
process.exit(r.status ?? 1);
