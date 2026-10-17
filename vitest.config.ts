import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const root = (path: string) => fileURLToPath(new URL(path, import.meta.url));

const migrations = await readD1Migrations(root('./migrations'));
const pgMigrations = readdirSync(root('./migrations/pg'))
  .filter((name) => name.endsWith('.sql'))
  .sort()
  .map((name) => ({ name, sql: readFileSync(root(`./migrations/pg/${name}`), 'utf8') }));

// test/pg/.env is written by `pnpm pg:up` (random password, gitignored). Without
// it PG_URL stays empty and every test in the pg projects fails with a message
// saying so — they are never skipped.
try {
  process.loadEnvFile(root('./test/pg/.env'));
} catch {
  // not started
}
const pgPassword = process.env['WA_TEST_PG_PASSWORD'];
const PG_URL = pgPassword ? `postgres://postgres:${pgPassword}@127.0.0.1:55436/workers_auth_test` : '';
const PG_HTTP_ENDPOINT = 'http://127.0.0.1:55446/sql';

// Real Neon (test project) — only when scripts/test-neon.mjs set WA_TEST_TARGET,
// after its guard passed. The URL arrives in the environment, never from a file
// read here, and an empty PG_HTTP_ENDPOINT means the driver's real endpoint.
const NEON = process.env['WA_TEST_TARGET'] === 'neon';
const NEON_URL = process.env['NEON_TEST_DATABASE_URL'] ?? '';
if (NEON && !NEON_URL) throw new Error('WA_TEST_TARGET=neon needs NEON_TEST_DATABASE_URL (run `pnpm test:neon`)');

/** The suites that run against both databases. */
const BOTH = ['test/device-auth-*.test.ts', 'test/store-contract.test.ts'];

function workerd(backend: 'd1' | 'pg' | 'neon') {
  return cloudflareTest({
    singleWorker: true,
    miniflare: {
      compatibilityDate: '2025-04-01',
      kvNamespaces: ['KV'],
      d1Databases: ['DB'],
      bindings: {
        TEST_MIGRATIONS: migrations,
        TEST_BACKEND: backend === 'd1' ? 'd1' : 'pg',
        PG_URL: backend === 'pg' ? PG_URL : backend === 'neon' ? NEON_URL : '',
        PG_HTTP_ENDPOINT: backend === 'neon' ? '' : PG_HTTP_ENDPOINT,
        PG_GUARD: backend === 'neon' ? 'only-auth-tables' : '',
        PG_MIGRATIONS: pgMigrations,
      },
    },
  });
}

/** Never in the local projects: they need Neon (or its env) to mean anything. */
const NEON_ONLY = ['test/neon/**', 'test/neon-node/**'];

const neonProjects = [
  {
    plugins: [workerd('neon')],
    test: {
      name: 'neon',
      sequence: { groupOrder: 0 },
      include: [...BOTH, 'test/pg/**/*.test.ts', 'test/neon/**/*.test.ts'],
      // Round trips go from this machine to aws-ap-southeast-1; same suites,
      // same assertions, only more time.
      testTimeout: 300_000,
      hookTimeout: 300_000,
      fileParallelism: false,
      setupFiles: ['./test/apply-migrations.ts', './test/pg/apply-pg-migrations.ts'],
    },
  },
  {
    test: {
      name: 'neon-node',
      sequence: { groupOrder: 1 },
      environment: 'node',
      fileParallelism: false,
      testTimeout: 120_000,
      hookTimeout: 120_000,
      include: ['test/pg-node/**/*.test.ts', 'test/neon-node/**/*.test.ts'],
      env: { WA_TEST_PG_URL: NEON_URL, WA_TEST_PG_TARGET: 'neon' },
    },
  },
];

export default defineConfig({
  test: {
    projects: NEON ? neonProjects : [
      {
        plugins: [workerd('d1')],
        test: {
          name: 'd1',
          // Projects run one after another (groupOrder), so the slow Postgres
          // suites never compete with D1's for CPU and D1 keeps its timings.
          sequence: { groupOrder: 0 },
          include: ['test/**/*.test.ts'],
          exclude: ['test/pg/**', 'test/pg-node/**', ...NEON_ONLY],
          setupFiles: ['./test/apply-migrations.ts'],
        },
      },
      {
        plugins: [workerd('pg')],
        test: {
          name: 'pg',
          sequence: { groupOrder: 1 },
          include: [...BOTH, 'test/pg/**/*.test.ts'],
          exclude: NEON_ONLY,
          // Every query is an HTTP round trip through the local Neon proxy
          // (~60-100 ms here, against well under 1 ms for local D1), so the
          // same suites need far longer. This project only; d1 keeps defaults.
          testTimeout: 120_000,
          hookTimeout: 120_000,
          // D1 gets isolated storage per test file; the Postgres database is one
          // shared server, so files must not run (and TRUNCATE) at the same time.
          fileParallelism: false,
          setupFiles: ['./test/apply-migrations.ts', './test/pg/apply-pg-migrations.ts'],
        },
      },
      {
        // Row-lock interleavings need interactive transactions on two real
        // connections, which the HTTP driver cannot hold open: plain Node + `pg`.
        test: {
          name: 'pg-node',
          sequence: { groupOrder: 2 },
          environment: 'node',
          fileParallelism: false,
          include: ['test/pg-node/**/*.test.ts'],
          env: { WA_TEST_PG_URL: PG_URL },
        },
      },
    ],
  },
});
