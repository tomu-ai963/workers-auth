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

/** The suites that run against both databases. */
const BOTH = ['test/device-auth-*.test.ts', 'test/store-contract.test.ts'];

function workerd(backend: 'd1' | 'pg') {
  return cloudflareTest({
    singleWorker: true,
    miniflare: {
      compatibilityDate: '2025-04-01',
      kvNamespaces: ['KV'],
      d1Databases: ['DB'],
      bindings: {
        TEST_MIGRATIONS: migrations,
        TEST_BACKEND: backend,
        PG_URL: backend === 'pg' ? PG_URL : '',
        PG_HTTP_ENDPOINT,
        PG_MIGRATIONS: pgMigrations,
      },
    },
  });
}

export default defineConfig({
  test: {
    projects: [
      {
        plugins: [workerd('d1')],
        test: {
          name: 'd1',
          // Projects run one after another (groupOrder), so the slow Postgres
          // suites never compete with D1's for CPU and D1 keeps its timings.
          sequence: { groupOrder: 0 },
          include: ['test/**/*.test.ts'],
          exclude: ['test/pg/**', 'test/pg-node/**'],
          setupFiles: ['./test/apply-migrations.ts'],
        },
      },
      {
        plugins: [workerd('pg')],
        test: {
          name: 'pg',
          sequence: { groupOrder: 1 },
          include: [...BOTH, 'test/pg/**/*.test.ts'],
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
