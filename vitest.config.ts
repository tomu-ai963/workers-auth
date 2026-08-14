import { fileURLToPath } from 'node:url';

import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-pool-workers';
import { defineConfig } from 'vitest/config';

const migrations = await readD1Migrations(fileURLToPath(new URL('./migrations', import.meta.url)));

export default defineConfig({
  plugins: [
    cloudflareTest({
      singleWorker: true,
      miniflare: {
        compatibilityDate: '2025-04-01',
        kvNamespaces: ['KV'],
        d1Databases: ['DB'],
        bindings: {
          TEST_MIGRATIONS: migrations,
        },
      },
    }),
  ],
  test: {
    setupFiles: ['./test/apply-migrations.ts'],
  },
});
