// Bindings provided by vitest.config.ts to the Miniflare test worker.
declare namespace Cloudflare {
  interface Env {
    KV: KVNamespace;
    DB: D1Database;
    TEST_MIGRATIONS: import('cloudflare:test').D1Migration[];
    /** 'd1' or 'pg': which database the device-auth suites run against. */
    TEST_BACKEND: string;
    /** pg project only; empty when `pnpm pg:up` has not been run. */
    PG_URL: string;
    PG_HTTP_ENDPOINT: string;
    PG_MIGRATIONS: Array<{ name: string; sql: string }>;
  }
}
