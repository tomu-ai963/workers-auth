// Bindings provided by vitest.config.ts to the Miniflare test worker.
declare namespace Cloudflare {
  interface Env {
    KV: KVNamespace;
    DB: D1Database;
    TEST_MIGRATIONS: import('cloudflare:test').D1Migration[];
  }
}
