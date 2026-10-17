import { env } from 'cloudflare:test';

import { resetDatabase } from './backend.js';

/**
 * Storage is shared across tests in this pool, so every test that asserts on
 * counts starts from a clean slate explicitly — on whichever backend the
 * project runs (D1, or Postgres too).
 */
export async function resetStorage(): Promise<void> {
  await resetDatabase();

  let cursor: string | undefined;
  do {
    const page = await env.KV.list(cursor ? { cursor } : {});
    await Promise.all(page.keys.map((key) => env.KV.delete(key.name)));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}
