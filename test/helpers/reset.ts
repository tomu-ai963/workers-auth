import { env } from 'cloudflare:test';

const TABLES = [
  'auth_sessions',
  'auth_revocations',
  'auth_user_revocations',
  'auth_magic_link_tokens',
  'auth_api_keys',
];

/**
 * Storage is shared across tests in this pool, so every test that asserts on
 * counts starts from a clean slate explicitly.
 */
export async function resetStorage(): Promise<void> {
  await env.DB.batch(TABLES.map((table) => env.DB.prepare(`DELETE FROM ${table}`)));

  let cursor: string | undefined;
  do {
    const page = await env.KV.list(cursor ? { cursor } : {});
    await Promise.all(page.keys.map((key) => env.KV.delete(key.name)));
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
}
