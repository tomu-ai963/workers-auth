/**
 * The two places where a D1 batch was safe only because D1 has one writer:
 * replaceCredential (revoke + insert) and resetLoginGuard (read + clear).
 * Each is interleaved deterministically on real connections.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { CredentialRecord } from '../../src/device-auth/store.js';
import { replaceCredentialStatements } from '../../src/store/pg/device-auth.js';
import { pgDeviceAuthStore } from '../../src/store/pg/index.js';
import { clientExecutor, connect, disconnect, interleave, NOW, type Connections } from './harness.js';

let c: Connections;
let store: ReturnType<typeof pgDeviceAuthStore>;

beforeAll(async () => {
  c = await connect();
  store = pgDeviceAuthStore(clientExecutor(c.b), { clock: () => NOW });
});

afterAll(async () => {
  await disconnect(c);
});

beforeEach(async () => {
  await c.monitor.query('TRUNCATE auth_credentials, auth_login_guards');
});

const pin = (id: string, at = NOW): CredentialRecord => ({
  credentialId: id,
  accountId: 'acct',
  type: 'pin',
  deviceId: null,
  material: { alg: 'pbkdf2-sha256', hash: id },
  createdAt: at,
  updatedAt: at,
  lastUsedAt: null,
});

/**
 * The store's own statements for a PIN replacement (advisory lock, revoke,
 * insert); `withLock: false` drops exactly the lock and nothing else.
 */
function replacement(r: CredentialRecord, withLock: boolean) {
  const statements = replaceCredentialStatements('public.auth_credentials', r).map((s) => ({ text: s.text, params: [...s.params] }));
  expect(statements[0]!.text).toMatch(/pg_advisory_xact_lock\(hashtextextended\('workers-auth:credential:' \|\| \$1::text, 0\)\)/);
  return withLock ? statements : statements.slice(1);
}

const live = async () =>
  (await c.monitor.query<{ credential_id: string }>(
    `SELECT credential_id FROM auth_credentials WHERE revoked_at IS NULL ORDER BY credential_id`,
  )).rows.map((r) => r.credential_id);

describe('replaceCredential: two concurrent PIN changes', () => {
  beforeEach(async () => {
    await store.replaceCredential(pin('p0'));
  });

  it('with the advisory lock, the second waits for the first and both succeed: last writer wins', async () => {
    const replaced = await interleave(c, replacement(pin('pA', NOW + 1), true), () => store.replaceCredential(pin('pB', NOW + 2)));
    expect(replaced).toBe(true); // B revoked A's PIN, which it could see once A had committed
    expect(await live()).toEqual(['pB']);
  });

  it('with the lock removed, the second fails with 23505 — the race the lock exists for', async () => {
    const b = clientExecutor(c.b);
    const error = await interleave(c, replacement(pin('pA', NOW + 1), false), () =>
      b.transaction(replacement(pin('pB', NOW + 2), false)),
    ).then(
      () => null,
      (e: { code?: string }) => e,
    );
    expect(error?.code).toBe('23505');
    expect(await live()).toEqual(['pA']);
  });
});

describe('replaceCredential: two concurrent first PINs (nothing to revoke)', () => {
  it('with the lock, the second waits, then revokes the first PIN and both succeed', async () => {
    const replaced = await interleave(c, replacement(pin('pA', NOW + 1), true), () => store.replaceCredential(pin('pB', NOW + 2)));
    expect(replaced).toBe(true);
    expect(await live()).toEqual(['pB']);
  });

  it('without it, the second blocks on the index and then fails with 23505', async () => {
    const b = clientExecutor(c.b);
    const error = await interleave(c, replacement(pin('pA', NOW + 1), false), () =>
      b.transaction(replacement(pin('pB', NOW + 2), false)),
    ).then(
      () => null,
      (e: { code?: string }) => e,
    );
    expect(error?.code).toBe('23505');
  });
});

describe('resetLoginGuard: the state it reports is the state it clears', () => {
  it('a failure and lock committed while it waits are reported, not an older snapshot', async () => {
    await c.monitor.query(`INSERT INTO auth_login_guards (account_id, failed_count, locked_at, updated_at) VALUES ('acct', 1, NULL, 0)`);
    const before = await interleave(
      c,
      [{ text: `UPDATE auth_login_guards SET failed_count = 3, locked_at = $1 WHERE account_id = 'acct'`, params: [NOW], rowCount: 1 }],
      () => store.resetLoginGuard('acct', NOW + 1),
    );
    expect(before).toEqual({ failedCount: 3, lockedAt: NOW });
    expect(await store.readLoginGuard('acct')).toEqual({ failedCount: 0, lockedAt: null });
  });

  it('is one statement: nothing between the read and the clear', async () => {
    await c.monitor.query(`INSERT INTO auth_login_guards (account_id, failed_count, locked_at, updated_at) VALUES ('acct', 2, $1, 0)`, [NOW]);
    const seen: string[] = [];
    const counting = pgDeviceAuthStore(
      {
        query: (text, params) => {
          seen.push(text);
          return c.b.query(text, [...params]);
        },
        transaction: () => {
          throw new Error('resetLoginGuard must not need a transaction');
        },
      },
      { clock: () => NOW },
    );
    expect(await counting.resetLoginGuard('acct', NOW + 1)).toEqual({ failedCount: 2, lockedAt: NOW });
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatch(/FOR UPDATE/);
  });
});
