/**
 * F1: an executor whose rowCount is null (a careless adapter) must not turn
 * "replaced" / "revoked" into false or 0. Decisions come from RETURNING rows;
 * where a count is still read (cleanup totals), a missing one throws.
 */
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { CredentialRecord } from '../../src/device-auth/store.js';
import { pgDeviceAuthStore, pgSessionStore, type PgExecutor, type PgQueryResult } from '../../src/store/pg/index.js';
import { clientExecutor, connect, DAY, disconnect, NOW, type Connections } from './harness.js';

let c: Connections;
let store: ReturnType<typeof pgDeviceAuthStore>;

function nullRowCount(executor: PgExecutor): PgExecutor {
  const strip = (r: PgQueryResult) => ({ ...r, rowCount: null as unknown as number });
  return {
    query: async (text, params) => strip(await executor.query(text, params)) as never,
    transaction: async (statements) => (await executor.transaction(statements)).map(strip),
  };
}

const pin = (id: string, at = NOW): CredentialRecord => ({
  credentialId: id,
  accountId: 'acct',
  type: 'pin',
  deviceId: null,
  material: {},
  createdAt: at,
  updatedAt: at,
  lastUsedAt: null,
});

beforeAll(async () => {
  c = await connect();
  store = pgDeviceAuthStore(nullRowCount(clientExecutor(c.b)), { clock: () => NOW });
});

afterAll(async () => {
  await disconnect(c);
});

beforeEach(async () => {
  await c.monitor.query('TRUNCATE auth_credentials, auth_trusted_devices, auth_sessions, auth_login_guards');
  for (const id of ['d1', 'd2', 'd3']) {
    await c.monitor.query(
      `INSERT INTO auth_trusted_devices
         (device_id, account_id, email, secret_hash, label, created_at, last_used_at, idle_expires_at, absolute_expires_at, revoked_at)
       VALUES ($1, 'acct', 'e@example.com', 'h', NULL, $2, $2, $3, $3, NULL)`,
      [id, NOW, NOW + DAY],
    );
  }
});

describe('with rowCount: null', () => {
  it('replaceCredential still reports a replacement, and the devices it revoked', async () => {
    expect(await store.replaceCredential(pin('p1'))).toEqual({ replaced: false, devicesRevoked: 0 });
    expect(await store.replaceCredential(pin('p2'), { revokeOtherDevices: { exceptDeviceId: 'd1' } })).toEqual({
      replaced: true,
      devicesRevoked: 2,
    });
  });

  it('revokeDevice and revokeAllDevices answer from RETURNING rows', async () => {
    expect(await store.revokeDevice('acct', 'd1', NOW)).toBe(true);
    expect(await store.revokeDevice('acct', 'd1', NOW)).toBe(false);
    expect(await store.revokeAllDevices('acct', NOW, 'd2')).toBe(1);
    expect(await store.revokeAllDevices('acct', NOW)).toBe(1);
  });

  it('a count that cannot be read from rows throws instead of reading as 0', async () => {
    await expect(store.cleanup(NOW)).rejects.toThrow(/rowCount null; it must report affected rows as a number/);
    const sessions = pgSessionStore(nullRowCount(clientExecutor(c.b)), { clock: () => NOW });
    await expect(sessions.cleanup(NOW)).rejects.toThrow(/rowCount null/);
  });
});
