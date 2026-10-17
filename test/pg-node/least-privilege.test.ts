/**
 * The least-privilege grants proposed for an auth role (README draft), checked
 * on the local server only: a role holding exactly these grants can run every
 * store method, and nothing outside them. Never runs against Neon (no roles
 * are created there).
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { CredentialRecord } from '../../src/device-auth/store.js';
import { pgDeviceAuthStore, pgSessionStore } from '../../src/store/pg/index.js';
import { clientExecutor, connect, DAY, disconnect, NOW, type Connections } from './harness.js';

const ROLE = 'wa_test_least_privilege';

/** The proposal, verbatim apart from the role name (applied by the owner after the migrations). */
const GRANTS = `
  GRANT USAGE ON SCHEMA public TO ${ROLE};
  GRANT SELECT, INSERT, UPDATE, DELETE ON
    auth_sessions, auth_email_codes, auth_trusted_devices, auth_credentials, auth_rate_limits
    TO ${ROLE};
  GRANT SELECT, INSERT, UPDATE ON auth_login_guards TO ${ROLE};
`;

let c: Connections;

describe.skipIf(process.env['WA_TEST_PG_TARGET'] === 'neon')('least-privilege role', () => {
  beforeAll(async () => {
    c = await connect();
    await c.monitor.query(`DROP OWNED BY ${ROLE}`).catch(() => {});
    await c.monitor.query(`DROP ROLE IF EXISTS ${ROLE}`);
    await c.monitor.query(`CREATE ROLE ${ROLE} NOLOGIN`);
    await c.monitor.query(GRANTS);
    await c.monitor.query(
      'TRUNCATE auth_sessions, auth_email_codes, auth_trusted_devices, auth_credentials, auth_rate_limits, auth_login_guards',
    );
    await c.b.query(`SET ROLE ${ROLE}`);
  });

  afterAll(async () => {
    await c?.b.query('RESET ROLE');
    await c?.monitor.query(`DROP OWNED BY ${ROLE}`);
    await c?.monitor.query(`DROP ROLE IF EXISTS ${ROLE}`);
    await disconnect(c);
  });

  it('runs every store method', async () => {
    expect((await c.b.query<{ r: string }>('SELECT current_user AS r')).rows[0]!.r).toBe(ROLE);
    const executor = clientExecutor(c.b);
    const s = pgDeviceAuthStore(executor, { clock: () => NOW });
    const sessions = pgSessionStore(executor, { clock: () => NOW });

    const session = await sessions.create({ userId: 'u', subjectType: 'user', idleTtlSec: 60, absoluteTtlSec: 60 });
    expect(await sessions.get(session.sid)).not.toBeNull();
    await sessions.touch(session.sid, NOW + 30_000);
    await sessions.revoke(session.sid);
    await sessions.revokeAllForUser('u');
    await sessions.cleanup(NOW);

    await s.hitRateLimit('b', 1000, NOW);
    await s.reserveRateLimit('b', 1000, NOW, 5);
    await s.readRateLimit('b', 1000, NOW);
    await s.refundRateLimit('b', NOW);
    await s.hitCircuitBreaker('cb', 1000, NOW, true);
    await s.readCircuitBreaker('cb', 1000, NOW);
    await s.putEmailCode({ email: 'e@x.io', codeHash: 'h', keyId: 'k', expiresAt: NOW + 600_000, createdAt: NOW, attemptsResetAt: NOW + 600_000 });
    expect(await s.reserveEmailCodeAttempt('e@x.io', NOW, 5)).not.toBeNull();
    expect(await s.consumeEmailCode('e@x.io', 'h')).toBe(true);
    await s.createDevice({
      deviceId: 'd1', accountId: 'acct', email: 'e@x.io', secretHash: 'h', label: null,
      createdAt: NOW, lastUsedAt: NOW, idleExpiresAt: NOW + DAY, absoluteExpiresAt: NOW + DAY, revokedAt: null,
    });
    await s.findDevice('d1');
    await s.touchDevice('d1', NOW, NOW + DAY);
    await s.listDevices('acct', NOW);
    const pin = (id: string): CredentialRecord => ({
      credentialId: id, accountId: 'acct', type: 'pin', deviceId: null, material: {}, createdAt: NOW, updatedAt: NOW, lastUsedAt: null,
    });
    await s.replaceCredential(pin('p1'));
    expect(await s.replaceCredential(pin('p2'), { resetLoginGuard: true, revokeOtherDevices: { exceptDeviceId: null } })).toEqual({
      replaced: true,
      devicesRevoked: 1,
    });
    await s.getActiveCredential('acct', 'pin');
    await s.markCredentialUsed('p2', NOW);
    await s.reserveLoginAttempt('acct', 3, NOW);
    await s.lockAccount('acct', 1, NOW);
    expect(await s.resetLoginGuard('acct', NOW)).toEqual({ failedCount: 1, lockedAt: NOW });
    await s.readLoginGuard('acct');
    await s.revokeDevice('acct', 'd1', NOW);
    await s.revokeAllDevices('acct', NOW);
    await s.cleanup(NOW + 2 * DAY);
  });

  it('and nothing else: no TRUNCATE, no DDL, no other table', async () => {
    const code = (p: Promise<unknown>) => p.then(() => 'ok', (e: { code?: string }) => e.code);
    expect(await code(c.b.query('TRUNCATE auth_sessions'))).toBe('42501');
    expect(await code(c.b.query('DELETE FROM auth_login_guards'))).toBe('42501');
    expect(await code(c.b.query('CREATE TABLE public.x (id int)'))).toBe('42501');
    expect(await code(c.b.query('ALTER TABLE auth_sessions ADD COLUMN x int'))).toBe('42501');
    expect(await code(c.b.query('SELECT * FROM auth_api_keys'))).toBe('42501');
  });
});
