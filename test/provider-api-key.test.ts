import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { sha256Hex } from '../src/crypto.js';
import {
  apiKey,
  d1ApiKeyStore,
  issueApiKey,
  kvApiKeyStore,
  parseApiKey,
  type ApiKeyStore,
} from '../src/providers/api-key.js';
import { resetStorage } from './helpers/reset.js';

let now = 1_700_000_000_000;
const clock = () => now;

function withKey(key: string, header = 'authorization'): Request {
  return new Request('https://app.example.com/api/jobs', {
    headers: { [header]: header === 'authorization' ? `Bearer ${key}` : key },
  });
}

beforeEach(async () => {
  now = 1_700_000_000_000;
  await resetStorage();
});

const stores: Array<[string, () => ApiKeyStore]> = [
  ['kv', () => kvApiKeyStore(env.KV)],
  ['d1', () => d1ApiKeyStore(env.DB, { clock })],
];

describe.each(stores)('apiKey (%s store)', (_label, makeStore) => {
  it('issues a key that verifies once and only in raw form', async () => {
    const store = makeStore();
    const issued = await issueApiKey({
      store,
      env: 'live',
      subjectId: 'svc_reporting',
      label: 'nightly job',
      claims: { role: 'reader' },
      clock,
    });

    expect(issued.key).toMatch(/^tk_live_[a-f0-9]{24}\.[A-Za-z0-9_-]{43}$/);
    expect(issued.record.secretHash).toBe(await sha256Hex(issued.key.split('.')[1] as string));
    expect(JSON.stringify(issued.record)).not.toContain(issued.key.split('.')[1] as string);

    const provider = apiKey({ store, clock });
    const user = await provider.verify(withKey(issued.key), env);
    expect(user?.id).toBe('svc_reporting');
    expect(user?.subjectType).toBe('service');
    expect(user?.claims).toMatchObject({
      role: 'reader',
      keyId: issued.keyId,
      env: 'live',
      label: 'nightly job',
      provider: 'api-key',
    });
  });

  it('keys rateLimitId on the key, not the subject it acts as', async () => {
    const store = makeStore();
    // Two keys for the same subject: rate limiting must not conflate them,
    // or one hot/compromised key exhausts the other's quota too.
    const a = await issueApiKey({ store, env: 'live', subjectId: 'svc_shared', clock });
    const b = await issueApiKey({ store, env: 'live', subjectId: 'svc_shared', clock });

    const provider = apiKey({ store, clock });
    const userA = await provider.verify(withKey(a.key), env);
    const userB = await provider.verify(withKey(b.key), env);

    expect(userA?.id).toBe('svc_shared');
    expect(userB?.id).toBe('svc_shared');
    expect(userA?.rateLimitId).toBe(a.keyId);
    expect(userB?.rateLimitId).toBe(b.keyId);
    expect(userA?.rateLimitId).not.toBe(userB?.rateLimitId);
  });

  it('accepts the x-api-key header as well', async () => {
    const store = makeStore();
    const issued = await issueApiKey({ store, env: 'test', subjectId: 'svc_1', clock });
    const provider = apiKey({ store, clock });
    expect(await provider.verify(withKey(issued.key, 'x-api-key'), env)).not.toBeNull();
  });

  it('rejects a tampered secret', async () => {
    const store = makeStore();
    const issued = await issueApiKey({ store, env: 'live', subjectId: 'svc_1', clock });
    const provider = apiKey({ store, clock });

    const [prefix, secret] = issued.key.split('.') as [string, string];
    const flipped = `${secret.slice(0, -1)}${secret.endsWith('a') ? 'b' : 'a'}`;
    expect(await provider.verify(withKey(`${prefix}.${flipped}`), env)).toBeNull();
  });

  it('rejects a valid secret presented under another key id', async () => {
    const store = makeStore();
    const a = await issueApiKey({ store, env: 'live', subjectId: 'svc_a', clock });
    const b = await issueApiKey({ store, env: 'live', subjectId: 'svc_b', clock });
    const provider = apiKey({ store, clock });

    const secretOfA = a.key.split('.')[1] as string;
    expect(await provider.verify(withKey(`tk_live_${b.keyId}.${secretOfA}`), env)).toBeNull();
  });

  it('rejects unknown key ids and malformed keys', async () => {
    const store = makeStore();
    const provider = apiKey({ store, clock });

    expect(await provider.verify(withKey('tk_live_aaaaaaaaaaaaaaaaaaaaaaaa.' + 'a'.repeat(43)), env)).toBeNull();
    expect(await provider.verify(withKey('not-a-key'), env)).toBeNull();
    expect(await provider.verify(new Request('https://app.example.com/api/jobs'), env)).toBeNull();
  });

  it('rejects a revoked key', async () => {
    const store = makeStore();
    const issued = await issueApiKey({ store, env: 'live', subjectId: 'svc_1', clock });
    const provider = apiKey({ store, clock });

    expect(await provider.verify(withKey(issued.key), env)).not.toBeNull();
    await store.revoke(issued.keyId);
    expect(await provider.verify(withKey(issued.key), env)).toBeNull();
  });

  it('rejects an expired key', async () => {
    const store = makeStore();
    const issued = await issueApiKey({ store, env: 'live', subjectId: 'svc_1', ttlSec: 3600, clock });
    const provider = apiKey({ store, clock });

    now += 3_599_000;
    expect(await provider.verify(withKey(issued.key), env)).not.toBeNull();
    now += 2_000;
    expect(await provider.verify(withKey(issued.key), env)).toBeNull();
  });

  it('rejects a key minted for another environment', async () => {
    const store = makeStore();
    const issued = await issueApiKey({ store, env: 'test', subjectId: 'svc_1', clock });

    expect(await apiKey({ store, env: 'live', clock }).verify(withKey(issued.key), env)).toBeNull();
    expect(await apiKey({ store, env: 'test', clock }).verify(withKey(issued.key), env)).not.toBeNull();

    // The env segment is part of the credential: rewriting it must not help.
    const forged = issued.key.replace('tk_test_', 'tk_live_');
    expect(await apiKey({ store, env: 'live', clock }).verify(withKey(forged), env)).toBeNull();
  });
});

describe('api key format', () => {
  it('parses only well-formed keys', () => {
    expect(parseApiKey(`tk_live_${'a'.repeat(24)}.${'b'.repeat(43)}`)).toEqual({
      env: 'live',
      keyId: 'a'.repeat(24),
      secret: 'b'.repeat(43),
    });
    expect(parseApiKey('tk_live_zzz.secret')).toBeNull();
    expect(parseApiKey('')).toBeNull();
    expect(parseApiKey(`tk_LIVE_${'a'.repeat(24)}.${'b'.repeat(43)}`)).toBeNull();
  });

  it('validates the env tag at issuance', async () => {
    await expect(
      issueApiKey({ store: kvApiKeyStore(env.KV), env: 'Live!', subjectId: 'svc' }),
    ).rejects.toThrow(/env must be/);
    await expect(
      issueApiKey({ store: kvApiKeyStore(env.KV), env: 'live', subjectId: '' }),
    ).rejects.toThrow(/subjectId is required/);
  });

  it('tracks last use only when asked', async () => {
    const store = d1ApiKeyStore(env.DB, { clock });
    const issued = await issueApiKey({ store, env: 'live', subjectId: 'svc_1', clock });

    await apiKey({ store, clock }).verify(withKey(issued.key), env);
    expect((await store.findById(issued.keyId))?.lastUsedAt ?? null).toBeNull();

    now += 5_000;
    await apiKey({ store, clock, trackLastUsed: true }).verify(withKey(issued.key), env);
    expect((await store.findById(issued.keyId))?.lastUsedAt).toBe(now);
  });

  it('kv store tracks last use too', async () => {
    const store = kvApiKeyStore(env.KV, { clock });
    const issued = await issueApiKey({ store, env: 'live', subjectId: 'svc_1', clock });

    now += 5_000;
    await apiKey({ store, clock, trackLastUsed: true }).verify(withKey(issued.key), env);
    expect((await store.findById(issued.keyId))?.lastUsedAt).toBe(now);
  });

  it('kv store: a stray touch write after revoke does not undo the revocation', async () => {
    // Revocation and last-used tracking live in separate keys precisely so
    // this can't happen — this is the regression test for that split.
    const store = kvApiKeyStore(env.KV, { clock });
    const issued = await issueApiKey({ store, env: 'live', subjectId: 'svc_1', clock });

    await store.revoke(issued.keyId);
    await store.touch?.(issued.keyId, now + 1000);

    expect((await store.findById(issued.keyId))?.revokedAt).not.toBeNull();
    expect(await apiKey({ store, clock }).verify(withKey(issued.key), env)).toBeNull();
  });
});
