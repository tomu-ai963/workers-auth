import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { clearJwksCache, neonAuth } from '../src/providers/neon.js';
import { bearer, generateKey, jwksFetch, signJwt, type TestKey } from './helpers/jwt.js';
import { resetStorage } from './helpers/reset.js';

const ISSUER = 'https://issuer.example.com';
const AUDIENCE = 'workers-auth-test';

let now = 1_700_000_000_000;
const clock = () => now;
const nowSec = () => Math.floor(now / 1000);

let rsaKey: TestKey;
let ecKey: TestKey;
let urlCounter = 0;

function freshUrl(): string {
  urlCounter += 1;
  return `${ISSUER}/.well-known/jwks-${urlCounter}.json`;
}

function claims(overrides: Record<string, unknown> = {}) {
  return {
    sub: 'user_42',
    iss: ISSUER,
    aud: AUDIENCE,
    email: 'user42@example.com',
    exp: nowSec() + 3600,
    iat: nowSec(),
    ...overrides,
  };
}

beforeEach(async () => {
  now = 1_700_000_000_000;
  clearJwksCache();
  await resetStorage();
  rsaKey ??= await generateKey('RS256', 'kid-rsa-1');
  ecKey ??= await generateKey('ES256', 'kid-ec-1');
});

describe('neonAuth', () => {
  it('accepts a well-formed RS256 token', async () => {
    const { fetchImpl, state } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });

    const user = await provider.verify(bearer(await signJwt(rsaKey, claims())), env);
    expect(user).not.toBeNull();
    expect(user?.id).toBe('user_42');
    expect(user?.email).toBe('user42@example.com');
    expect(user?.subjectType).toBe('user');
    expect(user?.rateLimitId).toBe('user_42');
    expect(user?.claims['provider']).toBe('neon');
    expect(user?.claims['iss']).toBe(ISSUER);
    expect(state.calls).toBe(1);

    // Second verification is served from the in-isolate cache.
    await provider.verify(bearer(await signJwt(rsaKey, claims())), env);
    expect(state.calls).toBe(1);
  });

  it('accepts ES256 as well', async () => {
    const { fetchImpl } = jwksFetch([ecKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });
    const user = await provider.verify(bearer(await signJwt(ecKey, claims())), env);
    expect(user?.id).toBe('user_42');
  });

  it('accepts any audience from the configured list', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: ['other', AUDIENCE],
      fetchImpl,
      clock,
    });
    expect(await provider.verify(bearer(await signJwt(rsaKey, claims())), env)).not.toBeNull();
  });

  it('rejects a mismatched issuer', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });
    const token = await signJwt(rsaKey, claims({ iss: 'https://evil.example.com' }));
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('rejects a mismatched audience', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });
    expect(await provider.verify(bearer(await signJwt(rsaKey, claims({ aud: 'other' }))), env)).toBeNull();
    expect(
      await provider.verify(bearer(await signJwt(rsaKey, claims({ aud: undefined }))), env),
    ).toBeNull();
  });

  it('rejects an expired token', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
      clockToleranceSec: 5,
    });
    const token = await signJwt(rsaKey, claims({ exp: nowSec() - 10 }));
    expect(await provider.verify(bearer(token), env)).toBeNull();

    // Still inside the tolerance window.
    const fresh = await signJwt(rsaKey, claims({ exp: nowSec() - 2 }));
    expect(await provider.verify(bearer(fresh), env)).not.toBeNull();
  });

  it('defaults to a 30 second clock-skew tolerance', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({ jwksUrl: freshUrl(), issuer: ISSUER, audience: AUDIENCE, fetchImpl, clock });

    // The issuer's clock is 20s ahead of ours: exp already looks past on paper.
    const skewed = await signJwt(rsaKey, claims({ exp: nowSec() - 20 }));
    expect(await provider.verify(bearer(skewed), env)).not.toBeNull();

    const tooOld = await signJwt(rsaKey, claims({ exp: nowSec() - 45 }));
    expect(await provider.verify(bearer(tooOld), env)).toBeNull();
  });

  it('rejects a token that is not valid yet', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });
    const token = await signJwt(rsaKey, claims({ nbf: nowSec() + 600 }));
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('rejects a token with no exp at all', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });
    const token = await signJwt(rsaKey, claims({ exp: undefined }));
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('rejects a tampered payload', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });
    const token = await signJwt(rsaKey, claims());
    const [header, , signature] = token.split('.') as [string, string, string];
    const forged = btoa(JSON.stringify(claims({ sub: 'admin' })))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
    expect(await provider.verify(bearer(`${header}.${forged}.${signature}`), env)).toBeNull();
  });

  it('rejects unlisted algorithms, including none', async () => {
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['RS256'],
      fetchImpl,
      clock,
    });

    const hs = await signJwt(rsaKey, claims(), { alg: 'HS256' });
    expect(await provider.verify(bearer(hs), env)).toBeNull();

    const none = await signJwt(rsaKey, claims(), { alg: 'none' });
    expect(await provider.verify(bearer(none), env)).toBeNull();

    const stripped = none.split('.').slice(0, 2).join('.');
    expect(await provider.verify(bearer(`${stripped}.`), env)).toBeNull();
  });

  it('refuses to use an RSA key for an EC algorithm', async () => {
    // The JWKS only holds the RSA key, but the header claims ES256 with its kid.
    const { fetchImpl } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });
    const token = await signJwt(rsaKey, claims(), { alg: 'ES256' });
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('rejects a request with no bearer token', async () => {
    const { fetchImpl, state } = jwksFetch([rsaKey.jwk]);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
    });
    expect(await provider.verify(new Request('https://app.example.com/'), env)).toBeNull();
    expect(state.calls).toBe(0);
  });

  it('fails closed when the JWKS endpoint is down', async () => {
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl: (async () => new Response('nope', { status: 500 })) as unknown as typeof fetch,
      clock,
    });
    expect(await provider.verify(bearer(await signJwt(rsaKey, claims())), env)).toBeNull();
  });

  it('refetches exactly once for an unknown kid, then rate limits', async () => {
    const { fetchImpl, state } = jwksFetch([rsaKey.jwk]);
    const jwksUrl = freshUrl();
    const provider = neonAuth({
      jwksUrl,
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
      minRefetchIntervalSec: 60,
    });

    // Warm the cache with the current key.
    expect(await provider.verify(bearer(await signJwt(rsaKey, claims())), env)).not.toBeNull();
    expect(state.calls).toBe(1);

    const rotated = await generateKey('RS256', 'kid-rsa-2');
    const rotatedToken = await signJwt(rotated, claims());

    // Inside the rate-limit window: no network call at all.
    expect(await provider.verify(bearer(rotatedToken), env)).toBeNull();
    expect(state.calls).toBe(1);

    now += 61_000;

    // Outside the window: exactly one refetch, which still does not have the key.
    expect(await provider.verify(bearer(rotatedToken), env)).toBeNull();
    expect(state.calls).toBe(2);

    // Immediately after, the rate limit holds again.
    expect(await provider.verify(bearer(rotatedToken), env)).toBeNull();
    expect(state.calls).toBe(2);

    // Once the endpoint really publishes the key, the refetch picks it up.
    now += 61_000;
    state.keys = [rsaKey.jwk, rotated.jwk];
    expect(await provider.verify(bearer(rotatedToken), env)).not.toBeNull();
    expect(state.calls).toBe(3);
  });

  it('aborts a JWKS fetch that hangs past the timeout', async () => {
    const hanging = (async (_url: unknown, init: { signal?: AbortSignal }) => {
      return new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      });
    }) as unknown as typeof fetch;

    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl: hanging,
      fetchTimeoutMs: 20,
      clock,
    });
    const token = await signJwt(rsaKey, claims());
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('rejects a JWKS document declared larger than the byte limit', async () => {
    const oversized = (async () =>
      new Response(JSON.stringify({ keys: [rsaKey.jwk] }), {
        headers: { 'content-type': 'application/json', 'content-length': String(10 * 1024 * 1024) },
      })) as unknown as typeof fetch;

    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl: oversized,
      maxJwksBytes: 1024,
      clock,
    });
    const token = await signJwt(rsaKey, claims());
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('rejects a JWKS body that is actually larger than the byte limit', async () => {
    // No Content-Length this time: the actual body size must be checked too.
    const padded = (async () =>
      new Response(JSON.stringify({ keys: [rsaKey.jwk], padding: 'x'.repeat(5000) }), {
        headers: { 'content-type': 'application/json' },
      })) as unknown as typeof fetch;

    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl: padded,
      maxJwksBytes: 1024,
      clock,
    });
    const token = await signJwt(rsaKey, claims());
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('rejects a JWKS document with too many keys', async () => {
    const manyKeys = Array.from({ length: 40 }, (_v, i) => ({ ...rsaKey.jwk, kid: `k${i}` }));
    const { fetchImpl } = jwksFetch(manyKeys);
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      maxJwksKeys: 32,
      clock,
    });
    const token = await signJwt(rsaKey, claims());
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('rejects a non-JSON JWKS response', async () => {
    const html = (async () =>
      new Response('<html>not json</html>', { headers: { 'content-type': 'text/html' } })) as unknown as typeof fetch;
    const provider = neonAuth({
      jwksUrl: freshUrl(),
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl: html,
      clock,
    });
    const token = await signJwt(rsaKey, claims());
    expect(await provider.verify(bearer(token), env)).toBeNull();
  });

  it('shares the JWKS through KV across isolates', async () => {
    const jwksUrl = freshUrl();
    const { fetchImpl, state } = jwksFetch([rsaKey.jwk]);
    const options = {
      jwksUrl,
      issuer: ISSUER,
      audience: AUDIENCE,
      fetchImpl,
      clock,
      cache: { kv: env.KV },
    };

    expect(await neonAuth(options).verify(bearer(await signJwt(rsaKey, claims())), env)).not.toBeNull();
    expect(state.calls).toBe(1);

    // A brand new isolate: module cache gone, KV cache still warm.
    clearJwksCache();
    expect(await neonAuth(options).verify(bearer(await signJwt(rsaKey, claims())), env)).not.toBeNull();
    expect(state.calls).toBe(1);
  });
});
