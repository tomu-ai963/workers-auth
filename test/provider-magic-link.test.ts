import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';

import { sha256Hex } from '../src/crypto.js';
import {
  d1MagicLinkStore,
  kvMagicLinkStore,
  magicLink,
  type MagicLinkStore,
} from '../src/providers/magic-link.js';
import { resetStorage } from './helpers/reset.js';

let now = 1_700_000_000_000;
const clock = () => now;

function callbackRequest(token: string): Request {
  return new Request(`https://app.example.com/auth/callback?token=${encodeURIComponent(token)}`);
}

function headerRequest(token: string): Request {
  return new Request('https://app.example.com/auth/session', {
    method: 'POST',
    headers: { 'x-magic-token': token },
  });
}

beforeEach(async () => {
  now = 1_700_000_000_000;
  await resetStorage();
});

function setup(overrides: Partial<Parameters<typeof magicLink>[0]> = {}) {
  const sent: Array<{ email: string; token: string }> = [];
  const provider = magicLink({
    store: d1MagicLinkStore(env.DB, { clock }),
    sendToken: async (email, token) => {
      sent.push({ email, token });
    },
    allowTokenInQuery: true,
    clock,
    ...overrides,
  });
  return { provider, sent };
}

describe('magicLink store safety', () => {
  it('refuses a store that cannot consume a token atomically', () => {
    expect(() =>
      magicLink({ store: kvMagicLinkStore(env.KV, { clock }), sendToken: async () => {} }),
    ).toThrow(/replayable/);
  });

  it('names the escape hatch and honours it', () => {
    expect(() =>
      magicLink({
        store: kvMagicLinkStore(env.KV, { clock }),
        sendToken: async () => {},
        dangerouslyAllowReplayableTokens: true,
      }),
    ).not.toThrow();
  });

  it('reports atomicity honestly per store', () => {
    expect(kvMagicLinkStore(env.KV).atomicTake).toBe(false);
    expect(d1MagicLinkStore(env.DB).atomicTake).toBe(true);
  });

  /**
   * Regression: the KV store reads then deletes, so two requests arriving
   * together both observed the token. This is the same race against the
   * atomic store, which must let exactly one through.
   */
  it('lets exactly one of two concurrent requests consume a token', async () => {
    const { provider, sent } = setup();
    await provider.start('victim@example.com');
    const token = sent[0]?.token as string;

    const results = await Promise.all([
      provider.verify(callbackRequest(token), env),
      provider.verify(callbackRequest(token), env),
      provider.verify(callbackRequest(token), env),
    ]);

    expect(results.filter((r) => r !== null)).toHaveLength(1);
  });

  it('demonstrates the replay the guard exists to prevent', async () => {
    const sent: string[] = [];
    const replayable = magicLink({
      store: kvMagicLinkStore(env.KV, { clock }),
      sendToken: async (_e, t) => {
        sent.push(t);
      },
      allowTokenInQuery: true,
      dangerouslyAllowReplayableTokens: true,
      clock,
    });
    await replayable.start('victim@example.com');
    const token = sent[0] as string;

    const results = await Promise.all([
      replayable.verify(callbackRequest(token), env),
      replayable.verify(callbackRequest(token), env),
    ]);
    // Both succeed — which is precisely why the default configuration throws.
    expect(results.filter((r) => r !== null)).toHaveLength(2);
  });
});

describe('magicLink token sources', () => {
  it('ignores ?token= unless the provider opted into it', async () => {
    const { provider, sent } = setup({ allowTokenInQuery: false });
    await provider.start('user@example.com');
    const token = sent[0]?.token as string;

    expect(await provider.verify(callbackRequest(token), env)).toBeNull();
    // The token was not consumed by that attempt.
    expect(await provider.verify(headerRequest(token), env)).not.toBeNull();
  });

  it('marks a query-reading provider as callback only', () => {
    expect(setup({ allowTokenInQuery: true }).provider.callbackOnly).toBe(true);
    expect(setup({ allowTokenInQuery: false }).provider.callbackOnly).toBe(false);
  });

  it('accepts the token from a JSON body', async () => {
    const { provider, sent } = setup({ allowTokenInQuery: false });
    await provider.start('user@example.com');
    const token = sent[0]?.token as string;

    const req = new Request('https://app.example.com/auth/session', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    expect(await provider.verify(req, env)).not.toBeNull();
  });
});

describe('magicLink', () => {
  it('issues a token, delivers it, and stores only its hash', async () => {
    const { provider, sent } = setup();
    expect(await provider.start('User@Example.com ')).toEqual({ ok: true });

    expect(sent).toHaveLength(1);
    expect(sent[0]?.email).toBe('user@example.com');
    const token = sent[0]?.token as string;
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const rows = await env.DB.prepare('SELECT token_hash FROM auth_magic_link_tokens').all<{
      token_hash: string;
    }>();
    expect(rows.results).toHaveLength(1);
    expect(rows.results[0]?.token_hash).toBe(await sha256Hex(token));
  });

  it('verifies a token exactly once, sequentially', async () => {
    const { provider, sent } = setup();
    await provider.start('user@example.com');
    const token = sent[0]?.token as string;

    const user = await provider.verify(callbackRequest(token), env);
    expect(user?.id).toBe('user@example.com');
    expect(user?.email).toBe('user@example.com');
    expect(user?.subjectType).toBe('user');
    expect(user?.claims['provider']).toBe('magic-link');

    expect(await provider.verify(callbackRequest(token), env)).toBeNull();
  });

  it('rejects a token after its TTL', async () => {
    const { provider, sent } = setup({ ttlSec: 900 });
    await provider.start('user@example.com');

    now += 899_000;
    expect(await provider.verify(callbackRequest(sent[0]?.token as string), env)).not.toBeNull();

    await provider.start('user@example.com');
    now += 901_000;
    expect(await provider.verify(callbackRequest(sent[1]?.token as string), env)).toBeNull();
  });

  it('rejects an unknown or malformed token', async () => {
    const { provider } = setup();
    expect(await provider.verify(callbackRequest('not-a-real-token'), env)).toBeNull();
    expect(await provider.verify(new Request('https://app.example.com/auth/callback'), env)).toBeNull();
  });

  it('treats unknown addresses exactly like known ones', async () => {
    const { provider, sent } = setup();
    const known = await provider.start('known@example.com');
    const unknown = await provider.start('nobody@example.com');

    expect(known).toEqual(unknown);
    expect(sent).toHaveLength(2);
    expect(sent[0]?.token).not.toBe(sent[1]?.token);
  });

  it('does not surface delivery failures to the caller', async () => {
    const errors: unknown[] = [];
    const { provider } = setup({
      sendToken: async () => {
        throw new Error('smtp exploded');
      },
      onSendError: (error) => errors.push(error),
    });

    expect(await provider.start('user@example.com')).toEqual({ ok: true });
    expect(errors).toHaveLength(1);
  });

  it('lets the app reject an address at verification time', async () => {
    const { provider, sent } = setup({ resolveUser: async () => null });
    await provider.start('user@example.com');
    expect(await provider.verify(callbackRequest(sent[0]?.token as string), env)).toBeNull();
  });

  it('maps a verified address onto the app user', async () => {
    const { provider, sent } = setup({
      resolveUser: async (email) => ({
        id: 'user_7',
        subjectType: 'user' as const,
        email,
        claims: { plan: 'pro' },
      }),
    });
    await provider.start('user@example.com');
    const user = await provider.verify(callbackRequest(sent[0]?.token as string), env);
    expect(user?.id).toBe('user_7');
    expect(user?.claims).toEqual({ plan: 'pro', provider: 'magic-link' });
  });

  it('rejects malformed input up front', async () => {
    const { provider } = setup();
    await expect(provider.start('not-an-email')).rejects.toThrow(TypeError);
  });
});

describe('magicLink configuration', () => {
  it('demands a sendToken implementation', () => {
    expect(() =>
      magicLink({ store: d1MagicLinkStore(env.DB), sendToken: undefined as never }),
    ).toThrow(/sendToken is required/);
  });

  it('demands a store', () => {
    expect(() =>
      magicLink({ store: undefined as unknown as MagicLinkStore, sendToken: async () => {} }),
    ).toThrow(/MagicLinkStore is required/);
  });

  it('rejects an unsafe table name', () => {
    expect(() => d1MagicLinkStore(env.DB, { table: 'x; DROP TABLE y' })).toThrow(
      /not a valid SQL identifier/,
    );
  });

  it('cleanup removes only expired, unconsumed tokens', async () => {
    const store = d1MagicLinkStore(env.DB, { clock });
    await store.put('hash-a', { email: 'a@example.com', expiresAt: now - 1 });
    await store.put('hash-b', { email: 'b@example.com', expiresAt: now + 900_000 });

    expect(await store.cleanup()).toBe(1);
    expect(await store.take('hash-b')).not.toBeNull();
  });
});
