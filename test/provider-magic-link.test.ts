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

function callback(token: string): Request {
  return new Request(`https://app.example.com/auth/callback?token=${encodeURIComponent(token)}`);
}

beforeEach(async () => {
  now = 1_700_000_000_000;
  await resetStorage();
});

const stores: Array<[string, () => MagicLinkStore]> = [
  ['kv', () => kvMagicLinkStore(env.KV, { clock })],
  ['d1', () => d1MagicLinkStore(env.DB, { clock })],
];

describe.each(stores)('magicLink (%s store)', (_label, makeStore) => {
  function setup(overrides: Partial<Parameters<typeof magicLink>[0]> = {}) {
    const sent: Array<{ email: string; token: string }> = [];
    const provider = magicLink({
      store: makeStore(),
      sendToken: async (email, token) => {
        sent.push({ email, token });
      },
      clock,
      ...overrides,
    });
    return { provider, sent };
  }

  it('issues a token, delivers it, and stores only its hash', async () => {
    const { provider, sent } = setup();
    expect(await provider.start('User@Example.com ')).toEqual({ ok: true });

    expect(sent).toHaveLength(1);
    expect(sent[0]?.email).toBe('user@example.com');
    const token = sent[0]?.token as string;
    expect(token).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const kvValues = await env.KV.list({ prefix: 'mlt:' });
    for (const key of kvValues.keys) {
      expect(key.name).toContain(await sha256Hex(token));
      expect(key.name).not.toContain(token);
      expect((await env.KV.get(key.name)) ?? '').not.toContain(token);
    }
    const rows = await env.DB.prepare('SELECT token_hash FROM auth_magic_link_tokens').all<{
      token_hash: string;
    }>();
    for (const row of rows.results) {
      expect(row.token_hash).toBe(await sha256Hex(token));
    }
  });

  it('verifies a token exactly once', async () => {
    const { provider, sent } = setup();
    await provider.start('user@example.com');
    const token = sent[0]?.token as string;

    const user = await provider.verify(callback(token), env);
    expect(user?.id).toBe('user@example.com');
    expect(user?.email).toBe('user@example.com');
    expect(user?.subjectType).toBe('user');
    expect(user?.claims['provider']).toBe('magic-link');

    expect(await provider.verify(callback(token), env)).toBeNull();
  });

  it('rejects a token after its TTL', async () => {
    const { provider, sent } = setup({ ttlSec: 900 });
    await provider.start('user@example.com');
    const token = sent[0]?.token as string;

    now += 899_000;
    const stillValid = await provider.verify(callback(token), env);
    expect(stillValid).not.toBeNull();

    await provider.start('user@example.com');
    const second = sent[1]?.token as string;
    now += 901_000;
    expect(await provider.verify(callback(second), env)).toBeNull();
  });

  it('rejects an unknown or malformed token', async () => {
    const { provider } = setup();
    expect(await provider.verify(callback('not-a-real-token'), env)).toBeNull();
    expect(await provider.verify(new Request('https://app.example.com/auth/callback'), env)).toBeNull();
  });

  it('accepts the token from a JSON body too', async () => {
    const { provider, sent } = setup();
    await provider.start('user@example.com');
    const token = sent[0]?.token as string;

    const req = new Request('https://app.example.com/auth/session', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token }),
    });
    expect(await provider.verify(req, env)).not.toBeNull();
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
    expect(await provider.verify(callback(sent[0]?.token as string), env)).toBeNull();
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
    const user = await provider.verify(callback(sent[0]?.token as string), env);
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
      magicLink({ store: kvMagicLinkStore(env.KV), sendToken: undefined as never }),
    ).toThrow(/sendToken is required/);
  });

  it('rejects an unsafe table name', () => {
    expect(() => d1MagicLinkStore(env.DB, { table: 'x; DROP TABLE y' })).toThrow(
      /not a valid SQL identifier/,
    );
  });
});
