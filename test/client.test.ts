import { afterEach, describe, expect, it } from 'vitest';

import clientSource from '../src/client.ts?raw';
import { AuthClientError, createAuthClient, type ClientFetch, type ClientRequestInit } from '../src/client.js';

type Call = { url: string; init: ClientRequestInit | undefined };

function recorder(handler: (call: Call) => unknown = () => ({ user: { id: 'u1' }, session: null })) {
  const calls: Call[] = [];
  let release: (() => void) | undefined;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  const fetchImpl: ClientFetch = async (url, init) => {
    calls.push({ url, init });
    const body = handler({ url, init });
    if (body === 'hold') {
      await gate;
      return { ok: true, status: 200, json: async () => ({ user: { id: 'u1' }, session: null }) };
    }
    if (typeof body === 'number') {
      return { ok: false, status: body, json: async () => ({ error: 'unauthenticated' }) };
    }
    return { ok: true, status: 200, json: async () => body };
  };

  return { calls, fetchImpl, release: () => release?.() };
}

const definedGlobals: string[] = [];

function stubDocument(cookie: string): void {
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { cookie } });
  definedGlobals.push('document');
}

afterEach(() => {
  for (const name of definedGlobals.splice(0)) {
    delete (globalThis as Record<string, unknown>)[name];
  }
});

describe('createAuthClient', () => {
  it('collapses concurrent session() calls into one request', async () => {
    const { calls, fetchImpl, release } = recorder(() => 'hold');
    const client = createAuthClient({ fetchImpl });

    const pending = Promise.all([client.session(), client.session(), client.session()]);
    expect(calls).toHaveLength(1);

    release();
    const results = await pending;
    expect(calls).toHaveLength(1);
    expect(results[0]).toEqual(results[1]);
    expect(results[2]).toEqual(results[0]);
  });

  it('does not cache: a later call hits the network again', async () => {
    const { calls, fetchImpl } = recorder();
    const client = createAuthClient({ fetchImpl });

    await client.session();
    await client.session();
    expect(calls).toHaveLength(2);
  });

  it('never merges state-changing calls', async () => {
    const { calls, fetchImpl } = recorder(() => ({ ok: true }));
    const client = createAuthClient({ fetchImpl });

    await Promise.all([client.logout(), client.logout()]);
    expect(calls).toHaveLength(2);
  });

  it('sends cookies and defeats intermediate caches', async () => {
    const { calls, fetchImpl } = recorder();
    await createAuthClient({ fetchImpl }).session();

    expect(calls[0]?.url).toBe('/auth/session');
    expect(calls[0]?.init?.credentials).toBe('include');
    expect(calls[0]?.init?.cache).toBe('no-store');
    expect(calls[0]?.init?.headers?.['accept']).toBe('application/json');
  });

  it('returns null instead of throwing on 401', async () => {
    const { fetchImpl } = recorder(() => 401);
    expect(await createAuthClient({ fetchImpl }).session()).toBeNull();
  });

  it('surfaces other failures as AuthClientError', async () => {
    const { fetchImpl } = recorder(() => 403);
    await expect(createAuthClient({ fetchImpl }).logout()).rejects.toBeInstanceOf(AuthClientError);
  });

  it('echoes the CSRF cookie back as a header', async () => {
    stubDocument('__Host-csrf=tok-123; other=x');
    const { calls, fetchImpl } = recorder(() => ({ ok: true }));
    const client = createAuthClient({ fetchImpl });

    expect(client.csrfToken()).toBe('tok-123');
    await client.logout();
    expect(calls[0]?.init?.headers?.['x-csrf-token']).toBe('tok-123');
  });

  it('works without a document at all', async () => {
    const { calls, fetchImpl } = recorder(() => ({ ok: true }));
    const client = createAuthClient({ fetchImpl });
    expect(client.csrfToken()).toBeNull();
    await client.logout();
    expect(calls[0]?.init?.headers?.['x-csrf-token']).toBeUndefined();
  });

  it('honours a custom baseUrl', async () => {
    const { calls, fetchImpl } = recorder();
    await createAuthClient({ baseUrl: 'https://api.example.com/auth/', fetchImpl }).session();
    expect(calls[0]?.url).toBe('https://api.example.com/auth/session');
  });
});

describe('client constraints', () => {
  /** Comments talk about these APIs on purpose; only real code must be clean. */
  const codeOnly = clientSource.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  it.each([
    'localStorage',
    'sessionStorage',
    'indexedDB',
    'BroadcastChannel',
    'setInterval',
    'setTimeout',
    'addEventListener',
  ])('does not reference %s', (api) => {
    expect(codeOnly).not.toContain(api);
  });

  it('touches none of those globals at runtime either', async () => {
    const trapped = ['localStorage', 'sessionStorage', 'indexedDB', 'BroadcastChannel'];
    for (const name of trapped) {
      Object.defineProperty(globalThis, name, {
        configurable: true,
        get() {
          throw new Error(`client touched ${name}`);
        },
      });
      definedGlobals.push(name);
    }

    stubDocument('__Host-csrf=tok');
    const { fetchImpl } = recorder(() => ({ ok: true }));
    const client = createAuthClient({ fetchImpl });

    await expect(client.session()).resolves.toBeDefined();
    await expect(client.logout()).resolves.toBeUndefined();
    expect(client.csrfToken()).toBe('tok');
  });
});
