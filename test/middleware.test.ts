import { env } from 'cloudflare:test';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';

import { createAuth, getOptionalUser, getSession, getUser, type CreateAuthOptions } from '../src/index.js';
import { d1MagicLinkStore, magicLink } from '../src/providers/magic-link.js';
import { kvSessionStore } from '../src/store/kv.js';
import { cookieHeader, getSetCookies, loginForCookies, readCookieJar, type CookieJar } from '../src/testing.js';
import type { AuthProvider, AuthUser } from '../src/types.js';
import { resetStorage } from './helpers/reset.js';

// This suite always uses the default cookie config, so the two cookie names
// are fixed. `readCookieJar`/`cookieHeader` don't assume any particular
// name — see src/testing.ts — so these are what let a handful of assertions
// below read a specific value back out of the jar.
const SESSION_COOKIE = '__Host-session';
const CSRF_COOKIE = '__Host-csrf';

const DAY = 60 * 60 * 24;
const ORIGIN = 'https://app.example.com';

let now = 1_700_000_000_000;
const clock = () => now;

/** Minimal provider: trusts a test header, so the middleware is what is tested. */
const stubProvider: AuthProvider = {
  name: 'stub',
  async verify(req) {
    const id = req.headers.get('x-test-user');
    if (!id) return null;
    return { id, subjectType: 'user', rateLimitId: id, email: `${id}@example.com`, claims: { provider: 'stub' } };
  },
};

function build(overrides: Partial<CreateAuthOptions> = {}) {
  const auth = createAuth({
    providers: [stubProvider],
    store: kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true }),
    session: { idleTtlSec: 7 * DAY, absoluteTtlSec: 30 * DAY, touchIntervalSec: 60 },
    clock,
    ...overrides,
  });

  const app = new Hono();
  app.use('/api/*', auth.middleware());
  app.use('/open/*', auth.middleware({ optional: true }));
  app.route('/auth', auth.routes());
  app.get('/api/me', (c) => c.json(getUser(c)));
  app.post('/api/things', (c) => c.json({ created: true }));
  app.get('/api/session-view', (c) => c.json({ session: getSession(c) }));
  app.get('/open/who', (c) => c.json({ user: getOptionalUser(c) ?? null }));

  // Lets a test drive `auth.createSession` with application-supplied metadata.
  app.post('/test/login', async (c) => {
    const meta = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    await auth.createSession(
      c,
      { id: 'user_x', subjectType: 'user', rateLimitId: 'user_x', claims: {} },
      { meta },
    );
    return c.json({ ok: true });
  });

  return { app, auth };
}

/**
 * Provider-specific (the `x-test-user` header only `stubProvider` above
 * understands), so it stays local — only the cookie-jar mechanics it uses
 * (`loginForCookies`, `readCookieJar`, `cookieHeader`) come from
 * `src/testing.js`.
 */
async function login(app: Hono, userId = 'user_1'): Promise<CookieJar> {
  return loginForCookies(
    (req) => app.fetch(req),
    new Request(`${ORIGIN}/auth/session`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'x-test-user': userId },
    }),
  );
}

beforeEach(async () => {
  now = 1_700_000_000_000;
  await resetStorage();
});

describe('middleware', () => {
  it('answers 401 with a uniform body when unauthenticated', async () => {
    const { app } = build();
    const res = await app.fetch(new Request(`${ORIGIN}/api/me`));
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthenticated' });
  });

  it('lets unauthenticated requests through in optional mode', async () => {
    const { app } = build();
    const res = await app.fetch(new Request(`${ORIGIN}/open/who`));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ user: null });
  });

  it('exposes the subject in optional mode when credentials are present', async () => {
    const { app } = build();
    const res = await app.fetch(
      new Request(`${ORIGIN}/open/who`, { headers: { 'x-test-user': 'user_9' } }),
    );
    const body = (await res.json()) as { user: AuthUser | null };
    expect(body.user?.id).toBe('user_9');
  });

  it('authenticates a bearer-style provider without any cookie', async () => {
    const { app } = build();
    const res = await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { 'x-test-user': 'u1' } }));
    expect(res.status).toBe(200);
    expect((await res.json()) as AuthUser).toMatchObject({ id: 'u1', subjectType: 'user' });
  });

  it('does not require CSRF for a credential-carrying request with no cookies', async () => {
    const { app } = build();
    const res = await app.fetch(
      new Request(`${ORIGIN}/api/things`, { method: 'POST', headers: { 'x-test-user': 'svc' } }),
    );
    expect(res.status).toBe(200);
  });
});

describe('POST /session', () => {
  it('sets a hardened session cookie pair', async () => {
    const { app } = build();
    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/session`, {
        method: 'POST',
        headers: { origin: ORIGIN, 'x-test-user': 'user_1' },
      }),
    );

    expect(res.status).toBe(200);
    const cookies = getSetCookies(res);
    expect(cookies).toHaveLength(2);

    const session = cookies.find((c) => c.startsWith('__Host-session=')) as string;
    expect(session).toContain('HttpOnly');
    expect(session).toContain('Secure');
    expect(session).toContain('SameSite=Lax');
    expect(session).toContain('Path=/');
    expect(session).not.toContain('Domain=');

    const csrf = cookies.find((c) => c.startsWith('__Host-csrf=')) as string;
    expect(csrf).toContain('Secure');
    expect(csrf).toContain('SameSite=Lax');
    expect(csrf).not.toContain('HttpOnly');

    const body = (await res.json()) as { user: AuthUser; session: Record<string, unknown> };
    expect(body.user.id).toBe('user_1');
    expect(JSON.stringify(body)).not.toContain(readCookieJar(res)[SESSION_COOKIE] as string);
    expect(body.session['sid']).toBeUndefined();
  });

  it('rejects credentials it cannot verify', async () => {
    const { app } = build();
    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/session`, { method: 'POST', headers: { origin: ORIGIN } }),
    );
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthenticated' });
  });

  it('requires an Origin header even for the first login', async () => {
    const { app } = build();
    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/session`, { method: 'POST', headers: { 'x-test-user': 'user_1' } }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'csrf_failed' });
  });

  it('refuses a re-login that reuses cookies without the CSRF token', async () => {
    const { app } = build();
    const first = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/session`, {
        method: 'POST',
        headers: { origin: ORIGIN, 'x-test-user': 'user_1', cookie: cookieHeader(first) },
      }),
    );
    expect(res.status).toBe(403);
  });

  it('rotates the session id on re-login', async () => {
    const { app } = build();
    const first = await login(app);
    const second = await app.fetch(
      new Request(`${ORIGIN}/auth/session`, {
        method: 'POST',
        headers: {
          origin: ORIGIN,
          'x-test-user': 'user_1',
          cookie: cookieHeader(first),
          'x-csrf-token': first[CSRF_COOKIE] as string,
        },
      }),
    );
    expect(second.status).toBe(200);
    const rotated = readCookieJar(second);
    expect(rotated[SESSION_COOKIE]).not.toBe(first[SESSION_COOKIE]);
    expect(rotated[CSRF_COOKIE]).not.toBe(first[CSRF_COOKIE]);

    // The old session is gone, not merely shadowed.
    const stale = await app.fetch(
      new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(first) } }),
    );
    expect(stale.status).toBe(401);
  });
});

describe('cookie sessions', () => {
  it('authenticates subsequent requests', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }));
    expect(res.status).toBe(200);
    expect((await res.json()) as AuthUser).toMatchObject({
      id: 'user_1',
      email: 'user_1@example.com',
      subjectType: 'user',
    });
  });

  it('rejects a POST with no CSRF token', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/api/things`, {
        method: 'POST',
        headers: { origin: ORIGIN, cookie: `__Host-session=${jar[SESSION_COOKIE] as string}` },
      }),
    );
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'csrf_failed' });
  });

  it('rejects a POST whose CSRF token does not match the cookie', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/api/things`, {
        method: 'POST',
        headers: { origin: ORIGIN, cookie: cookieHeader(jar), 'x-csrf-token': 'wrong' },
      }),
    );
    expect(res.status).toBe(403);
  });

  it('rejects a POST from another origin', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/api/things`, {
        method: 'POST',
        headers: {
          origin: 'https://evil.example.com',
          cookie: cookieHeader(jar),
          'x-csrf-token': jar[CSRF_COOKIE] as string,
        },
      }),
    );
    expect(res.status).toBe(403);
  });

  it('accepts a POST with a matching Origin and token', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/api/things`, {
        method: 'POST',
        headers: { origin: ORIGIN, cookie: cookieHeader(jar), 'x-csrf-token': jar[CSRF_COOKIE] as string },
      }),
    );
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ created: true });
  });

  it('slides the idle window at most once per touch interval', async () => {
    const { app } = build();
    const jar = await login(app);

    const read = async () => {
      const res = await app.fetch(
        new Request(`${ORIGIN}/auth/session`, { headers: { cookie: cookieHeader(jar) } }),
      );
      return (await res.json()) as { session: { idleExpiresAt: number } };
    };

    const initial = (await read()).session.idleExpiresAt;

    now += 30_000; // inside the interval: no write
    await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }));
    expect((await read()).session.idleExpiresAt).toBe(initial);

    now += 61_000; // past the interval: the window moves
    await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }));
    expect((await read()).session.idleExpiresAt).toBe(now + 7 * DAY * 1000);
  });

  it('stops accepting a session past its absolute expiry', async () => {
    const { app } = build();
    const jar = await login(app);

    now += 31 * DAY * 1000;
    const res = await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }));
    expect(res.status).toBe(401);
  });
});

describe('rateLimitId', () => {
  it('survives a second request that never re-runs the provider', async () => {
    const { app } = build();
    const jar = await login(app, 'user_1');

    // The first read comes back from `sessionToUser` rebuilding off the
    // cookie session, same as every request after login — `stubProvider`
    // only runs on POST /session itself.
    const first = (await (
      await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }))
    ).json()) as AuthUser;
    const second = (await (
      await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }))
    ).json()) as AuthUser;
    expect(first.rateLimitId).toBe('user_1');
    expect(second.rateLimitId).toBe('user_1');
  });

  it('persists into session meta even when storeUserClaims is off', async () => {
    const { app } = build({ storeUserClaims: false });
    const jar = await login(app, 'user_2');

    const user = (await (
      await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }))
    ).json()) as AuthUser;
    // Unlike full claims (gated by storeUserClaims — see SECURITY.md "Known
    // limits"), rateLimitId round-trips through the session unconditionally.
    expect(user.rateLimitId).toBe('user_2');
  });

  it('falls back to userId when reconstructing a session written before rateLimitId existed', async () => {
    const store = kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true });
    const auth = createAuth({
      providers: [stubProvider],
      store,
      session: { idleTtlSec: 7 * DAY, absoluteTtlSec: 30 * DAY, touchIntervalSec: 60 },
      clock,
    });
    const app = new Hono();
    app.use('/api/*', auth.middleware());
    app.get('/api/me', (c) => c.json(getUser(c)));

    // Stand-in for a session record written by a pre-upgrade deploy: no
    // `rateLimitId` under `meta.__auth` at all, since that key didn't exist
    // yet when the session was created.
    const session = await store.create({
      userId: 'legacy_user',
      subjectType: 'user',
      idleTtlSec: 7 * DAY,
      absoluteTtlSec: 30 * DAY,
      meta: { __auth: { email: 'legacy@example.com' } },
    });

    const res = await app.fetch(
      new Request(`${ORIGIN}/api/me`, { headers: { cookie: `${SESSION_COOKIE}=${session.sid}` } }),
    );
    expect(res.status).toBe(200);
    expect(((await res.json()) as AuthUser).rateLimitId).toBe('legacy_user');
  });

  it('fails closed, with an auditable reason, when a provider omits it', async () => {
    const brokenProvider: AuthProvider = {
      name: 'broken',
      async verify(req) {
        if (!req.headers.get('x-broken')) return null;
        // Simulates a plain-JS caller ignoring the TypeScript contract.
        return { id: 'x', subjectType: 'user', claims: {} } as AuthUser;
      },
    };
    const events: Array<Record<string, unknown>> = [];
    const { app } = build({
      providers: [brokenProvider],
      onEvent: (e) => events.push(e as unknown as Record<string, unknown>),
    });

    const res = await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { 'x-broken': '1' } }));
    expect(res.status).toBe(401);
    expect(
      events.some((e) => e['type'] === 'auth.failed' && e['provider'] === 'broken'),
    ).toBe(true);
  });
});

describe('GET /session', () => {
  it('reports the current session without leaking the id', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/session`, { headers: { cookie: cookieHeader(jar) } }),
    );
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain(jar[SESSION_COOKIE] as string);
    expect(JSON.parse(text)).toMatchObject({
      user: { id: 'user_1' },
      session: { userId: 'user_1', subjectType: 'user' },
    });
  });

  it('is 401 without a session', async () => {
    const { app } = build();
    const res = await app.fetch(new Request(`${ORIGIN}/auth/session`));
    expect(res.status).toBe(401);
  });
});

describe('POST /logout', () => {
  it('revokes the session and clears both cookies', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/logout`, {
        method: 'POST',
        headers: { origin: ORIGIN, cookie: cookieHeader(jar), 'x-csrf-token': jar[CSRF_COOKIE] as string },
      }),
    );
    expect(res.status).toBe(200);

    const cleared = getSetCookies(res);
    expect(cleared.every((c) => c.includes('Max-Age=0'))).toBe(true);
    expect(cleared.some((c) => c.startsWith('__Host-session='))).toBe(true);
    expect(cleared.some((c) => c.startsWith('__Host-csrf='))).toBe(true);

    const after = await app.fetch(
      new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }),
    );
    expect(after.status).toBe(401);
  });

  it('refuses to log out without a CSRF token', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/logout`, {
        method: 'POST',
        headers: { origin: ORIGIN, cookie: `__Host-session=${jar[SESSION_COOKIE] as string}` },
      }),
    );
    expect(res.status).toBe(403);

    const still = await app.fetch(
      new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }),
    );
    expect(still.status).toBe(200);
  });
});

function magicLinkSetup() {
  const sent: string[] = [];
  const provider = magicLink({
    store: d1MagicLinkStore(env.DB, { clock }),
    sendToken: async (_email, token) => {
      sent.push(token);
    },
    allowTokenInQuery: true,
    clock,
  });
  return { provider, sent, last: () => sent[sent.length - 1] as string };
}

describe('GET /callback', () => {
  it('mints a session from a magic-link token and redirects', async () => {
    const { provider, sent } = magicLinkSetup();
    const { app } = build({
      providers: [],
      callbackProviders: [provider],
      callbackRedirect: '/dashboard',
    });
    await provider.start('user@example.com');

    const res = await app.fetch(new Request(`${ORIGIN}/auth/callback?token=${sent[0] as string}`));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/dashboard');

    const jar = readCookieJar(res);
    expect(jar[SESSION_COOKIE]).toBeDefined();

    const me = await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }));
    expect((await me.json()) as AuthUser).toMatchObject({ id: 'user@example.com' });
  });

  it('never redirects off-origin', async () => {
    const { provider, last } = magicLinkSetup();
    const { app } = build({ providers: [], callbackProviders: [provider] });

    for (const target of ['https://evil.example.com/', '//evil.example.com/', '/\\evil.example.com']) {
      await provider.start('user@example.com');
      const res = await app.fetch(
        new Request(`${ORIGIN}/auth/callback?token=${last()}&redirect_to=${encodeURIComponent(target)}`),
      );
      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toBe('/');
    }
  });

  it('rejects a bad token', async () => {
    const { provider } = magicLinkSetup();
    const { app } = build({ providers: [], callbackProviders: [provider] });
    const res = await app.fetch(new Request(`${ORIGIN}/auth/callback?token=nope`));
    expect(res.status).toBe(401);
  });

  it('is not mounted at all without callbackProviders', async () => {
    const { app } = build();
    const res = await app.fetch(new Request(`${ORIGIN}/auth/callback?token=whatever`));
    expect(res.status).toBe(404);
  });
});

/**
 * Regression: a magic-link token used to be readable from `?token=` by every
 * provider run, so any route both accepted it and consumed it.
 */
describe('URL-borne credentials are confined to /callback', () => {
  it('refuses a query token on GET /auth/session and leaves it unspent', async () => {
    const { provider, sent } = magicLinkSetup();
    const { app } = build({ providers: [], callbackProviders: [provider] });
    await provider.start('victim@example.com');
    const token = sent[0] as string;

    const probe = await app.fetch(new Request(`${ORIGIN}/auth/session?token=${token}`));
    expect(probe.status).toBe(401);

    // The real link still works afterwards.
    const login = await app.fetch(new Request(`${ORIGIN}/auth/callback?token=${token}`));
    expect(login.status).toBe(302);
  });

  it('refuses a query token on an application route and leaves it unspent', async () => {
    const { provider, sent } = magicLinkSetup();
    const { app } = build({ providers: [], callbackProviders: [provider] });
    await provider.start('victim@example.com');
    const token = sent[0] as string;

    const probe = await app.fetch(new Request(`${ORIGIN}/api/me?token=${token}`));
    expect(probe.status).toBe(401);

    const login = await app.fetch(new Request(`${ORIGIN}/auth/callback?token=${token}`));
    expect(login.status).toBe(302);
  });

  it('refuses to register a URL-reading provider on every route', () => {
    const { provider } = magicLinkSetup();
    expect(() => build({ providers: [provider] })).toThrow(/callbackProviders/);
  });
});

describe('auth responses are never cacheable', () => {
  it('marks every route and every rejection no-store', async () => {
    const { app } = build();
    const jar = await login(app);

    const responses = [
      await app.fetch(new Request(`${ORIGIN}/auth/session`, { headers: { cookie: cookieHeader(jar) } })),
      await app.fetch(new Request(`${ORIGIN}/auth/session`)),
      await app.fetch(
        new Request(`${ORIGIN}/auth/session`, {
          method: 'POST',
          headers: { origin: ORIGIN, 'x-test-user': 'user_1' },
        }),
      ),
      await app.fetch(new Request(`${ORIGIN}/auth/logout`, { method: 'POST' })),
      await app.fetch(new Request(`${ORIGIN}/api/me`)),
      await app.fetch(
        new Request(`${ORIGIN}/api/things`, {
          method: 'POST',
          headers: { origin: ORIGIN, cookie: cookieHeader(jar) },
        }),
      ),
    ];

    for (const res of responses) {
      expect(res.headers.get('cache-control')).toBe('no-store, private');
      expect(res.headers.get('vary')).toBe('Cookie, Authorization');
    }
    // The last two are the middleware's own 401 / 403.
    expect(responses[4]?.status).toBe(401);
    expect(responses[5]?.status).toBe(403);
  });
});

/** Regression: `c.get('authSession').sid` used to expose the raw credential. */
describe('the raw session id never reaches application code', () => {
  it('strips sid from the context session', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/api/session-view`, { headers: { cookie: cookieHeader(jar) } }),
    );
    const body = (await res.json()) as { session: Record<string, unknown> };
    expect(body.session.userId).toBe('user_1');
    expect('sid' in body.session).toBe(false);
    expect(JSON.stringify(body)).not.toContain(jar[SESSION_COOKIE] as string);
  });
});

describe('createSession meta namespace', () => {
  it('rejects application metadata that collides with the reserved key', async () => {
    const { app } = build();
    const res = await app.fetch(
      new Request(`${ORIGIN}/test/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ __auth: { email: 'attacker@evil.com' } }),
      }),
    );
    expect(res.status).toBe(500);
  });

  it('does not let application metadata promote itself into an authenticated attribute', async () => {
    const { app } = build();
    const res = await app.fetch(
      new Request(`${ORIGIN}/test/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'spoofed@evil.com', provider: 'spoofed' }),
      }),
    );
    expect(res.status).toBe(200);
    const jar = readCookieJar(res);

    const me = await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }));
    const user = (await me.json()) as AuthUser;
    expect(user.email).toBeUndefined();
    expect(user.claims['provider']).toBeUndefined();
  });
});

describe('createAuth configuration', () => {
  it('requires both expiries', () => {
    const store = kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true });
    expect(() =>
      createAuth({ providers: [], store, session: { idleTtlSec: 3600 } as never }),
    ).toThrow(/absoluteTtlSec/);
    expect(() =>
      createAuth({ providers: [], store, session: { absoluteTtlSec: 3600 } as never }),
    ).toThrow(/idleTtlSec/);
    expect(() =>
      createAuth({ providers: [], store, session: { idleTtlSec: 7200, absoluteTtlSec: 3600 } }),
    ).toThrow(/must be >=/);
  });

  it('defaults to 7 day idle / 30 day absolute', () => {
    const auth = createAuth({ providers: [], store: kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true }) });
    expect(auth.config.session).toEqual({
      idleTtlSec: 7 * DAY,
      absoluteTtlSec: 30 * DAY,
      touchIntervalSec: 60,
    });
  });

  it('rejects an off-origin callback redirect', () => {
    expect(() =>
      createAuth({
        providers: [],
        store: kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true }),
        callbackRedirect: 'https://evil.example.com',
      }),
    ).toThrow(/relative path/);
  });

  it('rejects a basePath that is not a bare leading-slash path', () => {
    const store = kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true });
    expect(() => createAuth({ providers: [], store, basePath: 'auth' })).toThrow(/basePath/);
    expect(() => createAuth({ providers: [], store, basePath: '//auth' })).toThrow(/basePath/);
    expect(() => createAuth({ providers: [], store, basePath: '/auth/' })).toThrow(/basePath/);
  });

  it('leaves basePath unset by default', () => {
    const auth = createAuth({ providers: [], store: kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true }) });
    expect(auth.config.basePath).toBeUndefined();
  });

  it('emits audit events with fingerprints, never raw ids', async () => {
    const events: Array<Record<string, unknown>> = [];
    const { app } = build({ onEvent: (e) => events.push(e as unknown as Record<string, unknown>) });
    const jar = await login(app);
    await app.fetch(
      new Request(`${ORIGIN}/auth/logout`, {
        method: 'POST',
        headers: { origin: ORIGIN, cookie: cookieHeader(jar), 'x-csrf-token': jar[CSRF_COOKIE] as string },
      }),
    );

    const types = events.map((e) => e['type']);
    expect(types).toContain('session.created');
    expect(types).toContain('session.revoked');
    expect(JSON.stringify(events)).not.toContain(jar[SESSION_COOKIE] as string);
    expect(JSON.stringify(events)).not.toContain(jar[CSRF_COOKIE] as string);
  });
});

/**
 * `app.route('/auth', auth.routes())` is exercised by every other test in
 * this file via `build()`. This block covers the other supported mounting
 * style: `createAuth()` built per request, with its sub-app handed a raw
 * request directly (`auth.routes().fetch(...)`) instead of going through
 * `app.route()`. Without `basePath`, that style 404s — reproducing the bug
 * command-kun hit — because `auth.routes()` registers bare paths like
 * `/session` and nothing strips the `/auth` prefix off the incoming request
 * before it reaches that sub-app's own router.
 */
describe('basePath: mounting auth.routes() by delegating .fetch() directly', () => {
  function buildDelegated(basePath?: string) {
    const auth = createAuth({
      providers: [stubProvider],
      store: kvSessionStore(env.KV, { clock, allowUnrevocableSessions: true }),
      session: { idleTtlSec: 7 * DAY, absoluteTtlSec: 30 * DAY, touchIntervalSec: 60 },
      clock,
      ...(basePath !== undefined ? { basePath } : {}),
    });

    const app = new Hono();
    app.all('/auth/*', (c) => auth.routes().fetch(c.req.raw, c.env));
    return app;
  }

  it('without basePath, direct delegation 404s on every /auth/* route', async () => {
    const app = buildDelegated();
    const res = await app.fetch(new Request(`${ORIGIN}/auth/session`, { method: 'GET' }));
    expect(res.status).toBe(404);
  });

  it('with basePath set to the mount point, the route is reached', async () => {
    const app = buildDelegated('/auth');
    const res = await app.fetch(new Request(`${ORIGIN}/auth/session`, { method: 'GET' }));
    // 401 (no session cookie) rather than 404 confirms the route matched.
    expect(res.status).toBe(401);
  });

  it('a full login round-trip works through the delegated, basePath-scoped app', async () => {
    const app = buildDelegated('/auth');
    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/session`, {
        method: 'POST',
        headers: { origin: ORIGIN, 'x-test-user': 'user_1' },
      }),
    );
    expect(res.status).toBe(200);
    const setCookie = (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
    expect(setCookie).toHaveLength(2);
  });
});
