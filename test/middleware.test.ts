import { env } from 'cloudflare:test';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';

import { createAuth, getOptionalUser, getUser, type CreateAuthOptions } from '../src/index.js';
import { kvMagicLinkStore, magicLink } from '../src/providers/magic-link.js';
import { kvSessionStore } from '../src/store/kv.js';
import type { AuthProvider, AuthUser } from '../src/types.js';
import { resetStorage } from './helpers/reset.js';

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
    return { id, subjectType: 'user', email: `${id}@example.com`, claims: { provider: 'stub' } };
  },
};

function build(overrides: Partial<CreateAuthOptions> = {}) {
  const auth = createAuth({
    providers: [stubProvider],
    store: kvSessionStore(env.KV, { clock }),
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
  app.get('/open/who', (c) => c.json({ user: getOptionalUser(c) ?? null }));

  return { app, auth };
}

type Jar = { session?: string; csrf?: string };

/** `Headers.getSetCookie` exists in workerd but is missing from workers-types. */
function setCookies(res: Response): string[] {
  return (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
}

function readCookies(res: Response): Jar {
  const jar: Jar = {};
  for (const header of setCookies(res)) {
    const [pair] = header.split(';') as [string];
    const idx = pair.indexOf('=');
    const name = pair.slice(0, idx);
    const value = decodeURIComponent(pair.slice(idx + 1));
    if (name === '__Host-session') jar.session = value;
    if (name === '__Host-csrf') jar.csrf = value;
  }
  return jar;
}

function cookieHeader(jar: Jar): string {
  return [
    jar.session ? `__Host-session=${encodeURIComponent(jar.session)}` : null,
    jar.csrf ? `__Host-csrf=${encodeURIComponent(jar.csrf)}` : null,
  ]
    .filter(Boolean)
    .join('; ');
}

async function login(app: Hono, userId = 'user_1'): Promise<Jar> {
  const res = await app.fetch(
    new Request(`${ORIGIN}/auth/session`, {
      method: 'POST',
      headers: { origin: ORIGIN, 'x-test-user': userId },
    }),
  );
  expect(res.status).toBe(200);
  return readCookies(res);
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
    const cookies = setCookies(res);
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
    expect(JSON.stringify(body)).not.toContain(readCookies(res).session as string);
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
          'x-csrf-token': first.csrf as string,
        },
      }),
    );
    expect(second.status).toBe(200);
    const rotated = readCookies(second);
    expect(rotated.session).not.toBe(first.session);
    expect(rotated.csrf).not.toBe(first.csrf);

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
        headers: { origin: ORIGIN, cookie: `__Host-session=${jar.session as string}` },
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
          'x-csrf-token': jar.csrf as string,
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
        headers: { origin: ORIGIN, cookie: cookieHeader(jar), 'x-csrf-token': jar.csrf as string },
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

describe('GET /session', () => {
  it('reports the current session without leaking the id', async () => {
    const { app } = build();
    const jar = await login(app);

    const res = await app.fetch(
      new Request(`${ORIGIN}/auth/session`, { headers: { cookie: cookieHeader(jar) } }),
    );
    expect(res.status).toBe(200);
    const text = await res.text();
    expect(text).not.toContain(jar.session as string);
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
        headers: { origin: ORIGIN, cookie: cookieHeader(jar), 'x-csrf-token': jar.csrf as string },
      }),
    );
    expect(res.status).toBe(200);

    const cleared = setCookies(res);
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
        headers: { origin: ORIGIN, cookie: `__Host-session=${jar.session as string}` },
      }),
    );
    expect(res.status).toBe(403);

    const still = await app.fetch(
      new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }),
    );
    expect(still.status).toBe(200);
  });
});

describe('GET /callback', () => {
  it('mints a session from a magic-link token and redirects', async () => {
    const sent: string[] = [];
    const provider = magicLink({
      store: kvMagicLinkStore(env.KV, { clock }),
      sendToken: async (_email, token) => {
        sent.push(token);
      },
      clock,
    });
    const { app } = build({ providers: [provider], callbackRedirect: '/dashboard' });
    await provider.start('user@example.com');

    const res = await app.fetch(new Request(`${ORIGIN}/auth/callback?token=${sent[0] as string}`));
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe('/dashboard');

    const jar = readCookies(res);
    expect(jar.session).toBeDefined();

    const me = await app.fetch(new Request(`${ORIGIN}/api/me`, { headers: { cookie: cookieHeader(jar) } }));
    expect((await me.json()) as AuthUser).toMatchObject({ id: 'user@example.com' });
  });

  it('never redirects off-origin', async () => {
    const sent: string[] = [];
    const provider = magicLink({
      store: kvMagicLinkStore(env.KV, { clock }),
      sendToken: async (_email, token) => {
        sent.push(token);
      },
      clock,
    });
    const { app } = build({ providers: [provider] });

    for (const target of ['https://evil.example.com/', '//evil.example.com/', '/\\evil.example.com']) {
      await provider.start('user@example.com');
      const token = sent[sent.length - 1] as string;
      const res = await app.fetch(
        new Request(`${ORIGIN}/auth/callback?token=${token}&redirect_to=${encodeURIComponent(target)}`),
      );
      expect(res.status).toBe(302);
      expect(res.headers.get('location')).toBe('/');
    }
  });

  it('rejects a bad token', async () => {
    const { app } = build({
      providers: [
        magicLink({ store: kvMagicLinkStore(env.KV, { clock }), sendToken: async () => {}, clock }),
      ],
    });
    const res = await app.fetch(new Request(`${ORIGIN}/auth/callback?token=nope`));
    expect(res.status).toBe(401);
  });
});

describe('createAuth configuration', () => {
  it('requires both expiries', () => {
    const store = kvSessionStore(env.KV, { clock });
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
    const auth = createAuth({ providers: [], store: kvSessionStore(env.KV, { clock }) });
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
        store: kvSessionStore(env.KV, { clock }),
        callbackRedirect: 'https://evil.example.com',
      }),
    ).toThrow(/relative path/);
  });

  it('emits audit events with fingerprints, never raw ids', async () => {
    const events: Array<Record<string, unknown>> = [];
    const { app } = build({ onEvent: (e) => events.push(e as unknown as Record<string, unknown>) });
    const jar = await login(app);
    await app.fetch(
      new Request(`${ORIGIN}/auth/logout`, {
        method: 'POST',
        headers: { origin: ORIGIN, cookie: cookieHeader(jar), 'x-csrf-token': jar.csrf as string },
      }),
    );

    const types = events.map((e) => e['type']);
    expect(types).toContain('session.created');
    expect(types).toContain('session.revoked');
    expect(JSON.stringify(events)).not.toContain(jar.session as string);
    expect(JSON.stringify(events)).not.toContain(jar.csrf as string);
  });
});
