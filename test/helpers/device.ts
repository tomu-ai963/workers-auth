import { env } from 'cloudflare:test';
import { Hono } from 'hono';

import { randomToken } from '../../src/crypto.js';
import {
  d1DeviceAuthStore,
  deviceAuth,
  deviceBoundSessionStore,
  type DeviceAuthOptions,
} from '../../src/device-auth/index.js';
import { createAuth, getUser, type AuthEvent, type CreateAuthOptions } from '../../src/index.js';
import { sessionBearer } from '../../src/providers/session-bearer.js';
import { d1SessionStore } from '../../src/store/d1.js';
import { cookieHeader, readCookieJar, type CookieJar } from '../../src/testing.js';

export const ORIGIN = 'https://app.example.com';
export const T0 = 1_700_000_000_000;
export const SEC = 1000;
export const MIN = 60 * SEC;
export const HOUR = 60 * MIN;
export const DAY = 24 * HOUR;

export const time = { now: T0 };
export const clock = () => time.now;

/** Generated per run, never written down: a test secret is still a secret-shaped value. */
export const SECRET_A = randomToken(32);
export const SECRET_B = randomToken(32);

export type Harness = ReturnType<typeof setup>;

export function setup(
  overrides: Partial<DeviceAuthOptions> = {},
  authOverrides: Partial<CreateAuthOptions> = {},
) {
  const events: AuthEvent[] = [];
  const sent: Array<{ email: string; code: string }> = [];
  const store = d1DeviceAuthStore(env.DB, { clock });
  const sessionStore = deviceBoundSessionStore(d1SessionStore(env.DB, { clock }), store, { clock });
  const auth =
    overrides.auth ??
    createAuth({
      providers: [sessionBearer({ store: sessionStore })],
      store: sessionStore,
      clock,
      onEvent: (e) => events.push(e),
      ...authOverrides,
    });
  const device = deviceAuth({
    auth,
    store,
    secret: SECRET_A,
    transport: 'cookie',
    sendCode: async (email, code) => {
      sent.push({ email, code });
    },
    // Low cost keeps the suite fast; the default (100,000) has its own test.
    pin: { iterations: 1_000 },
    clock,
    ...overrides,
  });

  const app = new Hono();
  app.route('/auth/device', device.routes());
  app.route('/auth', auth.routes());
  app.use('/api/*', auth.middleware());
  app.get('/api/me', (c) => c.json(getUser(c)));
  app.post('/api/sensitive', device.requireFreshEmailAuth(), (c) => c.json({ ok: true }));

  const lastCode = (email: string) => {
    const hit = [...sent].reverse().find((m) => m.email === email);
    if (!hit) throw new Error(`no code sent to ${email}`);
    return hit.code;
  };

  return { app, auth, device, store, sessionStore, events, sent, lastCode };
}

export type Client = {
  jar: CookieJar;
  deviceToken?: string;
  sessionToken?: string;
  ip?: string;
  /** null = send no Origin header. */
  origin?: string | null;
};

export function client(init: Partial<Client> = {}): Client {
  return { jar: {}, ...init };
}

export type CallResult = { res: Response; status: number; body: Record<string, any> | null };

export async function call(
  h: Harness,
  c: Client,
  method: string,
  path: string,
  body?: unknown,
): Promise<CallResult> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (c.origin !== null) headers['origin'] = c.origin ?? ORIGIN;
  const cookie = cookieHeader(c.jar);
  if (cookie) headers['cookie'] = cookie;
  const csrf = c.jar['__Host-csrf'];
  if (csrf) headers['x-csrf-token'] = csrf;
  if (c.deviceToken) headers['x-device-token'] = c.deviceToken;
  if (c.sessionToken) headers['authorization'] = `Bearer ${c.sessionToken}`;
  if (c.ip) headers['cf-connecting-ip'] = c.ip;

  const res = await h.app.fetch(
    new Request(`${ORIGIN}${path}`, {
      method,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    }),
    env,
  );
  for (const [name, value] of Object.entries(readCookieJar(res))) {
    if (value) c.jar[name] = value;
    else delete c.jar[name];
  }
  const json = (await res
    .clone()
    .json()
    .catch(() => null)) as Record<string, any> | null;
  if (typeof json?.['deviceToken'] === 'string') c.deviceToken = json['deviceToken'];
  if (typeof json?.['sessionToken'] === 'string') c.sessionToken = json['sessionToken'];
  return { res, status: res.status, body: json };
}

/** start -> read the delivered code -> verify. */
export async function loginByEmail(
  h: Harness,
  c: Client,
  email: string,
  extra: Record<string, unknown> = {},
): Promise<CallResult> {
  const start = await call(h, c, 'POST', '/auth/device/email/start', { email });
  if (start.status !== 200) throw new Error(`email/start failed: ${start.status} ${JSON.stringify(start.body)}`);
  return call(h, c, 'POST', '/auth/device/email/verify', { email, code: h.lastCode(email), ...extra });
}

/** A fresh account with a trusted device and `pin` set. */
export async function enrolled(h: Harness, email: string, pin = '482915', init: Partial<Client> = {}) {
  const c = client(init);
  const verified = await loginByEmail(h, c, email);
  if (verified.status !== 200) throw new Error(`email/verify failed: ${JSON.stringify(verified.body)}`);
  const set = await call(h, c, 'POST', '/auth/device/pin', { pin });
  if (set.status !== 200) throw new Error(`pin set failed: ${JSON.stringify(set.body)}`);
  return c;
}

export function pinLogin(h: Harness, c: Client, pin: string) {
  return call(h, c, 'POST', '/auth/device/pin/login', { pin });
}
