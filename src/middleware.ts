/**
 * Hono middleware: resolve the session, enforce CSRF, publish the subject.
 */

import type { Context, MiddlewareHandler, Next } from 'hono';

import { parseCookies, serializeCookie, serializeCookieDeletion, type ResolvedCookieConfig } from './cookie.js';
import { issueCsrfToken, verifyCsrf } from './csrf.js';
import type {
  AuthUser,
  Clock,
  CsrfConfig,
  AuthProvider,
  Session,
  SessionStore,
  SubjectType,
} from './types.js';

declare module 'hono' {
  interface ContextVariableMap {
    /**
     * The authenticated subject. Guaranteed present inside a non-optional
     * middleware; may be undefined at runtime under `{ optional: true }` —
     * use {@link getOptionalUser} there.
     */
    user: AuthUser;
    /** The cookie session, or null when the subject authenticated by bearer. */
    authSession: Session | null;
  }
}

export type ResolvedSessionConfig = {
  idleTtlSec: number;
  absoluteTtlSec: number;
  touchIntervalSec: number;
};

export type ResolvedAuthConfig = {
  providers: AuthProvider[];
  store: SessionStore;
  cookie: ResolvedCookieConfig;
  session: ResolvedSessionConfig;
  csrf: CsrfConfig;
  clock: Clock;
  /** Persist the provider's full claim set into the session record. */
  storeUserClaims: boolean;
  /** Relative path used by `GET /callback` on success. */
  callbackRedirect: string;
  onEvent: (event: AuthEvent) => void;
};

export type AuthEvent =
  | { type: 'session.created'; userId: string; subjectType: SubjectType; sidFingerprint: string }
  | { type: 'session.revoked'; sidFingerprint: string }
  | { type: 'auth.failed'; reason: string; provider?: string }
  | { type: 'csrf.failed'; reason: string };

export type MiddlewareOptions = {
  /** Allow unauthenticated requests through instead of answering 401. */
  optional?: boolean;
};

/** The single failure body. Never says which check failed. */
export function unauthorizedBody(): { error: 'unauthenticated' } {
  return { error: 'unauthenticated' };
}

export function getUser(c: Context): AuthUser {
  const user = c.get('user') as AuthUser | undefined;
  if (!user) throw new Error('getUser: no authenticated user on this context');
  return user;
}

export function getOptionalUser(c: Context): AuthUser | undefined {
  return c.get('user') as AuthUser | undefined;
}

export function getSession(c: Context): Session | null {
  return (c.get('authSession') as Session | null | undefined) ?? null;
}

export function sessionToUser(session: Session): AuthUser {
  const meta = (session.meta ?? {}) as { email?: unknown; claims?: unknown; provider?: unknown };
  const claims = (meta.claims && typeof meta.claims === 'object' ? meta.claims : {}) as Record<string, unknown>;
  return {
    id: session.userId,
    subjectType: session.subjectType,
    ...(typeof meta.email === 'string' ? { email: meta.email } : {}),
    claims: {
      ...claims,
      ...(typeof meta.provider === 'string' ? { provider: meta.provider } : {}),
    },
  };
}

/** Runs the providers in order and returns the first success. */
export async function verifyProviders(
  providers: readonly AuthProvider[],
  req: Request,
  env: unknown,
  onEvent?: (event: AuthEvent) => void,
): Promise<AuthUser | null> {
  for (const provider of providers) {
    try {
      const user = await provider.verify(req, env);
      if (user) return user;
    } catch (error) {
      // A broken provider must not authenticate anyone, and must not stop the
      // next provider from being tried.
      onEvent?.({
        type: 'auth.failed',
        reason: error instanceof Error ? error.name : 'provider_error',
        provider: provider.name,
      });
    }
  }
  return null;
}

export function setSessionCookies(
  c: Context,
  config: ResolvedAuthConfig,
  sid: string,
  csrfToken: string,
  maxAgeSec: number,
): void {
  const base = { secure: config.cookie.secure, sameSite: config.cookie.sameSite, path: '/' as const };
  c.header(
    'set-cookie',
    serializeCookie(config.cookie.sessionCookieName, sid, {
      ...base,
      httpOnly: true,
      maxAge: maxAgeSec,
    }),
    { append: true },
  );
  // The CSRF token must be readable by the page's own JS to be echoed back in
  // a header — that is the whole point of double-submit. It is not a
  // credential on its own.
  c.header(
    'set-cookie',
    serializeCookie(config.cookie.csrfCookieName, csrfToken, {
      ...base,
      httpOnly: false,
      maxAge: maxAgeSec,
    }),
    { append: true },
  );
}

export function clearSessionCookies(c: Context, config: ResolvedAuthConfig): void {
  const base = { secure: config.cookie.secure, sameSite: config.cookie.sameSite, path: '/' as const };
  c.header('set-cookie', serializeCookieDeletion(config.cookie.sessionCookieName, { ...base, httpOnly: true }), {
    append: true,
  });
  c.header('set-cookie', serializeCookieDeletion(config.cookie.csrfCookieName, { ...base, httpOnly: false }), {
    append: true,
  });
}

export { issueCsrfToken };

export type CookieSession = {
  session: Session | null;
  csrfCookie: string | undefined;
};

/**
 * Reads only the cookie session — no providers are consulted. Kept separate
 * because provider verification can have side effects (a magic-link token is
 * single-use), so it must run exactly once per request.
 */
export async function readCookieSession(
  c: Context,
  config: ResolvedAuthConfig,
): Promise<CookieSession> {
  const cookies = parseCookies(c.req.raw.headers.get('cookie'));
  const sid = cookies[config.cookie.sessionCookieName];
  const csrfCookie = cookies[config.cookie.csrfCookieName];
  const session = sid ? await config.store.get(sid) : null;
  return { session, csrfCookie };
}

export type ResolvedRequestAuth = {
  user: AuthUser | null;
  session: Session | null;
  csrfCookie: string | undefined;
};

/** Cookie session first, then the providers. Never throws. */
export async function resolveRequestAuth(
  c: Context,
  config: ResolvedAuthConfig,
): Promise<ResolvedRequestAuth> {
  const { session, csrfCookie } = await readCookieSession(c, config);
  if (session) {
    return { user: sessionToUser(session), session, csrfCookie };
  }

  const user = await verifyProviders(config.providers, c.req.raw, c.env, config.onEvent);
  return { user, session: null, csrfCookie };
}

export function createMiddleware(
  config: ResolvedAuthConfig,
  options: MiddlewareOptions = {},
): MiddlewareHandler {
  const optional = options.optional === true;

  return async function authMiddleware(c: Context, next: Next) {
    const { user, session, csrfCookie } = await resolveRequestAuth(c, config);

    const csrf = await verifyCsrf({
      req: c.req.raw,
      cookieToken: csrfCookie,
      cookieAuthenticated: session !== null,
      config: config.csrf,
    });
    if (!csrf.ok) {
      config.onEvent({ type: 'csrf.failed', reason: csrf.reason });
      return c.json({ error: 'csrf_failed' as const }, 403);
    }

    if (!user) {
      if (optional) {
        c.set('authSession', null);
        return next();
      }
      config.onEvent({ type: 'auth.failed', reason: 'no_credentials' });
      return c.json(unauthorizedBody(), 401);
    }

    c.set('user', user);
    c.set('authSession', session);

    if (session) {
      const at = config.clock();
      if (at - session.lastSeenAt >= config.session.touchIntervalSec * 1000) {
        // Sliding window. `touch` never pushes past the absolute expiry.
        await config.store.touch(session.sid, at + config.session.idleTtlSec * 1000);
      }
    }

    return next();
  };
}
