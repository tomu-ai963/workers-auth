/**
 * Hono middleware: resolve the session, enforce CSRF, publish the subject.
 */

import type { Context, MiddlewareHandler, Next } from 'hono';

import { parseCookies, serializeCookie, serializeCookieDeletion, type ResolvedCookieConfig } from './cookie.js';
import { issueCsrfToken, verifyCsrf } from './csrf.js';
import { applyNoStore } from './headers.js';
import type {
  AuthUser,
  Clock,
  CsrfConfig,
  AuthProvider,
  Session,
  SessionInfo,
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
    /**
     * The cookie session minus its credential, or null when the subject
     * authenticated by bearer. The raw `sid` is deliberately absent: it must
     * not be reachable from application code, where one `c.json(session)` or
     * log line would leak it.
     */
    authSession: SessionInfo | null;
  }
}

/** Drops the credential before a session is handed to application code. */
export function toSessionInfo(session: Session): SessionInfo {
  const { sid: _sid, ...info } = session;
  return info;
}

/**
 * Namespace for the fields the SDK itself keeps in `Session.meta`. Application
 * metadata lives alongside it and can never collide with — or be mistaken for —
 * an authenticated attribute.
 */
export const AUTH_META_KEY = '__auth';

export type AuthMeta = {
  email?: string;
  provider?: string;
  claims?: Record<string, unknown>;
  /**
   * Persisted unconditionally (unlike `claims`, which is gated behind
   * `storeUserClaims`) so a cookie-authenticated request rebuilt by
   * {@link sessionToUser} on request N+1 still has the same `rateLimitId` a
   * rate limiter saw on request 1 — without this, a limiter reading
   * `user.rateLimitId` would see it only on the login request itself.
   */
  rateLimitId?: string;
};

export type ResolvedSessionConfig = {
  idleTtlSec: number;
  absoluteTtlSec: number;
  touchIntervalSec: number;
};

export type ResolvedAuthConfig = {
  providers: AuthProvider[];
  /** Consulted only by `GET /callback`. May hold `callbackOnly` providers. */
  callbackProviders: AuthProvider[];
  store: SessionStore;
  cookie: ResolvedCookieConfig;
  session: ResolvedSessionConfig;
  csrf: CsrfConfig;
  clock: Clock;
  /** Persist the provider's full claim set into the session record. */
  storeUserClaims: boolean;
  /** Relative path used by `GET /callback` on success. */
  callbackRedirect: string;
  /** See `CreateAuthOptions.basePath`. Undefined unless the caller set it. */
  basePath?: string;
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

export function getSession(c: Context): SessionInfo | null {
  return (c.get('authSession') as SessionInfo | null | undefined) ?? null;
}

/**
 * Rebuilds the subject from a session record.
 *
 * Only the SDK's own `meta.__auth` namespace is consulted. Application metadata
 * sitting next to it can never be promoted into an authenticated attribute,
 * however it happens to be named.
 */
export function sessionToUser(session: Session | SessionInfo): AuthUser {
  const namespaced = (session.meta ?? {})[AUTH_META_KEY];
  const auth = (typeof namespaced === 'object' && namespaced !== null ? namespaced : {}) as {
    email?: unknown;
    provider?: unknown;
    claims?: unknown;
    rateLimitId?: unknown;
  };
  const claims = (auth.claims && typeof auth.claims === 'object' ? auth.claims : {}) as Record<
    string,
    unknown
  >;
  return {
    id: session.userId,
    subjectType: session.subjectType,
    ...(typeof auth.email === 'string' ? { email: auth.email } : {}),
    // Falls back to `userId` for a session written before `rateLimitId`
    // existed in `meta.__auth` (a pre-upgrade session still live at deploy
    // time) — never surfaces as missing, even though it wasn't provider-set.
    rateLimitId: typeof auth.rateLimitId === 'string' && auth.rateLimitId ? auth.rateLimitId : session.userId,
    claims: {
      ...claims,
      ...(typeof auth.provider === 'string' ? { provider: auth.provider } : {}),
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
      if (user) {
        // A provider that forgets `rateLimitId` is a config/implementation
        // bug, not "bad credentials" — but it must still fail closed rather
        // than hand application code (and any rate limiter reading
        // `user.rateLimitId`) an unset value. Caught below like any other
        // provider error, so it shows up as `auth.failed` with this
        // provider's name rather than a bare 500.
        if (typeof user.rateLimitId !== 'string' || user.rateLimitId.length === 0) {
          throw new TypeError(`provider "${provider.name}" returned a user with no rateLimitId`);
        }
        return user;
      }
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
      applyNoStore(c);
      return c.json({ error: 'csrf_failed' as const }, 403);
    }

    if (!user) {
      if (optional) {
        c.set('authSession', null);
        return next();
      }
      config.onEvent({ type: 'auth.failed', reason: 'no_credentials' });
      applyNoStore(c);
      return c.json(unauthorizedBody(), 401);
    }

    c.set('user', user);
    c.set('authSession', session ? toSessionInfo(session) : null);

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
