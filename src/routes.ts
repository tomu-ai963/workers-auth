/**
 * The endpoints `auth.routes()` mounts, plus session creation.
 *
 *   POST /session   verify credentials -> mint session -> set cookies
 *   GET  /session   the current cookie session (401 when there is none)
 *   POST /logout    revoke + clear cookies
 *   GET  /callback  magic-link landing -> mint session -> redirect
 *                   (mounted only when `callbackProviders` is non-empty)
 */

import { Hono, type Context } from 'hono';

import { fingerprint } from './crypto.js';
import { verifyCsrf } from './csrf.js';
import { applyNoStore } from './headers.js';
import {
  AUTH_META_KEY,
  clearSessionCookies,
  issueCsrfToken,
  readCookieSession,
  sessionToUser,
  setSessionCookies,
  unauthorizedBody,
  verifyProviders,
  type AuthMeta,
  type ResolvedAuthConfig,
} from './middleware.js';
import type { AuthUser, Session } from './types.js';

export type CreateSessionOptions = {
  scope?: Session['scope'];
  meta?: Record<string, unknown>;
  /**
   * Session to rotate out, when the caller already read it. Pass `undefined`
   * to let this function look it up.
   */
  previousSession?: Session | null;
};

/**
 * Mints a session for a verified subject and writes both cookies.
 * Any pre-existing session is revoked first — a login always rotates the id,
 * which is what makes session fixation a non-issue.
 */
export async function createSessionFor(
  c: Context,
  config: ResolvedAuthConfig,
  user: AuthUser,
  options: CreateSessionOptions = {},
): Promise<Session> {
  const previous =
    options.previousSession !== undefined
      ? options.previousSession
      : (await readCookieSession(c, config)).session;
  if (previous) {
    await config.store.revoke(previous.sid);
  }

  if (options.meta && AUTH_META_KEY in options.meta) {
    throw new TypeError(
      `createSession: "${AUTH_META_KEY}" is reserved for the SDK; put application metadata under another key`,
    );
  }

  const authMeta: AuthMeta = {
    ...(user.email ? { email: user.email } : {}),
    ...(typeof user.claims['provider'] === 'string' ? { provider: user.claims['provider'] } : {}),
    ...(config.storeUserClaims ? { claims: user.claims } : {}),
  };

  const session = await config.store.create({
    userId: user.id,
    subjectType: user.subjectType,
    idleTtlSec: config.session.idleTtlSec,
    absoluteTtlSec: config.session.absoluteTtlSec,
    ...(options.scope ? { scope: options.scope } : {}),
    meta: { ...(options.meta ?? {}), [AUTH_META_KEY]: authMeta },
  });

  const maxAgeSec = Math.max(1, Math.ceil((session.absoluteExpiresAt - config.clock()) / 1000));
  setSessionCookies(c, config, session.sid, issueCsrfToken(), maxAgeSec);

  config.onEvent({
    type: 'session.created',
    userId: session.userId,
    subjectType: session.subjectType,
    sidFingerprint: await fingerprint(session.sid),
  });

  return session;
}

/** Public view of a session. The raw sid never appears here. */
function publicSession(session: Session) {
  return {
    userId: session.userId,
    subjectType: session.subjectType,
    createdAt: session.createdAt,
    idleExpiresAt: session.idleExpiresAt,
    absoluteExpiresAt: session.absoluteExpiresAt,
    ...(session.scope ? { scope: session.scope } : {}),
  };
}

/** Only same-site relative paths may be redirect targets. */
export function safeRedirectPath(candidate: string | null | undefined, fallback: string): string {
  if (!candidate) return fallback;
  if (!candidate.startsWith('/')) return fallback;
  if (candidate.startsWith('//') || candidate.startsWith('/\\')) return fallback;
  if (candidate.includes('\\') || candidate.includes('\n') || candidate.includes('\r')) return fallback;
  return candidate;
}

export function createRoutes(config: ResolvedAuthConfig): Hono {
  // See `CreateAuthOptions.basePath`: only set when this sub-app is going to
  // be handed a full, unstripped request path directly (i.e. mounted via its
  // own `.fetch()` rather than `app.route()`, which strips the prefix itself).
  const app = config.basePath ? new Hono().basePath(config.basePath) : new Hono();

  // Identity responses must never be stored by anything downstream.
  app.use('*', async (c, next) => {
    applyNoStore(c);
    await next();
  });

  app.post('/session', async (c) => {
    const current = await readCookieSession(c, config);

    const csrf = await verifyCsrf({
      req: c.req.raw,
      cookieToken: current.csrfCookie,
      cookieAuthenticated: current.session !== null,
      requireOrigin: true,
      config: config.csrf,
    });
    if (!csrf.ok) {
      config.onEvent({ type: 'csrf.failed', reason: csrf.reason });
      return c.json({ error: 'csrf_failed' as const }, 403);
    }

    const user = await verifyProviders(config.providers, c.req.raw, c.env, config.onEvent);
    if (!user) {
      config.onEvent({ type: 'auth.failed', reason: 'no_credentials' });
      return c.json(unauthorizedBody(), 401);
    }

    const session = await createSessionFor(c, config, user, { previousSession: current.session });
    return c.json({ ok: true as const, user, session: publicSession(session) });
  });

  /**
   * Reports the cookie session and nothing else. Providers are deliberately not
   * run here: verification can have side effects (a magic-link token is
   * single-use), and a GET must not consume a credential.
   */
  app.get('/session', async (c) => {
    const { session } = await readCookieSession(c, config);
    if (!session) return c.json(unauthorizedBody(), 401);
    return c.json({ user: sessionToUser(session), session: publicSession(session) });
  });

  app.post('/logout', async (c) => {
    const current = await readCookieSession(c, config);

    const csrf = await verifyCsrf({
      req: c.req.raw,
      cookieToken: current.csrfCookie,
      cookieAuthenticated: current.session !== null,
      requireOrigin: true,
      config: config.csrf,
    });
    if (!csrf.ok) {
      config.onEvent({ type: 'csrf.failed', reason: csrf.reason });
      return c.json({ error: 'csrf_failed' as const }, 403);
    }

    if (current.session) {
      await config.store.revoke(current.session.sid);
      config.onEvent({
        type: 'session.revoked',
        sidFingerprint: await fingerprint(current.session.sid),
      });
    }
    // Always clear, even when there was nothing to revoke: a stale cookie
    // should not survive a logout.
    clearSessionCookies(c, config);
    return c.json({ ok: true as const });
  });

  // Only mounted when the caller opted into a URL-borne credential. Without
  // that, there is no landing route to burn a token on.
  if (config.callbackProviders.length > 0) {
    app.get('/callback', async (c) => {
      const user = await verifyProviders(
        config.callbackProviders,
        c.req.raw,
        c.env,
        config.onEvent,
      );
      if (!user) {
        config.onEvent({ type: 'auth.failed', reason: 'callback_rejected' });
        return c.json(unauthorizedBody(), 401);
      }
      await createSessionFor(c, config, user);
      const target = safeRedirectPath(c.req.query('redirect_to'), config.callbackRedirect);
      return c.redirect(target, 302);
    });
  }

  return app;
}
