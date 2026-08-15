/**
 * @tomu-ai/workers-auth
 *
 * Auth session management for Cloudflare Workers + Hono.
 * The client is deliberately thin; all state lives on the server.
 */

import type { Context, Hono, MiddlewareHandler } from 'hono';

import { resolveCookieConfig } from './cookie.js';
import {
  clearSessionCookies,
  createMiddleware,
  readCookieSession,
  verifyProviders,
  type AuthEvent,
  type MiddlewareOptions,
  type ResolvedAuthConfig,
} from './middleware.js';
import { createRoutes, createSessionFor, type CreateSessionOptions } from './routes.js';
import type {
  AuthProvider,
  AuthUser,
  Clock,
  CookieConfig,
  CsrfConfig,
  Session,
  SessionConfig,
  SessionStore,
} from './types.js';

export type CreateAuthOptions = {
  /**
   * Tried in order on every request; the first success wins. A provider that
   * reads its credential from the URL (`callbackOnly`) is rejected here.
   */
  providers: AuthProvider[];
  /**
   * Consulted only by `GET /callback`. This is where a magic-link provider
   * configured with `allowTokenInQuery` belongs, so that `?token=` is honoured
   * on exactly one route instead of all of them. `GET /callback` is not mounted
   * at all when this is empty.
   */
  callbackProviders?: AuthProvider[];
  store: SessionStore;
  cookie?: CookieConfig;
  /**
   * Both TTLs are required together. Omit the whole object to take the
   * defaults (7 day idle / 30 day absolute).
   */
  session?: SessionConfig;
  csrf?: CsrfConfig;
  /**
   * Persist the provider's whole claim set in the session record so that
   * `c.get('user').claims` survives across requests. Off by default: claims go
   * stale, and the session store is not the right home for profile data.
   */
  storeUserClaims?: boolean;
  /** Default redirect target for `GET /callback`. Must be a relative path. */
  callbackRedirect?: string;
  /**
   * Bakes a path prefix into `auth.routes()` itself (via Hono's `basePath()`),
   * so the returned sub-app matches `${basePath}/session` etc. on the full
   * request path it's given.
   *
   * Use this **only** when `auth.routes()` is mounted by calling its own
   * `.fetch()` directly — typically because `createAuth()` has to be built
   * per request (bindings only exist inside a request in Workers), which
   * rules out `app.route('/auth', auth.routes())` mounted once at module
   * scope:
   *
   * ```ts
   * const auth = createAuth({ ..., basePath: '/auth' });
   * app.all('/auth/*', (c) => auth.routes().fetch(c.req.raw, c.env));
   * ```
   *
   * Leave this unset when mounting the ordinary way with
   * `app.route('/auth', auth.routes())` — Hono's `app.route()` already
   * strips the matched prefix before delegating, so setting `basePath` too
   * would apply the prefix twice.
   */
  basePath?: string;
  /** Structured audit hook. Never receives raw tokens — only fingerprints. */
  onEvent?: (event: AuthEvent) => void;
  clock?: Clock;
};

export type Auth = {
  middleware(options?: MiddlewareOptions): MiddlewareHandler;
  routes(): Hono;
  /** Mint a session for an already-verified subject and set the cookies. */
  createSession(c: Context, user: AuthUser, options?: CreateSessionOptions): Promise<Session>;
  /** Revoke the current cookie session and clear the cookies. */
  destroySession(c: Context): Promise<void>;
  /** Run the provider chain against a raw request. */
  verify(req: Request, env?: unknown): Promise<AuthUser | null>;
  readonly config: ResolvedAuthConfig;
};

const DEFAULT_IDLE_TTL_SEC = 60 * 60 * 24 * 7; // 7 days
const DEFAULT_ABSOLUTE_TTL_SEC = 60 * 60 * 24 * 30; // 30 days
const DEFAULT_TOUCH_INTERVAL_SEC = 60;

function resolveSessionConfig(config: SessionConfig | undefined) {
  if (config === undefined) {
    return {
      idleTtlSec: DEFAULT_IDLE_TTL_SEC,
      absoluteTtlSec: DEFAULT_ABSOLUTE_TTL_SEC,
      touchIntervalSec: DEFAULT_TOUCH_INTERVAL_SEC,
    };
  }
  const { idleTtlSec, absoluteTtlSec, touchIntervalSec = DEFAULT_TOUCH_INTERVAL_SEC } = config;

  // Both expiries are mandatory. Configuring one and letting the other default
  // is exactly how sessions end up effectively immortal.
  if (typeof idleTtlSec !== 'number' || !Number.isFinite(idleTtlSec) || idleTtlSec <= 0) {
    throw new TypeError('createAuth: session.idleTtlSec must be a positive number of seconds');
  }
  if (typeof absoluteTtlSec !== 'number' || !Number.isFinite(absoluteTtlSec) || absoluteTtlSec <= 0) {
    throw new TypeError('createAuth: session.absoluteTtlSec must be a positive number of seconds');
  }
  if (absoluteTtlSec < idleTtlSec) {
    throw new TypeError('createAuth: session.absoluteTtlSec must be >= session.idleTtlSec');
  }
  if (!Number.isFinite(touchIntervalSec) || touchIntervalSec < 0) {
    throw new TypeError('createAuth: session.touchIntervalSec must be >= 0');
  }
  return { idleTtlSec, absoluteTtlSec, touchIntervalSec };
}

export function createAuth(options: CreateAuthOptions): Auth {
  if (!Array.isArray(options.providers)) {
    throw new TypeError('createAuth: providers must be an array');
  }
  const callbackProviders = options.callbackProviders ?? [];
  if (!Array.isArray(callbackProviders)) {
    throw new TypeError('createAuth: callbackProviders must be an array');
  }
  // A provider that reads `?token=` would otherwise authenticate — and consume
  // the token on — every route the middleware covers.
  const misplaced = options.providers.find((p) => p.callbackOnly === true);
  if (misplaced) {
    throw new TypeError(
      `createAuth: provider "${misplaced.name}" reads its credential from the URL and must be ` +
        'listed in callbackProviders, not providers (a URL-borne token must not authenticate ' +
        'every route).',
    );
  }
  if (!options.store || typeof options.store.get !== 'function') {
    throw new TypeError('createAuth: a SessionStore is required');
  }

  const callbackRedirect = options.callbackRedirect ?? '/';
  if (!callbackRedirect.startsWith('/') || callbackRedirect.startsWith('//')) {
    throw new TypeError('createAuth: callbackRedirect must be a same-origin relative path');
  }

  const basePath = options.basePath;
  if (basePath !== undefined) {
    if (!basePath.startsWith('/') || basePath.startsWith('//') || basePath.endsWith('/')) {
      throw new TypeError(
        "createAuth: basePath must look like '/auth' — a leading slash, no trailing slash, no protocol-relative form",
      );
    }
  }

  const config: ResolvedAuthConfig = {
    providers: options.providers,
    callbackProviders,
    store: options.store,
    cookie: resolveCookieConfig(options.cookie),
    session: resolveSessionConfig(options.session),
    csrf: options.csrf ?? {},
    clock: options.clock ?? Date.now,
    storeUserClaims: options.storeUserClaims === true,
    callbackRedirect,
    basePath,
    onEvent: options.onEvent ?? (() => {}),
  };

  return {
    config,
    middleware(middlewareOptions?: MiddlewareOptions) {
      return createMiddleware(config, middlewareOptions);
    },
    routes() {
      return createRoutes(config);
    },
    createSession(c, user, createOptions) {
      return createSessionFor(c, config, user, createOptions);
    },
    async destroySession(c) {
      const { session } = await readCookieSession(c, config);
      if (session) await config.store.revoke(session.sid);
      clearSessionCookies(c, config);
    },
    verify(req, env) {
      return verifyProviders(config.providers, req, env, config.onEvent);
    },
  };
}

// --- re-exports -------------------------------------------------------------

export type {
  AuthErrorBody,
  AuthErrorCode,
  AuthProvider,
  AuthUser,
  Clock,
  CookieConfig,
  CsrfConfig,
  NewSession,
  RevocationList,
  RevocationQuery,
  Session,
  SessionConfig,
  SessionInfo,
  SessionScope,
  SessionStore,
  SubjectType,
} from './types.js';

export {
  AUTH_META_KEY,
  getOptionalUser,
  getSession,
  getUser,
  readCookieSession,
  resolveRequestAuth,
  sessionToUser,
  toSessionInfo,
  verifyProviders,
  type AuthEvent,
  type AuthMeta,
  type MiddlewareOptions,
  type ResolvedAuthConfig,
} from './middleware.js';

export { createRoutes, createSessionFor, safeRedirectPath, type CreateSessionOptions } from './routes.js';

export { applyNoStore, AUTH_VARY, NO_STORE } from './headers.js';

export {
  getCookie,
  parseCookies,
  resolveCookieConfig,
  serializeCookie,
  serializeCookieDeletion,
  type CookieAttributes,
  type ResolvedCookieConfig,
} from './cookie.js';

export {
  checkDoubleSubmit,
  checkOrigin,
  DEFAULT_CSRF_HEADER,
  isStateChanging,
  issueCsrfToken,
  SAFE_METHODS,
  verifyCsrf,
  type CsrfResult,
} from './csrf.js';

export {
  base64urlDecode,
  base64urlEncode,
  fingerprint,
  randomToken,
  secretEquals,
  sha256Hex,
  timingSafeEqual,
  verifySecretHash,
} from './crypto.js';
