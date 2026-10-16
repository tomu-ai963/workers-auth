/**
 * Bearer sessions — for a frontend and API on different sites.
 *
 * When the page lives on `*.github.io` and the API on `*.workers.dev`, the
 * session cookie is third-party from the browser's point of view and Safari
 * (and increasingly everyone) drops it. A bearer session is the same server-
 * held session record, handed to the client once as `wsb_<sid>` and presented
 * back as `Authorization: Bearer wsb_<sid>`.
 *
 * What changes versus a cookie session, and why:
 *   - The token is readable by the page's JS, so XSS can exfiltrate it. Keep
 *     the lifetime short (`deviceAuth` defaults to 12 hours, no sliding); on a
 *     trusted device the next login is just the PIN.
 *   - No CSRF exposure: nothing is ambient, so nothing can be forged.
 *   - Only sessions minted with `transport: 'bearer'` are accepted here. A
 *     cookie session id, if it ever leaked, cannot be replayed as a bearer.
 */

import { deviceCheckApplied, isBearerSession, sessionToUser } from '../middleware.js';
import type { AuthProvider, AuthUser, Session, SessionStore } from '../types.js';

export const BEARER_SESSION_PREFIX = 'wsb_';

/** Maximum accepted header token length; a real one is 4 + 43 chars. */
const MAX_TOKEN_LENGTH = 128;

export function bearerSessionToken(sid: string): string {
  return `${BEARER_SESSION_PREFIX}${sid}`;
}

/** The raw sid from `Authorization: Bearer wsb_…`, or null. */
export function readBearerSessionId(req: Request): string | null {
  const header = req.headers.get('authorization');
  if (!header) return null;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  const token = match?.[1];
  if (!token || token.length > MAX_TOKEN_LENGTH || !token.startsWith(BEARER_SESSION_PREFIX)) return null;
  const sid = token.slice(BEARER_SESSION_PREFIX.length);
  return /^[A-Za-z0-9_-]{20,}$/.test(sid) ? sid : null;
}

/**
 * The live bearer session this request presents, or null. A session minted on
 * a trusted device is refused unless `store` is the `deviceBoundSessionStore()`
 * itself, since only that store checks the device.
 */
export async function readBearerSession(store: SessionStore, req: Request): Promise<Session | null> {
  const sid = readBearerSessionId(req);
  if (!sid) return null;
  const session = await store.get(sid);
  return session && isBearerSession(session) && deviceCheckApplied(store, session) ? session : null;
}

/** Revokes the presented bearer session. Resolves false when there was none. */
export async function revokeBearerSession(store: SessionStore, req: Request): Promise<boolean> {
  const session = await readBearerSession(store, req);
  if (!session) return false;
  await store.revoke(session.sid);
  return true;
}

export interface SessionBearerProvider extends AuthProvider {
  /** The store this provider reads. `deviceAuth()` checks it is device-bound. */
  readonly sessionStore: SessionStore;
}

export type SessionBearerOptions = {
  store: SessionStore;
  name?: string;
};

/**
 * An `AuthProvider` that accepts bearer sessions. List it in `providers` so
 * `auth.middleware()` authenticates `Authorization: Bearer wsb_…` requests.
 *
 * No sliding window: the middleware only `touch()`es cookie sessions, so a
 * bearer session ends at its idle/absolute expiry regardless of activity.
 */
export function sessionBearer(options: SessionBearerOptions): SessionBearerProvider {
  const { store, name = 'session-bearer' } = options;
  if (!store || typeof store.get !== 'function') {
    throw new TypeError('sessionBearer: a SessionStore is required');
  }
  return {
    name,
    sessionStore: store,
    async verify(req: Request): Promise<AuthUser | null> {
      const session = await readBearerSession(store, req);
      return session ? sessionToUser(session) : null;
    },
  };
}
