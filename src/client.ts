/**
 * The browser client. It is intentionally not clever.
 *
 * What it does: send a request with cookies, parse the JSON, hand it back.
 * What it does NOT do, by design and permanently:
 *   - persist anything in web storage
 *   - mirror auth state to other tabs over a channel
 *   - run a background refresh timer
 *   - cache responses
 *
 * The only optimisation allowed here is in-flight de-duplication: two
 * simultaneous calls share one request, and the shared promise is dropped the
 * moment it settles. Nothing is remembered afterwards.
 *
 * Every request is sent with `cache: 'no-store'` so no layer between the page
 * and the Worker can answer an auth call from a cached body.
 */

/**
 * Structural shapes for the browser fetch surface. Declared locally so this
 * module compiles under Workers types, DOM types, or neither.
 */
export type ClientRequestInit = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  credentials?: 'include' | 'omit' | 'same-origin';
  cache?: 'no-store';
};

export type ClientResponse = {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
};

export type ClientFetch = (input: string, init?: ClientRequestInit) => Promise<ClientResponse>;

export type AuthClientOptions = {
  /** Where `auth.routes()` is mounted. Default: `/auth`. */
  baseUrl?: string;
  /** Injectable fetch. Default: the global. */
  fetchImpl?: ClientFetch;
  /** Name of the readable CSRF cookie. Default: `__Host-csrf`. */
  csrfCookieName?: string;
  /** Header used to echo the CSRF token. Default: `x-csrf-token`. */
  csrfHeaderName?: string;
};

export type ClientUser = {
  id: string;
  subjectType: 'user' | 'service';
  email?: string;
  claims: Record<string, unknown>;
};

export type ClientSession = {
  userId: string;
  subjectType: 'user' | 'service';
  createdAt: number;
  idleExpiresAt: number;
  absoluteExpiresAt: number;
  scope?: { orgId?: string; role?: string };
};

export type SessionResponse = {
  user: ClientUser;
  session: ClientSession | null;
};

export class AuthClientError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(`auth request failed (${status}: ${code})`);
    this.name = 'AuthClientError';
    this.status = status;
    this.code = code;
  }
}

export type AuthClient = {
  /** Current session, or null when unauthenticated. Never cached. */
  session(): Promise<SessionResponse | null>;
  /** Exchange provider credentials for a session cookie. */
  login(init?: { body?: unknown; headers?: Record<string, string> }): Promise<SessionResponse>;
  /** Revoke the session server-side and clear the cookies. */
  logout(): Promise<void>;
  /** The double-submit token, read straight from the cookie. */
  csrfToken(): string | null;
};

function readCookie(name: string): string | null {
  const host = globalThis as { document?: { cookie?: string } };
  const jar = host.document?.cookie;
  if (!jar) return null;
  for (const part of jar.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(idx + 1).trim());
    } catch {
      return part.slice(idx + 1).trim();
    }
  }
  return null;
}

export function createAuthClient(options: AuthClientOptions = {}): AuthClient {
  const baseUrl = (options.baseUrl ?? '/auth').replace(/\/+$/, '');
  const globalFetch = (globalThis as { fetch?: ClientFetch }).fetch;
  const doFetch: ClientFetch =
    options.fetchImpl ??
    ((input, init) => {
      if (!globalFetch) throw new Error('createAuthClient: no fetch available');
      return globalFetch(input, init);
    });
  const csrfCookieName = options.csrfCookieName ?? '__Host-csrf';
  const csrfHeaderName = options.csrfHeaderName ?? 'x-csrf-token';

  /**
   * In-flight de-duplication. The entry is deleted in `finally`, so this map is
   * empty whenever nothing is on the wire — it is not a cache.
   */
  const inflight = new Map<string, Promise<ClientResponse>>();

  /**
   * `dedupKey` is only ever passed for idempotent reads. State-changing calls
   * are never merged: two logouts are two logouts.
   */
  function request(path: string, init: ClientRequestInit, dedupKey?: string): Promise<ClientResponse> {
    if (dedupKey) {
      const existing = inflight.get(dedupKey);
      if (existing) return existing;
    }

    const pending = doFetch(`${baseUrl}${path}`, {
      ...init,
      credentials: 'include',
      cache: 'no-store',
      headers: { accept: 'application/json', ...init.headers },
    }).finally(() => {
      if (dedupKey) inflight.delete(dedupKey);
    });

    if (dedupKey) inflight.set(dedupKey, pending);
    return pending;
  }

  function csrfHeaders(extra?: Record<string, string>): Record<string, string> {
    const token = readCookie(csrfCookieName);
    return { ...(token ? { [csrfHeaderName]: token } : {}), ...extra };
  }

  async function parseError(res: ClientResponse): Promise<never> {
    let code = 'unknown';
    try {
      const body = (await res.json()) as { error?: unknown };
      if (typeof body?.error === 'string') code = body.error;
    } catch {
      // Body was not JSON; the status code is all we get.
    }
    throw new AuthClientError(res.status, code);
  }

  return {
    csrfToken() {
      return readCookie(csrfCookieName);
    },

    async session() {
      const res = await request('/session', { method: 'GET' }, 'GET /session');
      if (res.status === 401) return null;
      if (!res.ok) return parseError(res);
      return (await res.json()) as SessionResponse;
    },

    async login(init = {}) {
      const hasBody = init.body !== undefined;
      const res = await request('/session', {
        method: 'POST',
        headers: csrfHeaders({
          ...(hasBody ? { 'content-type': 'application/json' } : {}),
          ...init.headers,
        }),
        ...(hasBody ? { body: JSON.stringify(init.body) } : {}),
      });
      if (!res.ok) return parseError(res);
      return (await res.json()) as SessionResponse;
    },

    async logout() {
      const res = await request('/logout', {
        method: 'POST',
        headers: csrfHeaders(),
      });
      if (!res.ok) return parseError(res);
    },
  };
}
