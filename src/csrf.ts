/**
 * CSRF defence: Origin allow-listing + a double-submit token.
 *
 * Naive double-submit is weak when an attacker controls a sibling subdomain and
 * can write cookies onto the parent domain. We close that hole by pinning the
 * CSRF cookie to the `__Host-` prefix (see cookie.ts), which browsers refuse to
 * accept from a `Domain=` attribute.
 */

import { randomToken, secretEquals } from './crypto.js';
import type { CsrfConfig } from './types.js';

export const SAFE_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS']);

export const DEFAULT_CSRF_HEADER = 'x-csrf-token';

export type CsrfFailure = 'origin_missing' | 'origin_mismatch' | 'token_missing' | 'token_mismatch';

export type CsrfResult = { ok: true } | { ok: false; reason: CsrfFailure };

export function isStateChanging(method: string): boolean {
  return !SAFE_METHODS.has(method.toUpperCase());
}

export function issueCsrfToken(): string {
  return randomToken();
}

function canonicalOrigin(value: string): string | null {
  try {
    const url = new URL(value);
    if (!url.protocol || !url.host) return null;
    return url.origin;
  } catch {
    return null;
  }
}

/**
 * The request must carry an `Origin` header matching its own origin or one of
 * the configured trusted origins. A missing Origin is a rejection: every
 * browser sends it on state-changing requests, and non-browser clients should
 * be using a bearer credential (which skips CSRF entirely).
 */
export function checkOrigin(req: Request, trustedOrigins: readonly string[] = []): CsrfResult {
  const raw = req.headers.get('origin');
  if (!raw || raw === 'null') return { ok: false, reason: 'origin_missing' };

  const origin = canonicalOrigin(raw);
  if (!origin) return { ok: false, reason: 'origin_mismatch' };

  const self = canonicalOrigin(req.url);
  if (self && origin === self) return { ok: true };

  for (const trusted of trustedOrigins) {
    const canonical = canonicalOrigin(trusted);
    if (canonical && canonical === origin) return { ok: true };
  }
  return { ok: false, reason: 'origin_mismatch' };
}

/** Compares the CSRF cookie against the CSRF header in constant time. */
export async function checkDoubleSubmit(
  req: Request,
  cookieToken: string | undefined,
  headerName: string = DEFAULT_CSRF_HEADER,
): Promise<CsrfResult> {
  const headerToken = req.headers.get(headerName);
  if (!cookieToken || !headerToken) return { ok: false, reason: 'token_missing' };
  const equal = await secretEquals(cookieToken, headerToken);
  return equal ? { ok: true } : { ok: false, reason: 'token_mismatch' };
}

export type CsrfCheckInput = {
  req: Request;
  /** Value of the CSRF cookie, if the browser sent one. */
  cookieToken: string | undefined;
  /**
   * Whether the request is authenticated by a cookie. CSRF only applies to
   * ambient credentials; a bearer token / API key request is not forgeable.
   */
  cookieAuthenticated: boolean;
  /**
   * Demand an `Origin` header even when the request carries no cookies. Set for
   * the session endpoints (`POST /session`, `POST /logout`), which only ever
   * serve browsers — that is what stops login CSRF on the very first request.
   * Left off for app routes so a server-to-server POST with an API key still
   * works.
   */
  requireOrigin?: boolean;
  config?: CsrfConfig;
};

/**
 * Full check for a state-changing request.
 *
 * A request is "ambient" when it carries either a session cookie the store
 * accepted or a CSRF cookie. Ambient requests get both checks. Non-ambient ones
 * are only Origin-checked, and only where `requireOrigin` says so.
 */
export async function verifyCsrf(input: CsrfCheckInput): Promise<CsrfResult> {
  const { req, cookieToken, cookieAuthenticated, requireOrigin = false, config = {} } = input;

  if (config.dangerouslyDisable === true) return { ok: true };
  if (!isStateChanging(req.method)) return { ok: true };

  const ambient = cookieAuthenticated || cookieToken !== undefined;
  if (!ambient && !requireOrigin) return { ok: true };

  const origin = checkOrigin(req, config.trustedOrigins ?? []);
  if (!origin.ok) return origin;

  // Nothing has been handed to this client to echo back yet; the Origin check
  // above is the whole defence for that one bootstrap request.
  if (!ambient) return { ok: true };

  return checkDoubleSubmit(req, cookieToken, config.headerName ?? DEFAULT_CSRF_HEADER);
}
