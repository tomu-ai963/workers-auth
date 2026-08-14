/**
 * Cookie serialization with the secure defaults baked in.
 *
 * There is no "just turn off Secure" switch: the only way to get an insecure
 * cookie is to set `dangerouslyAllowInsecureCookies`, and that also forfeits
 * the `__Host-` prefix, which is exactly what you want it to look like in a
 * diff.
 */

import type { CookieConfig } from './types.js';

export type CookieAttributes = {
  path?: string;
  domain?: string;
  maxAge?: number;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'Lax' | 'Strict' | 'None';
};

export type ResolvedCookieConfig = {
  sessionCookieName: string;
  csrfCookieName: string;
  secure: boolean;
  sameSite: 'Lax' | 'Strict' | 'None';
  path: '/';
};

const TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

/** Applies the defaults and rejects combinations that silently weaken cookies. */
export function resolveCookieConfig(config: CookieConfig = {}): ResolvedCookieConfig {
  const insecure = config.dangerouslyAllowInsecureCookies === true;
  const prefix = config.prefix ?? (insecure ? '' : '__Host-');
  const name = config.name ?? 'session';
  const csrfName = config.csrfName ?? 'csrf';
  const sameSite = config.sameSite ?? 'Lax';
  const secure = !insecure;

  if (!TOKEN_RE.test(name) || !TOKEN_RE.test(csrfName)) {
    throw new TypeError('cookie: name and csrfName must be valid cookie tokens');
  }
  if (name === csrfName) {
    throw new TypeError('cookie: name and csrfName must differ');
  }
  if (!secure && prefix !== '') {
    throw new TypeError(
      'cookie: the __Host-/__Secure- prefix requires Secure; drop the prefix if you really want insecure cookies',
    );
  }
  if (prefix === '' && secure) {
    // Reachable only when the caller explicitly passed `prefix: ''` on https.
    // Dropping the prefix forfeits subdomain-injection protection, which the
    // double-submit CSRF token relies on — so it needs the danger flag too.
    throw new TypeError(
      'cookie: dropping the cookie prefix requires dangerouslyAllowInsecureCookies (it disables subdomain-injection protection)',
    );
  }
  if (sameSite === 'None' && !secure) {
    throw new TypeError('cookie: SameSite=None requires Secure');
  }

  return {
    sessionCookieName: `${prefix}${name}`,
    csrfCookieName: `${prefix}${csrfName}`,
    secure,
    sameSite,
    path: '/',
  };
}

export function serializeCookie(name: string, value: string, attrs: CookieAttributes = {}): string {
  if (!TOKEN_RE.test(name.replace(/^__(Host|Secure)-/, ''))) {
    throw new TypeError(`serializeCookie: invalid cookie name ${JSON.stringify(name)}`);
  }
  const encoded = encodeURIComponent(value);
  const parts = [`${name}=${encoded}`];

  const path = attrs.path ?? '/';
  parts.push(`Path=${path}`);

  if (attrs.maxAge !== undefined) {
    const maxAge = Math.max(0, Math.floor(attrs.maxAge));
    parts.push(`Max-Age=${maxAge}`);
    parts.push(`Expires=${new Date(Date.now() + maxAge * 1000).toUTCString()}`);
  }
  if (attrs.domain) parts.push(`Domain=${attrs.domain}`);
  if (attrs.httpOnly !== false) parts.push('HttpOnly');
  if (attrs.secure !== false) parts.push('Secure');
  parts.push(`SameSite=${attrs.sameSite ?? 'Lax'}`);

  // __Host- has hard requirements; assert rather than emit a cookie the browser
  // will silently drop.
  if (name.startsWith('__Host-')) {
    if (path !== '/' || attrs.domain || attrs.secure === false) {
      throw new TypeError('__Host- cookies require Secure, Path=/ and no Domain');
    }
  }
  if (name.startsWith('__Secure-') && attrs.secure === false) {
    throw new TypeError('__Secure- cookies require Secure');
  }

  return parts.join('; ');
}

/** Serializes the deletion of a cookie (same attributes, empty value, Max-Age=0). */
export function serializeCookieDeletion(name: string, attrs: CookieAttributes = {}): string {
  return serializeCookie(name, '', { ...attrs, maxAge: 0 });
}

export function parseCookies(header: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const pair of header.split(';')) {
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    const key = pair.slice(0, idx).trim();
    if (!key) continue;
    const raw = pair.slice(idx + 1).trim();
    if (key in out) continue; // first occurrence wins; ignore shadowing duplicates
    try {
      out[key] = decodeURIComponent(raw);
    } catch {
      out[key] = raw;
    }
  }
  return out;
}

export function getCookie(req: Request, name: string): string | undefined {
  return parseCookies(req.headers.get('cookie'))[name];
}
