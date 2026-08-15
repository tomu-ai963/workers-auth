/**
 * Test-time helpers for exercising Cookie-session auth end to end.
 *
 * Every SDK integration that uses a session cookie needs the same shape of
 * test: log in, capture the `Set-Cookie` headers, replay them as a `Cookie`
 * header on the next request. Without a shared place to put that, every
 * adopting project re-derives it — parsing `Set-Cookie`, working around
 * `Headers.getSetCookie()` being missing from `@cloudflare/workers-types`,
 * building the `Cookie` header back up — slightly differently each time.
 *
 * Deliberately framework- and provider-agnostic:
 *   - No Hono import. Every helper takes a plain `Response`, or a plain
 *     `(Request) => Response | Promise<Response>` fetcher, so this works
 *     whether the thing under test is a Hono app's `.fetch()`, a raw
 *     `export default { fetch }` Worker, or anything else fetch-shaped.
 *   - No assumption about which `AuthProvider` is configured, or about the
 *     cookie names in use. `cookie: { name, csrfName, prefix }` is
 *     configurable per `createAuth()` call, so a helper that hardcoded
 *     `__Host-session` would silently stop working the moment a caller's
 *     config diverges from this SDK's own defaults — `readCookieJar` reads
 *     back whatever cookie names the server actually sent instead.
 *   - No Node builtins. This module is safe to import from a test that runs
 *     inside `@cloudflare/vitest-pool-workers`' workerd pool, not only from
 *     plain Node/vitest.
 *
 * Only import this from test files — it is not meant for application code.
 */

/** Cookie name -> value, exactly as sent back by the server. */
export type CookieJar = Record<string, string>;

/**
 * `Headers.getSetCookie()` exists in workerd (and in modern browsers and
 * Node) but is missing from `@cloudflare/workers-types`' `Headers` type.
 * One cast, here, instead of in every project that adopts this SDK.
 */
export function getSetCookies(res: Response): string[] {
  return (res.headers as unknown as { getSetCookie(): string[] }).getSetCookie();
}

/**
 * Parses every `Set-Cookie` header off a response into a jar keyed by cookie
 * name. Cookie attributes (`Path`, `Max-Age`, `HttpOnly`, ...) are discarded
 * — this jar only exists to be replayed as a `Cookie` request header, which
 * carries names and values only.
 */
export function readCookieJar(res: Response): CookieJar {
  const jar: CookieJar = {};
  for (const header of getSetCookies(res)) {
    const [pair] = header.split(';') as [string];
    const idx = pair.indexOf('=');
    if (idx < 0) continue;
    const name = pair.slice(0, idx).trim();
    if (!name) continue;
    const value = decodeURIComponent(pair.slice(idx + 1).trim());
    jar[name] = value;
  }
  return jar;
}

/**
 * Serializes a jar back into a `Cookie` request header value. Entries with
 * an empty value are dropped — that's what a `Set-Cookie: name=; Max-Age=0`
 * deletion looks like once parsed, and a request shouldn't carry it forward.
 */
export function cookieHeader(jar: CookieJar): string {
  return Object.entries(jar)
    .filter(([, value]) => value)
    .map(([name, value]) => `${name}=${encodeURIComponent(value)}`)
    .join('; ');
}

export type Fetcher = (req: Request) => Response | Promise<Response>;

/**
 * Sends `req` — built to satisfy whichever `AuthProvider` is configured: an
 * `Authorization` header for `apiKey`/`neonAuth`, an `x-magic-token` header
 * or body for `magicLink`, a test double's own header, whatever — and
 * expects a 200 `POST /session` response. Returns the resulting cookie jar.
 *
 * Throws (with the response body) on anything else, since a non-200 here is
 * almost always a test setup mistake — a missing `Origin` header, a provider
 * that didn't verify — not the behavior under test.
 */
export async function loginForCookies(fetcher: Fetcher, req: Request): Promise<CookieJar> {
  const res = await fetcher(req);
  if (res.status !== 200) {
    const body = await res
      .clone()
      .text()
      .catch(() => '');
    throw new Error(
      `loginForCookies: expected 200 from ${req.method} ${req.url}, got ${res.status}: ${body}`,
    );
  }
  return readCookieJar(res);
}
