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

// ---------------------------------------------------------------------------
// Magic-link / email helpers
// ---------------------------------------------------------------------------

/**
 * The smallest shape a delivered email can have and still be useful to a test.
 *
 * Deliberately not a provider's type. Resend, Mailtrap, SES and a local
 * catch-all inbox all return different envelopes, and pinning any one of them
 * here would drag that provider's SDK — and its API-shape churn — into this
 * package. Every field a test actually needs to *route* an assertion is here;
 * anything provider-specific stays on the caller's side of `fetchEmails`.
 *
 * `html`/`text` are both optional because providers differ on which one they
 * return (and some return both); {@link extractMagicLinkFromEmail} takes a
 * plain string so the caller picks whichever their provider populated.
 */
export type EmailLike = {
  to: string;
  subject: string;
  html?: string;
  text?: string;
  /** ISO-8601, as every provider that exposes a timestamp at all reports it. */
  createdAt?: string;
};

/** Matches an absolute http(s) URL, stopping at whitespace or HTML delimiters. */
const URL_PATTERN = /https?:\/\/[^\s"'<>]+/g;

/**
 * Trailing characters that end a sentence far more often than they end a URL.
 * `Click https://example.com/verify?token=abc.` would otherwise yield a token
 * with a `.` welded onto it, and the resulting failure ("invalid token") points
 * at the auth layer rather than at this helper.
 */
const TRAILING_PUNCTUATION = /[.,;:!?]+$/;

/** Path segments that mark a link as the auth one when no query key does. */
const AUTH_PATH_PATTERN = /(magic|verify|confirm|login|signin|sign-in|auth)/i;

/**
 * A query key is "token-ish" once case and separators are normalised away:
 * `token`, `magic_token`, `magicToken`, `verify-token`, `magiclink` all count.
 * Providers and projects each spell it differently; the shape is what matters.
 */
function isTokenishKey(key: string): boolean {
  const normalised = key.toLowerCase().replace(/[-_]/g, '');
  return normalised.includes('token') || normalised.includes('magiclink') || normalised === 'magic';
}

/** `&amp;` / `&#38;` / `&#x26;` -> `&`. The only entity that shows up inside a URL. */
function decodeHtmlAmpersands(url: string): string {
  return url.replace(/&(?:amp|#38|#[xX]26);/g, '&');
}

/**
 * Ranks a candidate URL: lower is better. Tier 0 carries a token-ish query
 * parameter, tier 1 looks like an auth path (`/magic/<token>` style links put
 * the token in the path, so there is no query key to find), tier 2 is anything
 * else. An unparseable candidate lands in tier 2 rather than being discarded —
 * it may still be the only URL in the body, and returning it produces a better
 * failure downstream than pretending the body had no link at all.
 */
function rankUrl(candidate: string): number {
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return 2;
  }
  for (const key of url.searchParams.keys()) {
    if (isTokenishKey(key)) return 0;
  }
  return AUTH_PATH_PATTERN.test(url.pathname) ? 1 : 2;
}

/**
 * Pulls the magic-link URL out of a delivered email body.
 *
 * Takes the raw body as a string — HTML or plain text — rather than a parsed
 * document, because there is no DOM in workerd and because the plain-text part
 * of a multipart email has no markup to parse in the first place.
 *
 * Marketing footers, logo `src=`s and unsubscribe links mean a real email body
 * usually holds several URLs, so the first match is the wrong answer. Instead
 * every match is ranked (see `rankUrl`) and the best-ranked one wins; ties are
 * broken by document order, which keeps the result stable.
 *
 * `options.pattern` replaces the URL scan entirely. Magic-link URL formats are
 * a per-project choice — a custom scheme for a deep link into a native app, a
 * token embedded in a `data-` attribute, a host that must be matched exactly —
 * and this helper should not be the reason such a project cannot use the rest
 * of this module. A supplied pattern is used as-is: its first match is returned
 * (capture group 1 if the pattern has one, so a caller can point at the token
 * rather than the whole URL), with no ranking, since a caller specific enough
 * to write the pattern has already made the choice ranking would make for it.
 *
 * Throws rather than returning `null`: every call site is a test that cannot
 * proceed without the link, so an early throw naming what was searched beats an
 * `undefined` surfacing later as a confusing request failure.
 */
export function extractMagicLinkFromEmail(body: string, options: { pattern?: RegExp } = {}): string {
  if (options.pattern) {
    // `match` on a /g pattern returns all matches with no capture groups, which
    // would silently ignore a caller's group — force a single-match read.
    const pattern = options.pattern.global
      ? new RegExp(options.pattern.source, options.pattern.flags.replace(/g/g, ''))
      : options.pattern;
    const match = pattern.exec(body);
    if (!match) {
      throw new Error(
        `extractMagicLinkFromEmail: options.pattern ${String(options.pattern)} did not match in body (length: ${body.length})`,
      );
    }
    return decodeHtmlAmpersands((match[1] ?? match[0]).trim());
  }

  let best: string | undefined;
  let bestRank = Number.POSITIVE_INFINITY;
  for (const match of body.matchAll(URL_PATTERN)) {
    // `&amp;` is how an HTML body spells `&`, so a URL lifted straight out of
    // an `href` would otherwise carry a literal `amp;` into every parameter
    // after the first.
    const candidate = decodeHtmlAmpersands(match[0].replace(TRAILING_PUNCTUATION, ''));
    const rank = rankUrl(candidate);
    if (rank < bestRank) {
      best = candidate;
      bestRank = rank;
      if (rank === 0) break;
    }
  }

  if (best === undefined) {
    throw new Error(`extractMagicLinkFromEmail: no URL matched in body (length: ${body.length})`);
  }
  return best;
}

/**
 * Polls `fetchEmails` until one of the returned emails satisfies `predicate`.
 *
 * `fetchEmails` is injected rather than built in, and that is the whole point:
 * this package sends no email and knows no email provider — `magicLink()` takes
 * a `sendToken` callback for the same reason. The caller, who already holds a
 * Resend API key, a Mailtrap inbox id or a local catch-all server, supplies
 * "how to list the mail that has arrived"; this helper supplies only the retry
 * loop that every such test otherwise rewrites. Nothing here imports, or needs
 * to know, which provider is behind it.
 *
 * Polls immediately, then every `intervalMs` until `timeoutMs` has elapsed,
 * with a final poll landing on the deadline itself. Polling before the first
 * sleep matters because delivery has often already happened by the time the
 * test looks — sleeping first would add `intervalMs` to every green run.
 *
 * The timeout error reports how many polls ran and how many emails the last one
 * returned, which separates the two failure modes that look identical from the
 * outside: nothing was ever delivered (count 0 — look at the sending side)
 * versus mail arrived but `predicate` never matched (count > 0 — look at the
 * predicate, usually a subject or recipient mismatch).
 *
 * No Node builtins: the sleep is a `setTimeout` promise, so this is safe to
 * call from a test running inside the workerd pool, and it goes through the
 * global `setTimeout`/`Date` so vitest's fake timers can drive it and a suite
 * need not spend the real timeout waiting.
 */
export async function waitForEmail(
  fetchEmails: () => Promise<EmailLike[]>,
  predicate: (email: EmailLike) => boolean,
  options: { timeoutMs?: number; intervalMs?: number } = {},
): Promise<EmailLike> {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const intervalMs = options.intervalMs ?? 500;
  const startedAt = Date.now();

  let polls = 0;
  let lastCount = 0;
  for (;;) {
    const emails = await fetchEmails();
    polls++;
    lastCount = emails.length;
    for (const email of emails) {
      if (predicate(email)) return email;
    }

    const elapsed = Date.now() - startedAt;
    if (elapsed >= timeoutMs) break;
    // Never sleep past the deadline: the last poll should land on it rather
    // than after it, so a caller's `timeoutMs` is also the worst-case wait.
    await sleep(Math.min(intervalMs, timeoutMs - elapsed));
  }

  throw new Error(
    `waitForEmail: no email matched after ${polls} poll(s) over ${timeoutMs}ms ` +
      `(last fetch returned ${lastCount} email(s))`,
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
