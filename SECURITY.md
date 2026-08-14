# Security

Everything below is a **default**, not a recommendation you have to opt into.
Where an escape hatch exists it is named `dangerously*` and shows up in a diff.

This document reflects the state after a security review (2026-08) that found
two P0s and four P1s, all fixed. The findings and fixes are recorded under
[Fixed findings](#fixed-findings-2026-08-review) because the reasoning behind
each fix is exactly the kind of thing that gets silently un-fixed in a later
refactor if it isn't written down.

## Defaults

### Cookies

| property | value | notes |
| --- | --- | --- |
| prefix | `__Host-` | browsers reject it if `Domain` is set or `Path` is not `/`, which is what makes the CSRF cookie unforgeable from a sibling subdomain |
| `HttpOnly` | on (session cookie) | the CSRF cookie is deliberately readable — see below |
| `Secure` | on | |
| `SameSite` | `Lax` | configurable; `None` requires `Secure` |
| `Path` | `/` | forced |
| `Domain` | never set | |

`resolveCookieConfig` throws rather than emitting a cookie the browser would
silently drop (`__Host-` with a `Domain`, `SameSite=None` without `Secure`, …).

The only way to run without `Secure` is
`cookie: { dangerouslyAllowInsecureCookies: true }`, which also forfeits the
prefix. Local http development only.

### Session identifiers

- 256 bits from `crypto.getRandomValues`, base64url encoded (43 chars).
- **Stores only ever hold `sha256(sid)`.** A dump of KV or D1 does not yield a
  usable session. This is asserted by tests.
- **The raw `sid` never reaches application code either.** `c.get('authSession')`
  is typed `SessionInfo` — `Session` minus `sid` — so there is no `c.json(...)`
  or log line that can leak it by accident. Only `store.create()`'s return value
  carries it, for the one moment the SDK needs to put it in a cookie.
- A login always mints a new id and revokes the previous session, so session
  fixation has nothing to fix.
- Raw ids never appear in responses (`GET /session` returns metadata only) or in
  audit events, which carry a 12-hex-char `sha256` fingerprint instead.

### Expiry

Both windows are enforced, always:

- **idle** — slides forward on activity, at most once per `touchIntervalSec`
  (default 60s) to avoid a store write per request. In `kvSessionStore`, the
  idle window lives in a separate key from the session record — see
  [`touch()` cannot resurrect a revoked session](#fixed-findings-2026-08-review)
  below for why.
- **absolute** — never extended. `touch()` clamps the idle window to it.

Configuring one without the other throws. Expiry is checked in code on every
read, not delegated to KV's `expirationTtl` (60s minimum, eventually consistent
deletes) or to a background job.

### Revocation

Revocation is not one guarantee — it's three, and the SDK is explicit about
which one each configuration gives you. See the
[store comparison table in the README](./README.md#choosing-a-session-store).

The short version: `kvSessionStore()` alone can always revoke one session
(logout), but it **cannot** guarantee revoking every session of a user, because
that requires enumerating a user's sessions and KV's `list()` is eventually
consistent — a session created moments before the sweep can be missing from the
listing and survive it. Rather than offer a "log out everywhere" that
sometimes doesn't, `kvSessionStore().revokeAllForUser()` throws unless a
`revocationList` is attached. `revocationList` and `d1SessionStore` both answer
"log out everywhere" with a single timestamp comparison (`created_at <
revoked_before`) that needs no enumeration and therefore cannot miss a session.

### CSRF

Two independent checks on state-changing methods (`POST` / `PUT` / `PATCH` /
`DELETE`):

1. **Origin allow-list** — the `Origin` header must equal the request's own
   origin or a configured `trustedOrigins` entry. A missing or `null` Origin is a
   rejection.
2. **Double-submit token** — 256-bit random value in a readable `__Host-csrf`
   cookie, echoed in the `x-csrf-token` header, compared with a
   length-independent constant-time comparison.

Scope of each check:

| request | Origin | double-submit |
| --- | --- | --- |
| `POST /session`, `POST /logout` | required | required once a CSRF cookie exists |
| app routes, cookie-authenticated | required | required |
| app routes, bearer/API-key only, no cookies | skipped | skipped |

The last row is deliberate: a request that carries no ambient credential cannot
be forged by a third-party site, and demanding `Origin` there would break
service-to-service calls. Whether a request counts as cookie-authenticated is
decided by the store, not by whether a cookie is merely present: a Cookie
header and an `Authorization` header can arrive on the same request, and the
middleware always resolves the cookie session first, so CSRF is evaluated
against what actually authenticated the request rather than what one field
happened to contain. The first row is also deliberate — the session endpoints
only ever serve browsers, and requiring `Origin` there is what stops login CSRF
on the very first request, before any token has been handed out.

The CSRF cookie is intentionally not `HttpOnly`: the page's own JavaScript has
to read it to echo it back. It is not a credential on its own — it is only
meaningful together with the `HttpOnly` session cookie.

### Response caching

Every response from `auth.routes()`, and every 401/403 the middleware returns,
carries `Cache-Control: no-store, private` and `Vary: Cookie, Authorization`
unconditionally. There is no opt-out. An identity response is never safe to
cache — a Cloudflare cache rule, a service worker, a corporate proxy or bfcache
sitting between the Worker and the browser can otherwise serve one user's
`GET /session` response to the next visitor. The client already sends
`cache: 'no-store'`, but that only binds the client's own fetch call; the
server header is what makes it hold regardless of what's in between.

### Secret handling

- Every stored credential (session id, magic-link token, API key secret) is
  stored as SHA-256 hex and compared with `timingSafeEqual` over fixed-length
  digests, or `secretEquals` (hash-then-compare) when the input length is
  attacker-controlled.
- An unknown API key id still hashes the presented secret and still runs the
  comparison against a dummy digest, so "no such key" and "wrong secret" go
  through the same code path with no early return. (We don't claim a measured
  timing difference here — at this granularity, wall-clock noise dominates any
  real signal — the guarantee comes from reading the code, not from a
  benchmark.)
- Nothing in this package logs a raw token, session id or API key. The `onEvent`
  audit hook receives fingerprints only.

### Uniform failures

Authentication failures all produce `401 {"error":"unauthenticated"}`. A caller
cannot tell a missing credential from an expired one, an unknown user from a bad
signature. CSRF failures are the one distinguishable case
(`403 {"error":"csrf_failed"}`), because they are a client bug rather than an
authentication signal. Detail belongs in your own logs via `onEvent`.

### JWT verification (`neonAuth`)

- The algorithm allow-list is applied to the JWT header **before** any key
  lookup, so `alg: none` and HMAC confusion die immediately.
- The JWK is rebuilt from scratch (`kty`/`crv`/`n`/`e`/`x`/`y` only) before
  import; a hostile JWKS cannot smuggle `key_ops` or `alg` tricks past WebCrypto.
- The key type must match the header algorithm — an RSA key cannot be used to
  satisfy an `ES256` header.
- `iss`, `aud`, `exp` and `nbf` are all verified, with a 60 second default
  tolerance (`clockToleranceSec`) — enough to absorb ordinary clock drift
  between the issuer and the edge without it showing up as sporadic,
  hard-to-diagnose 401s.
- A token without `exp` is rejected.
- The JWKS fetch is bounded: `fetchTimeoutMs` (default 3000ms),
  `maxJwksBytes` (default 256KB, checked against both `Content-Length` and the
  actual body), `maxJwksKeys` (default 32) and a `Content-Type` check. A hung,
  oversized or hostile JWKS endpoint fails the request that triggered the fetch
  instead of stalling every authenticated request behind it.
- A JWKS fetch failure fails closed (no fallback to an unverified token).
- An unknown `kid` triggers at most one refetch per `minRefetchIntervalSec`.
  This limit is per isolate — it does not coordinate across the many isolates a
  Worker can run concurrently — so treat it as bounding the *added* load from
  unknown-`kid` traffic to roughly the same order as normal cold-start JWKS
  fetches, not as a hard global cap. Set `cache: { kv }` to reduce how often
  isolates need to hit the network at all.

### Magic links

Single use and confined to the callback route — the two properties that make a
magic link safe to email. Both are explained at length in the
[README](./README.md#magiclink-store-sendtoken-ttlsec), because both were the
subject of confirmed findings; see below.

### SQL

Every D1 query uses bound parameters. The only interpolated values are table
names, which are validated against `^[A-Za-z_][A-Za-z0-9_]*$` at construction and
throw otherwise.

## Fixed findings (2026-08 review)

Each of these was reproduced with a proof-of-concept before the fix, and the
PoC was re-run against the fix to confirm it no longer reproduces. The tests
that replaced the PoCs live in the test suite permanently; this section
explains *why*, since that reasoning is what stops the bug from coming back
through a well-intentioned refactor.

### [Fixed, was P0] `touch()` could resurrect a revoked session

`kvSessionStore`'s `touch()` used to read the session record, update its idle
expiry, and write it back. KV has no compare-and-set, so that read-modify-write
could interleave with a concurrent `revoke()`: a `touch()` already in flight
could land its write *after* the record was deleted, bringing the session back.
A logout racing against any other request from the same browser — a background
poll, a second tab, a service worker — could undo itself.

**Fix**: the idle window moved out of the session record entirely, into a
separate `seen:<sha256(sid)>` key. `touch()` now only ever writes that key and
never reads or rewrites the session record, so it has nothing left to race
`revoke()` on. A `touch()` that lands after a `revoke()` writes a marker for a
session that no longer exists — `get()` requires the record to be present
first, so the stray marker is inert. The race stops being a correctness
problem and becomes a KV key that expires on its own.

### [Fixed, was P0] `revokeAllForUser` could silently miss a session

The KV store used to keep a `uidx:<userId>:*` reverse index and sweep it with
`kv.list()` to find every session to revoke. KV's `list()` is eventually
consistent: a session created shortly before the sweep can be absent from the
listing and survive "log out everywhere" without any error or indication that
anything was missed.

**Fix**: `kvSessionStore().revokeAllForUser()` now throws unless a
`revocationList` is attached, and the reverse index is gone entirely —
enumeration-based revocation was the bug, so it was removed rather than
patched. `revocationList.revokeUser(userId, revokedBefore)` writes one
timestamp; a session is invalid if `createdAt < revokedBefore`. No listing, no
missed session. `d1SessionStore().revokeAllForUser()` was always a single
strongly-consistent `DELETE` and needed no change.

### [Fixed, was P1] Magic-link tokens were replayable, even on D1

The original claim was that KV's *eventual consistency* was the risk and D1
was safe because it's strongly consistent. That framing was wrong: the actual
bug was that `take()` was a `get` followed by a `delete` — not atomic, on
either store. Two requests arriving together could both read the token before
either deleted it, so both would log in. This reproduces on a strongly
consistent local emulator; it has nothing to do with replication lag.

**Fix**: `MagicLinkStore` now declares `atomicTake: boolean`, and
`magicLink()` throws at construction if the store's `atomicTake` is `false`
(escape hatch: `dangerouslyAllowReplayableTokens: true`, which is not
recommended). `d1MagicLinkStore` uses `DELETE ... RETURNING` — one statement,
so exactly one of two racing requests gets the row back — which is what
actually provides atomicity, not D1's consistency model. `kvMagicLinkStore`
still exists for prototyping but is rejected by default.

### [Fixed, was P1] A magic-link token authenticated (and consumed itself on) every route

`magicLink()`'s default token lookup read `?token=` on *any* request, because
the provider ran on every route the middleware covered. A URL-borne credential
leaks through Referer headers, browser history, access logs and shared
inboxes; anywhere it leaked, an attacker could use it to authenticate on an
arbitrary endpoint — or simply burn it by hitting any route, invalidating the
victim's real link before they clicked it.

**Fix**: reading `?token=` requires `allowTokenInQuery: true`, and a provider
configured that way is marked `callbackOnly` and must be listed in
`callbackProviders`, not `providers`. `createAuth()` throws if a
`callbackOnly` provider ends up in `providers`. `GET /callback` is the only
route `callbackProviders` runs on, and it is only mounted when
`callbackProviders` is non-empty.

### [Fixed, was P1] Auth responses had no cache directives

`GET /session` and friends returned only `content-type`. Nothing told a CDN
rule, service worker or corporate proxy that the response must not be
reused for a different user.

**Fix**: `auth.routes()` and the middleware's own 401/403 responses now carry
`Cache-Control: no-store, private` and `Vary: Cookie, Authorization`
unconditionally, with no opt-out.

### [Fixed, was P1] JWKS fetches were unbounded

No timeout, no size limit, no key-count limit, no content-type check. A hung
or hostile JWKS endpoint could stall every authenticated request behind the
fetch, or exhaust the isolate on an oversized/adversarial response.

**Fix**: `fetchTimeoutMs`, `maxJwksBytes` (checked against declared
`Content-Length` and the actual body) and `maxJwksKeys`, plus a `Content-Type`
check, all with sane defaults (3s / 256KB / 32 keys).

### [Fixed, P2 promoted to pre-1.0] `Session.sid` was reachable from application code

`c.get('authSession')` used to be the full `Session`, `sid` included. Nobody
was using it yet, which made this the only window to remove it without a
breaking change later.

**Fix**: the context value is now `SessionInfo` (`Session` minus `sid`). Only
`store.create()`'s return value — used internally to set the cookie — still
carries the raw id.

### [Fixed, P2 promoted to pre-1.0] Application `meta` could collide with SDK-reserved fields

`createSessionFor` used to spread `{ ...options.meta, email, provider, claims }`.
Passing `meta: { email: '...' }` silently overwrote the SDK's own `email`, and
conversely — if the provider didn't supply one — the application's `meta.email`
would come back out of `sessionToUser()` looking like an authenticated
attribute.

**Fix**: the SDK's own fields live under a single reserved key, `meta.__auth`,
via `AUTH_META_KEY`. `createSessionFor` throws if the caller's `meta` also uses
that key. Application metadata can use any other key without risk of it being
promoted into `AuthUser`.

### [Fixed] `hono` was declared an optional peer dependency but required at runtime

`package.json` had `peerDependenciesMeta: { hono: { optional: true } } }`, but
the root entry point statically imports `Hono`, so any project that used only
`createAuth`/`auth.routes()` without also having `hono` installed would hit
`MODULE_NOT_FOUND`. `./client` and `./store/*` genuinely have no hono
dependency (verified against the built output) — only the root does.

**Fix**: `optional: true` removed. `hono` is a required peer for the root
entry point.

### [Fixed, hardening] `kvApiKeyStore.revoke()` was a read-modify-write on the whole record

Not from the review, but the same shape of bug as the two P0s above:
`revoke()` read the record, set `revokedAt`, and wrote it back — racing a
concurrent `touch()` the same way session `touch()`/`revoke()` used to.

**Fix**: revocation moved into its own key, written blind. `revoke()` no
longer reads anything, so it has nothing to race. `touch()` still
read-modify-writes the core record, but only `lastUsedAt` is at stake there —
see [Known limits](#known-limits).

### [Fixed, hardening] `d1SessionStore.cleanup()` and `d1MagicLinkStore` gaps

`cleanup()` used a single `WHERE a <= ? OR b <= ?`, which can't use either
index for a seek and degrades to a full table scan as the table grows — split
into two indexed DELETEs (`migrations/0001_sessions.sql` gained an index on
`idle_expires_at` to match). `d1MagicLinkStore` had no `cleanup()` at all, so
expired-but-never-consumed tokens accumulated indefinitely; it now has one,
symmetric with the session and revocation stores.

### [Fixed, hardening] `serializeCookie`'s `path`/`domain` were not header-safe

Not from the review. `value` was already `encodeURIComponent`-encoded, but
`path` and `domain` were written into the `Set-Cookie` header verbatim. No
caller inside this SDK ever passes anything but `'/'` and no domain, so this
was unreachable through the SDK's own code paths — but `serializeCookie` is a
public export, and a caller passing an unsanitized `path` or `domain`
containing `\r\n` could inject arbitrary header lines.

**Fix**: both are checked against a control-character/`;`-free pattern and
`serializeCookie` throws if either fails it.

## Known limits

Read these before shipping.

1. **The JWKS refetch rate limit is per isolate**, as noted above. Configure
   `cache: { kv }` to reduce cross-isolate network pressure further.
2. **No rate limiting.** This package does not throttle `POST /session`,
   `magicLink.start()` or API key verification. Put a limiter in front of them.
3. **`storeUserClaims` duplicates identity data** into the session record, where
   it goes stale. Off by default; only the subject's email and provider name are
   persisted (under `meta.__auth`).
4. **`Session.scope` is not enforced.** It is carried through the store and
   returned to you, but nothing in this version evaluates org/role
   authorization.
5. **Cookie sessions do not carry the provider's full claims** unless you opt
   into `storeUserClaims`. `c.get('user').claims` on a cookie-authenticated
   request is minimal by design — load fresh profile data from your own database.
6. **`GET /callback` mints a session on a GET.** That is inherent to email
   links. The token is unguessable, single-use, and now confined to this one
   route, but an attacker who gets a victim to open *their* link logs the
   victim into the attacker's account. If that matters for your app, land on a
   page that POSTs to `/session` instead.
7. **A per-user revocation marker (`auth_user_revocations`) must outlive every
   session it could invalidate.** `revocationList(...).cleanup()` only deletes
   a marker once `maxSessionLifetimeSec` has passed since it was written —
   deleting it earlier would silently un-revoke sessions created before it. Set
   `maxSessionLifetimeSec` to the longest `absoluteTtlSec` you configure
   anywhere, or leave the generous 90-day default.
8. **`kvApiKeyStore.touch()` is a best-effort read-modify-write.** Two
   concurrent requests can lose one `lastUsedAt` update to the other. This is
   intentionally not fixed with the same key-split used for revocation:
   `lastUsedAt` is telemetry, not an access decision, so an occasional stale
   value is an acceptable trade for not adding a third KV key per API key. The
   revocation flag itself has no such race — see
   [Fixed findings](#fixed-findings-2026-08-review) below.

## Reporting

This is an internal package. Report findings in the repository's issue tracker
and do not include real tokens, session ids or API keys in the report.
