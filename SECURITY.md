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
sometimes doesn't, `kvSessionStore()` requires the caller to pick a posture
**at construction time**: attach a `revocationList`, or pass
`allowUnrevocableSessions: true` to explicitly accept that
`revokeAllForUser()` will be a no-op. Omitting both throws when the store is
built. `revocationList` and `d1SessionStore` both answer "log out everywhere"
with a single timestamp comparison (`created_at < revoked_before`) that needs
no enumeration and therefore cannot miss a session.

Every `SessionStore` exposes `canRevokeAllForUser: boolean`, fixed at
construction, so this is checkable in code rather than only in documentation
— relevant if "log out everywhere" is a compliance or audit requirement and a
silent no-op would otherwise be indistinguishable from success.

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

- Every stored credential (session id, magic-link token, API key secret,
  trusted-device secret) is stored as SHA-256 hex and compared with `timingSafeEqual` over fixed-length
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
- `iss`, `aud`, `exp` and `nbf` are all verified, with a 30 second default
  tolerance (`clockToleranceSec`). This is a separate lever from session
  revocation: leeway only widens the window `exp`/`nbf` are checked against
  during JWT verification (proof of identity), while `revoke()` /
  `revokeAllForUser()` invalidate the *session* the JWT led to — increasing
  one has no effect on the other. The tradeoff leeway makes: raising it
  reduces false 401s caused by clock drift between Neon and the Worker's edge,
  but every extra second is also a second an expired token keeps working past
  its stated `exp`. 30s was chosen as a deliberately conservative value —
  lower than the 60s often used elsewhere — because for this SDK the
  immediacy of expiry matters more than shaving off the rare drift-caused
  401. It is a per-call option (`clockToleranceSec`), so raise or lower it for
  your own deployment if the tradeoff should land differently there.
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

### `AuthUser.rateLimitId`

A single stable identifier, always set, for a rate limiter to key on —
`user.rateLimitId` — instead of every caller having to work out which of
`user.id` / `claims.keyId` / `claims.sub` is the right value for whichever
provider happens to be configured.

**Why top-level, not under `claims`.** Every other provider-specific value
lives in `claims` and stays there deliberately — see
[Layer 2: providers](./README.md#layer-2-providers) — so that providers are
swappable without application code branching on which one is active. Rate
limiting is the one exception: it is a cross-cutting concern on the same
level as authentication itself (every authenticated request needs an
identifier to limit on, regardless of provider), not a provider-specific
detail. Burying it in `claims` would have re-created exactly the problem this
field exists to close — a caller having to know, per provider, which claim
key to read.

**Why the value differs per provider.** Each provider already has a natural
answer for "what's the stable identifier a rate limiter should never lose
continuity on," and it isn't always `id`:

| provider | `rateLimitId` | why not `id`? |
| --- | --- | --- |
| `apiKey` | `claims.keyId` (the key presented) | `id` is the subject the key acts as, and one subject can hold several keys (e.g. one per deployment); limiting by subject would let a hot or compromised key exhaust every other key's quota too. |
| `neonAuth` | JWT `sub` | happens to equal `id` here — `sub` is already the identity `id` is set from. |
| `magicLink`, no `resolveUser` | the verified email address | it's already `id` in this configuration — no more stable value exists to fall back to. |
| `magicLink`, with `resolveUser` | whatever the callback's `AuthUser.rateLimitId` says | the SDK didn't create that user record, so it cannot guess a stable key for it — `resolveUser` implementations must set this themselves. |

**Persistence.** `rateLimitId` is written into `Session.meta.__auth`
unconditionally by `createSessionFor` — unlike the rest of `claims`, which is
only persisted when `storeUserClaims` is on (see
[Known limits](#known-limits)). Without this, a cookie-authenticated request
on request 2+ would rebuild `AuthUser` via `sessionToUser()` from the stored
session and lose `rateLimitId`, even though request 1 (the login itself) had
it — a rate limiter reading `user.rateLimitId` would then see it only on
`POST /session`, not on the requests that follow. `sessionToUser()` falls
back to `session.userId` when a stored session predates this field (a session
written by a version of this SDK before `rateLimitId` existed), so an
in-flight session across a deploy never surfaces an empty value — see
[Known limits](#known-limits) for what that fallback means operationally.

**Enforcement.** `AuthUser.rateLimitId` is a required field, and
`verifyProviders()` throws if a provider (built-in or custom) returns a user
without one — caught by the same handling as any other provider error, so it
surfaces as `auth.failed` with that provider's name via `onEvent`, and the
request fails closed with the uniform `401`, rather than continuing with a
value that would silently defeat rate limiting.

**Migration note (this field replaces an interim workaround, not part of this
SDK).** A caller using the `apiKey` provider that was reading
`user.claims.keyId ?? user.id` itself as the rate-limit key can switch to
reading `user.rateLimitId` directly — for `apiKey` the value is identical
(`claims.keyId` is still set too, unchanged, so this is a non-breaking
switch). This is the SDK now doing formally, for every provider, what that
call site was working around for one.

### Magic links

Single use and confined to the callback route — the two properties that make a
magic link safe to email. Both are explained at length in the
[README](./README.md#magiclink-store-sendtoken-ttlsec), because both were the
subject of confirmed findings; see below.

### PIN / trusted device / email code (`deviceAuth`)

- **Nothing secret at rest.** Email codes are `HMAC-SHA256(key, email \n code)`;
  device secrets (32 random bytes) are `sha256`; PINs are
  `PBKDF2-SHA256(HMAC(pepper, pin), 16-byte salt)` with a per-credential salt.
  The HMAC key and the pepper are HKDF-derived from one app secret, with
  distinct `info` labels so neither reveals the other or the secret. A secret
  that is short or obviously low-entropy is refused at construction.
- **The pepper is the real protection for a 6-digit PIN.** 10^6 PINs fall to
  brute force at any PBKDF2 cost once the table *and* the pepper leak; the
  pepper keeps a table-only leak useless. That is why the iteration count is
  configurable (Free-plan CPU limits) without changing the security argument.
- **Codes:** 6 (or, opt-in, 8) digits from `crypto.getRandomValues` with
  rejection sampling (no modulo bias), 10-minute lifetime, single use
  (`DELETE ... RETURNING`, so of two correct submissions racing exactly one
  wins), 5 attempts per code. Comparison is constant time over fixed-length
  HMAC hex.
- **Guessing budget per address, not per code.** A resend inside the first
  code's lifetime keeps the attempts already used (and cannot extend that
  lifetime), and every address has a cap of 10 failed verifications per fixed
  24 h window across all of its codes — 10 per window, so up to 20 within 24 h
  when they straddle a window boundary. The cap is reserved *before* a code is
  checked and given back on success, or when there was no live code to check
  (none, expired, or its attempts used up — nothing was compared, so nothing
  is charged). A slot is only taken while one is free; a verify refused at the
  cap leaves the count untouched, so a burst of concurrent verifies can
  neither overshoot the cap nor fill it without real wrong guesses. A request that presents
  a valid trusted device registered to the address is counted against that
  device's own budget (`maxFailuresPerDevice`, default 10 per window) instead,
  so the owner of a device can still verify — and unlock a PIN — when someone
  else has spent the address's budget. See Known limits for the residual risk
  in numbers and for the lock-out trade-off.
- **Attempts are reserved before they are checked.** The 10-per-address (and
  per-device), 5-per-code and 3-per-account limits each move their counter in
  the same single statement that checks it (`UPSERT ... DO UPDATE ... WHERE
  count < max RETURNING`, `UPDATE ... WHERE attempts < max RETURNING`, `UPSERT ... DO UPDATE ... WHERE
  failed_count < max AND locked_at IS NULL RETURNING`), *before* the hash is
  compared. Twenty concurrent wrong PINs run at most three verifications;
  fifteen concurrent wrong codes get at most ten checked (with the per-code
  limit raised so the address cap is what binds). Both are tested, as is a
  burst of 20 or 40 verifies with no code leaving the budget untouched.
- **A PIN is only ever checked alongside a valid trusted device,** and the
  failure counter is only touched after that device has been proven. Someone
  who merely knows an address cannot lock that account's PIN login.
- **No CPU for unauthenticated callers.** A missing, tampered, revoked or
  expired device token, a locked account, or an account without a PIN is
  answered *before* any PBKDF2 runs. There is deliberately no dummy derivation:
  equalising timing would mean letting anyone make the Worker spend ~100 ms of
  CPU per request.
- **Locked means locked.** While locked, a right and a wrong PIN produce the
  identical `401 {"error":"email_verification_required"}` — the same answer as
  an unknown device — because the PIN is never compared at all. Time does not
  unlock; only a successful email code does (a magic-link login does not).
- **No account enumeration at `/email/start`.** The response, and the call to
  `sendCode`, are the same whether or not the address has an account; the
  account is only looked up (`resolveUser`) after a correct code. Apps must not
  branch inside `sendCode` on account existence (documented on the option).
- **Rate limits:** 60 s cooldown and 5 codes/hour per address (per device for
  a request presenting one of the address's trusted devices), 20 starts per IP
  per hour; verifies and PIN logins are capped per IP too. IPv4 is keyed per
  address, IPv6 per **/64** (one subscriber typically holds a whole /64), and
  only `CF-Connecting-IP` is read — never `X-Forwarded-For`. Per-address keys
  use the app's `normalizeEmail`, so an app that folds `+tags` / dots folds the
  limits too. All of these apply to every address equally, so a `429` says
  nothing about whether an account exists. Optional: `botCheck` (Turnstile etc.)
  before `/email/start`, `/email/verify` and `/pin/login`, failing closed;
  `circuitBreaker` (off by default) on `/email/verify`, counting only
  verifications that compared a live code, attempts and failures in one row
  and one fixed window.
- **PIN changes require a fresh email code** (default: within 10 minutes). The
  freshness fact (`emailVerifiedAt`) is written under a module-private symbol
  that the package's entry points do not export, so neither application code
  nor any other provider can mint it; a PIN-login session never has it.
- **Weak PINs** are refused at enrolment: fewer than 3 distinct digits, runs
  (wrapping 9→0), palindromes, repeated blocks, doubled digits, two keypad
  lines, and the six-digit entries of a public common-password list; dates
  optionally. Apps can add their own rule.
- **Devices** slide 90 days from last use, end 365 days after registration
  regardless, and can be revoked individually, all at once, or by the device
  itself (`/device/forget`).
- **Revoking a device ends its sessions.** Sessions minted on a device record
  it, and `deviceBoundSessionStore` checks that device on every `get()` (cookie
  and bearer alike), refusing and deleting the session once the device is
  revoked or expired. "Revoke all devices" and `revokeOtherDevicesOnChange` also
  call `revokeAllForUser()`, which reaches sessions that have no device. Both
  prerequisites are checked when `deviceAuth()` is constructed. Only the exact
  object `deviceBoundSessionStore()` returned counts as device-bound (a
  `WeakSet` registry, not an inheritable marker), and the cookie middleware and
  `sessionBearer()` refuse a session carrying a device id that they read
  through any other store — so `Object.create(wrapped)`, an app wrapper over
  it, or a second `createAuth()` on the same table cannot skip the check.
- **CSRF (cookie transport):** every POST requires a same-origin (or
  `trustedOrigins`) `Origin`, and once a CSRF cookie exists, the double-submit
  header too — the device cookie is an ambient credential, so a cross-site
  `POST /pin/login` is rejected before it can log in *or* count a failure.
- **Bearer and cookie sessions do not cross over.** `sessionBearer()` accepts
  only sessions minted with `transport: 'bearer'`, and the cookie path refuses
  them. Bearer sessions are short-lived (12 h, no sliding) because page JS can
  read them.
- **Bounded input.** Request bodies are capped at 4 KB, by `Content-Length`
  and by counting the stream, before any JSON parsing.
- **Secret rotation:** every hash records the `keyId` of the secret that made
  it; `previousSecrets` keep old rows verifiable and PINs are re-hashed under
  the current secret on their next success. See the README for the procedure.

### SQL

Every D1 query uses bound parameters. The only interpolated values are table
names, which are validated against `^[A-Za-z_][A-Za-z0-9_]*$` at construction and
throw otherwise.

The Postgres stores likewise bind every value (`$1`…). The one interpolated
name is the `schema` option, checked against `^[a-z_][a-z0-9_]{0,62}$` when
the store is built (no quotes, dots, whitespace, semicolons or upper case);
table names are fixed.

### Postgres stores (`./store/pg`)

The guarantees above hold on Postgres under these conditions, which are the
app's to meet (README → Postgres stores):

- **Autocommit, and a connection of its own per request.** Failure slots are
  reserved before a PIN or code is checked and must stay reserved, so each
  `query()` must commit on its own. Inside a transaction the app opened, a
  rollback would hand the reserved guesses back and the PIN/code limits would
  not hold; a `pg` Client shared across requests can put one request's
  statements into another's transaction. A runtime check was considered and
  left out: `now() = statement_timestamp()` reads as "autocommit" for the first
  statement of a transaction sent in the same message as its `BEGIN`
  (measured: `BEGIN; SELECT now() = statement_timestamp()` returns true), so it
  cannot detect the case reliably.
- **`rowCount` is a number.** Outcomes that matter (was a PIN replaced, which
  devices were revoked) come from `RETURNING` rows; a count the stores still
  read must be a finite number or they throw. An adapter that turned a
  driver's `null` into `0` once made a PIN change skip revoking the other
  devices (review F1).

- **Fresh reads.** The executor must reach the primary with no query cache:
  Hyperdrive only with `--caching-disabled`, no read replica. A cached or
  lagging `SELECT` keeps a revoked session or device alive and lets a rate
  limit read an old count.
- **READ COMMITTED.** Each limit is one conditional statement; under READ
  COMMITTED a statement that meets a row locked by a concurrent writer waits,
  then re-evaluates its condition against the row as that writer committed it
  (PostgreSQL docs, 13.2.1). Tested deterministically for all seven
  conditional statements by holding a row lock on one connection and running
  the statement on another (`test/pg-node/locks.test.ts`).
- **PIN change is one transaction** (D1: one batch) on both backends: the new
  PIN, the cleared login guard and — with `revokeOtherDevicesOnChange` — the
  other devices' revocation commit together or not at all (review F3; before,
  a failure after the PIN write left the new PIN live and the other devices
  trusted). Ending the account's sessions follows as a separate step, because
  a KV session store cannot join a transaction; if it fails, the other
  devices' sessions are refused anyway, since their devices are revoked
  (deviceBoundSessionStore). Sessions with no device survive such a failure
  until they expire or the next revoke-all.
- **What D1's single writer gave for free** is made explicit: PIN replacement
  serialises per account with `pg_advisory_xact_lock` (without it, two
  concurrent changes fail with a unique violation — reproduced in
  `test/pg-node/races.test.ts`), and `resetLoginGuard` locks the row before
  reading the state it reports.
- **Retries:** once, and only on 40001 / 40P01, which Postgres raises after
  rolling the transaction back. Never on network errors or timeouts, where the
  statement may have committed and a reservation would be charged twice.

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

**Fix**: `kvSessionStore()` requires a `revocationList` or an explicit
`allowUnrevocableSessions: true`, checked at construction (see below — this
was originally a call-time throw, moved to construction time in a follow-up),
and the reverse index is gone entirely — enumeration-based revocation was the
bug, so it was removed rather than patched. `revocationList.revokeUser(userId,
revokedBefore)` writes one timestamp; a session is invalid if `createdAt <
revokedBefore`. No listing, no missed session. `d1SessionStore().revokeAllForUser()`
was always a single strongly-consistent `DELETE` and needed no change.

**Follow-up**: the original fix above still let `kvSessionStore()` construct
successfully without a `revocationList`, and only threw once
`revokeAllForUser()` was actually called. That call tends to happen almost
exclusively during incident response ("log out everywhere" after a compromised
account) — the worst possible moment to discover a missing dependency for the
first time, since it would not have surfaced in ordinary development or
testing. The check was moved to construction time: `kvSessionStore()` now
throws immediately unless `revocation` is set or `allowUnrevocableSessions:
true` is passed to explicitly accept the reduced guarantee. With
`allowUnrevocableSessions: true`, `revokeAllForUser()` is a no-op instead of
throwing — the caller already acknowledged this at construction, so there is
no second throw to hit later.

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

## Fixed findings (2026-10 review of `deviceAuth`)

Each P0 was first reproduced as a test against the pre-fix code
(`31af0a7`), where it failed; the same tests pass after the fix
(`test/device-auth-p0-regression.test.ts`).

- **[Fixed, was P0] Email codes could be brute-forced across resends.** A
  resend reset the 5-attempt budget, so one address allowed 25 guesses/hour
  indefinitely (≈ 20 %/year). Now: attempts carry over within the first code's
  lifetime, and a per-address cap (10 failures / 24 h, reserved before
  checking) spans all codes. 8-digit codes are available.
- **[Fixed, was P0] Revoking a device did not end its sessions.** A thief's
  session survived `/devices/:id/revoke`, `revoke-all` and
  `revokeOtherDevicesOnChange`. Now: device-bound sessions are checked against
  their device on every request, and the bulk revocations also call
  `revokeAllForUser()`; `deviceAuth()` refuses a configuration that lacks
  either.
- **[Fixed, was P1] Per-IP limits were per IPv6 address.** Now per /64; a
  `botCheck` hook and an optional `circuitBreaker` were added, and the residual
  risk is stated in numbers (Known limits 10).
- **[Fixed, P2]** `normalizeEmail` option; extended weak-PIN rules and list;
  bearer sessions refused on the cookie path; `emailVerifiedAt` moved behind a
  module-private symbol; `sendCode` / `onSendError` caveats; secret entropy
  check; 4 KB body cap; `deviceLabel` escaping and `getClientIp` caveats
  documented; `requireClientIp` option.

## Fixed findings (2026-10 re-review of `deviceAuth`)

The P1 was first reproduced as a test against the pre-fix code (`f16066c`),
where it failed; it passes after the fix
(`test/device-auth-lockout.test.ts`, "verification test E").

- **[Fixed, was P1] The per-address failure cap locked owners out.** Anyone
  who knew an address could spend its 10-failure budget (a verify with no
  code at all was charged), and a user whose PIN was locked then had no way
  to get the email code that unlocks it for 24 h. Now: a verify with no live
  code (none, expired, attempts used up) is not charged; a request presenting
  a valid trusted device of the address uses that device's own budget
  (`emailCode.maxFailuresPerDevice`, plus per-device resend cooldown and
  hourly cap at `/email/start`) instead of the address's; `botCheck` can also
  guard `/email/verify`. What the cap still stops is listed in Known limits 14.
- **[Fixed, P2] Fixed-window wording.** The caps are per fixed window: 10 per
  window, up to 20 across a window boundary within 24 h. Docs now say so.
- **[Fixed, P2] The device-bound store could be stepped around.** The marker
  was an inherited property, so `Object.create(wrapped)` with its own `get()`
  passed the check. Now a `WeakSet` registry, and session readers refuse
  device-bound sessions read through unregistered stores.
- **[Fixed, P2] Circuit-breaker counting.** No-live-code verifies counted as
  failures, and attempts and failures were two rows that could sit in
  different windows. Now only checked verifications count, both counters are
  one row in one window, and the README gives the number of IPs needed to
  open it.
- **[Fixed, P2] SecLists attribution.** Its MIT notice ships in
  `THIRD_PARTY_NOTICES`.
- **[Fixed, was P1 — found re-checking `2491bdc`] A burst of no-code verifies
  filled the budget.** The failure slot was taken unconditionally and a
  request refused at the cap did not give it back, so requests that arrived
  before earlier ones had been refunded stayed counted: 20 parallel verifies
  with no code ever sent locked an address for 24 h. The slot is now taken by
  a conditional statement that changes nothing at the cap (address and device
  budgets alike).

## Known limits

Read these before shipping.

1. **The JWKS refetch rate limit is per isolate**, as noted above. Configure
   `cache: { kv }` to reduce cross-isolate network pressure further.
2. **No rate limiting outside `deviceAuth`.** This package does not throttle
   `POST /session`, `magicLink.start()` or API key verification. Put a limiter
   in front of them. `deviceAuth` has its own limits (see above); its per-IP
   limits are skipped when no client IP is available (`CF-Connecting-IP` is
   always set on Cloudflare, so this only affects non-Cloudflare setups) unless
   `requireClientIp: true`, which refuses such requests instead.
3. **`storeUserClaims` duplicates identity data** into the session record, where
   it goes stale. Off by default; only the subject's email, provider name, and
   `rateLimitId` are persisted (under `meta.__auth`) regardless — see
   [`AuthUser.rateLimitId`](#authuserratelimitid) for why that one field is the
   exception.
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
9. **A bearer session token is readable by page JavaScript.** In
   `deviceAuth`'s `transport: 'response'` mode, an XSS on the frontend can
   exfiltrate the session token and the device token. The session token is
   short-lived (12 h default) and the device token alone is useless without
   the PIN, but the app owns where both are stored and must treat XSS as
   account compromise. Use `transport: 'cookie'` wherever the layout allows.
10. **A 6-digit email code is still guessable at scale.** After the 2026-10
    fixes the budget is at most **10 failed guesses per address per fixed
    24 h window** (so up to 20 inside 24 h across a window boundary, but no
    more than 10 per window on average over a year), plus
    `maxFailuresPerDevice` per window for whoever holds one of the address's
    trusted devices:
    - one targeted address: ≤ 3,650 guesses/year → ≈ **0.37 % per year**
      (8-digit codes: ≈ 0.0037 %);
    - a spray across N registered addresses by an attacker with unlimited IPs
      (a botnet, many /64s): 10·N guesses/day → N = 1,000 ≈ 0.01 expected
      takeovers/day (≈ 3–4 a year); N = 100,000 ≈ 1 a day;
    - from one IPv4 address or IPv6 /64 (60 verifies/hour): ≤ 1,440
      guesses/day ≈ 0.0014 expected takeovers/day.
    Every guess needs a code to exist, so each also lands an email in the
    target's inbox. For larger user bases use `botCheck` (Turnstile) on
    `/email/start`, `emailCode.digits: 8` (÷100), and consider
    `circuitBreaker`.
11. **PBKDF2 at the default 100,000 iterations costs ~146 ms of CPU** per PIN
    check (measured locally in workerd), which exceeds the Workers Free plan's
    10 ms limit. Free-plan apps should lower `pin.iterations`; the pepper, not
    the iteration count, carries the security argument (see above). The local
    workerd used for this measurement accepted 100,001 iterations; the 100,000
    cap is Cloudflare's documented production limit and is enforced by
    `deviceAuth()` at construction regardless.
12. **The lockout is per account and shared across devices.** Anyone holding
    *one* of an account's trusted devices can lock the PIN login for all of
    them with three wrong guesses. Recovery is an email code.
13. **`auth_trusted_devices.email` and `auth_email_codes.email` store the
    normalised address in the clear**, as `auth_magic_link_tokens` already did.
    It is an identifier, not a credential; audit events use a fingerprint.
14. **The per-address failure cap is a lock anyone can pull.** Ten wrong
    guesses against live codes for an address — requesting the codes (which
    land in the owner's inbox) and guessing, nothing more than the address
    needed — make `/email/start` and `/email/verify` answer `429` for it until
    the window ends, for every request that does not present a trusted device
    of the address. Until then that stops: logging in on a new device;
    unlocking a locked PIN; setting or changing the PIN; app routes behind
    `requireFreshEmailAuth()`; and any login for a user with no PIN or whose
    trusted device has expired or been revoked. PIN login on a trusted device
    is unaffected, and **a user holding a valid trusted device of the address
    recovers through that device's own budget** (`maxFailuresPerDevice`),
    which someone without the device cannot spend. Users with no live trusted
    device have to wait. This is the deliberate price of bounding guesses per
    address; tune `emailCode.maxFailuresPerEmail` / `failureWindowSec` if it is
    wrong for your product.
15. **`circuitBreaker` is a global off-switch for email login** in the hands of
    whoever can generate `minFailures` failures. It is off by default for that
    reason. With default per-IP limits that takes at least
    `⌈minFailures / 120⌉` IPv4 addresses or IPv6 /64s for a window of up to an
    hour (README has the derivation) — and one client if client IPs are
    missing and `requireClientIp` is off.
16. **Device-bound sessions cost one extra D1 read per request** for sessions
    minted on a trusted device. `deviceBoundSessionStore` wraps the inner store
    through its prototype; a custom store that relies on `this`-bound private
    class fields (`#x`) would need its own wrapper — placed *inside*
    `deviceBoundSessionStore()`, since a wrapper outside it is no longer
    recognised as device-bound and its device-bound sessions are refused.
17. **Weak-PIN detection is a blocklist, not a guarantee.** It covers the
    structural patterns and common picks listed above; birthdays are only
    refused with `pin.rejectDateLike`.

### Postgres stores

18. **Tested against a local Neon HTTP proxy, not Neon itself.** The suites
    run through `@neondatabase/serverless` against `local-neon-http-proxy` in
    front of PostgreSQL 17, and through `pg` directly. Neon's real HTTP
    endpoint, its connection pooler, compute cold starts and other Postgres
    versions have not been exercised; a run against a test Neon branch is the
    remaining check.
19. **A transient network error surfaces as a 500.** It is deliberately not
    retried (see above), so a request can fail where a retry would have
    worked; the client retries the request instead.
20. **The advisory-lock key space is shared with the app.** The key is
    `hashtextextended('workers-auth:credential:' || account_id, 0)`; an app
    taking advisory locks with colliding 64-bit keys on the same database
    would only add waiting, never break correctness.
21. **Latency is per query.** Over Neon HTTP every statement is a round trip
    from the Worker to the database region: an authenticated request on a
    trusted device costs two or three (the session, its device, an occasional
    sliding-expiry update), an email verification about fifteen. A suspended
    Neon compute adds its cold start to the first one.

## Reporting

This is an internal package. Report findings in the repository's issue tracker
and do not include real tokens, session ids or API keys in the report.
