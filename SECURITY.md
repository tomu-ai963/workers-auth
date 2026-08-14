# Security

Everything below is a **default**, not a recommendation you have to opt into.
Where an escape hatch exists it is named `dangerously*` and shows up in a diff.

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
- A login always mints a new id and revokes the previous session, so session
  fixation has nothing to fix.
- Raw ids never appear in responses (`GET /session` returns metadata only) or in
  audit events, which carry a 12-hex-char `sha256` fingerprint instead.

### Expiry

Both windows are enforced, always:

- **idle** — slides forward on activity, at most once per `touchIntervalSec`
  (default 60s) to avoid a store write per request;
- **absolute** — never extended. `touch()` clamps the idle window to it.

Configuring one without the other throws. Expiry is checked in code on every
read, not delegated to KV's `expirationTtl` (60s minimum, eventually consistent
deletes) or to a background job.

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
service-to-service calls. The first row is also deliberate — the session
endpoints only ever serve browsers, and requiring `Origin` there is what stops
login CSRF on the very first request, before any token has been handed out.

The CSRF cookie is intentionally not `HttpOnly`: the page's own JavaScript has to
read it to echo it back. It is not a credential on its own — it is only
meaningful together with the `HttpOnly` session cookie.

### Secret handling

- Every stored credential (session id, magic-link token, API key secret) is
  stored as SHA-256 hex and compared with `timingSafeEqual` over fixed-length
  digests, or `secretEquals` (hash-then-compare) when the input length is
  attacker-controlled.
- An unknown API key id still hashes the presented secret and still runs the
  comparison against a dummy digest, so "no such key" and "wrong secret" cost
  the same.
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
- `iss`, `aud`, `exp` and `nbf` are all verified, with a 5 second default
  tolerance (`clockToleranceSec`).
- A token without `exp` is rejected.
- A JWKS fetch failure fails closed.
- An unknown `kid` triggers at most one refetch per `minRefetchIntervalSec`.

### Magic links

- 256-bit token, stored as SHA-256, single-use, 15 minute default TTL.
- `start()` performs identical work for every address and never surfaces a
  delivery error, so it is not an account oracle.
- `d1MagicLinkStore` consumes tokens atomically (`DELETE ... RETURNING`).

### SQL

Every D1 query uses bound parameters. The only interpolated values are table
names, which are validated against `^[A-Za-z_][A-Za-z0-9_]*$` at construction and
throw otherwise.

## Known limits

Read these before shipping.

1. **`kvMagicLinkStore` cannot guarantee single use.** KV has no atomic
   read-and-delete, so two requests racing on the same token can both observe
   it. Use `d1MagicLinkStore` when that matters.
2. **KV revocation is eventually consistent** unless you attach a
   `revocationList`. Budget up to ~60s for a logout to be visible everywhere.
   `revoke()` writes the tombstone *before* deleting the record, and falls back
   to a 30 day horizon if the record is not visible yet, so a revoke is never
   silently lost.
3. **`GET /callback` mints a session on a GET.** That is inherent to email
   links. The token is unguessable and single-use, but an attacker who gets a
   victim to open *their* link logs the victim into the attacker's account. If
   that matters for your app, land on a page that POSTs to `/session` instead of
   mounting `/callback`.
4. **The JWKS refetch rate limit is per isolate.** Module-scope state does not
   span isolates, so a distributed flood of unknown-`kid` tokens can still cause
   more than one fetch per interval globally. Configure `cache: { kv }` to bound
   it further.
5. **No rate limiting.** This package does not throttle `POST /session`,
   `magicLink.start()` or API key verification. Put a limiter in front of them.
6. **`storeUserClaims` duplicates identity data** into the session record, where
   it goes stale. Off by default; only the subject's email and provider name are
   persisted.
7. **`Session.scope` is not enforced.** It is carried through the store and
   returned to you, but nothing in this version evaluates org/role
   authorization.
8. **Cookie sessions do not carry the provider's full claims** unless you opt
   into `storeUserClaims`. `c.get('user').claims` on a cookie-authenticated
   request is minimal by design — load fresh profile data from your own database.

## Reporting

This is an internal package. Report findings in the repository's issue tracker
and do not include real tokens, session ids or API keys in the report.
