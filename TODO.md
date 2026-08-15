# Deferred work

Phase 2 items from the 2026-08 security review that were **not** implemented in
Step 1.5, with the reason each was deferred. All are non-security-blocking —
none of them are required before Step 2 (command-kun integration). Revisit
after Step 2 has surfaced real usage patterns, since several of these are
easier to size correctly with a real caller in hand.

## Deferred: needs a design decision, not just an implementation

### Defer expensive KV deletes to `ctx.waitUntil`

**Where**: `src/store/kv.ts` — `get()`'s expired-session cleanup
(`forget(sidHash)`), currently `await`ed inline on the request path.

**Why deferred**: doing this properly requires either (a) threading the Hono
`Context` / `ExecutionContext` into every `SessionStore` method, which changes
the `SessionStore` interface — a public API surface — or (b) accepting an
`ExecutionContext` at `kvSessionStore()` construction time, which doesn't fit
requests where the store is built once at module scope and reused (see the
README's two setup patterns). Either choice is an API decision worth making
deliberately, not as a drive-by fix. The cost being deferred is small: it's two
`kv.delete()` calls, once, only on the request that happens to find an expired
session.

**Revisit when**: Step 2 shows whether command-kun builds `createAuth` per
request (has `ExecutionContext` handy) or once at module scope (doesn't).

### `Sec-Fetch-Site: same-origin` fallback for browsers without `Origin` on same-origin requests

**Where**: `src/csrf.ts` — `checkOrigin`.

**Why deferred**: this is a security-relevant relaxation, not a pure
availability fix — it widens what the CSRF check accepts. `Sec-Fetch-Site` is
supported by all currently-shipping browsers; the failure mode it would guard
against (old Safari sending same-origin POSTs with no `Origin` header) is
believed obsolete but wasn't verified against real traffic. Adding a fallback
check without confirming the gap is real risks quietly weakening the check for
a problem that no longer exists.

**Revisit when**: command-kun's real traffic shows a same-origin POST being
rejected for a missing `Origin` header (it should show up as `csrf_failed` /
`origin_missing` in `onEvent`, which is exactly what that hook is for).

### JWKS grace period after cache expiry

**Where**: `src/providers/neon.ts` — `loadKeys` / `fetchJwks`.

**Why deferred**: fail-closed (no fallback to a stale JWKS once the cache TTL
has passed and a refetch fails) is the current, deliberate behavior — see
SECURITY.md. A grace period trades that guarantee for availability during a
JWKS outage. That's a real tradeoff between two legitimate priorities and
should be a conscious call by whoever owns the SLA for the projects consuming
this, not a default baked in here.

**Revisit when**: a real JWKS outage actually happens to one of the projects
using `neonAuth`, or before onboarding a project with an availability
requirement stricter than "auth fails closed."

### Production-misuse detection for `dangerouslyAllowInsecureCookies`

**Where**: `src/cookie.ts` — `resolveCookieConfig`.

**Why deferred**: the idea (warn if `dangerouslyAllowInsecureCookies: true` is
set while the request looks like it's over `https`) needs a concrete signal
for "in production" that's reliable inside a Worker, and none of the obvious
ones are: `c.req.url` protocol is spoofable by whatever's in front of the
Worker, environment variables aren't visible from `resolveCookieConfig`'s
call site (it runs at `createAuth()` construction, before any request), and a
Worker doesn't have a single canonical "am I in prod" bit. Guessing wrong in
either direction is worse than not guessing: a false warning trains people to
ignore it, and a missed one gives false confidence. The flag's name already
carries "dangerously" and requires an explicit line in a diff, which is most of
the real protection this would add.

**Revisit when**: there's a concrete proposal for the production signal that
doesn't rely on trusting client-controlled input.

## Not deferred — already implemented in Step 1.5

For reference, since a review of this file benefits from not re-litigating what
was already done: `touch()` KV split, `revokeAllForUser` user-marker, magic-link
`atomicTake` gate, `callbackProviders` split, `Cache-Control: no-store`, JWKS
timeout/size/key-count limits, `sid` removed from `SessionInfo`, `meta.__auth`
namespacing, `hono` peer dependency fix, JWT clock tolerance, `kvApiKeyStore`
revocation key split + `touch` implementation, `d1MagicLinkStore.cleanup()`,
`d1SessionStore.cleanup()` index split, cookie `path`/`domain`
header-injection guard. See SECURITY.md's "Fixed findings" section for the
reasoning behind each.

Two of these were further revised in Step 1.5-b, after this list was written:
`kvSessionStore()` now throws at construction time unless `revocation` or
`allowUnrevocableSessions: true` is set (rather than throwing only when
`revokeAllForUser()` is called), and the JWT clock tolerance default moved
from 60s to 30s. See SECURITY.md for both.
