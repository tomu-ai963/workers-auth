/**
 * Response headers that every auth answer must carry.
 *
 * The client already sends `cache: 'no-store'`, but that only binds the one
 * caller we wrote. A CDN rule, a service worker, a corporate proxy or bfcache
 * will happily store an identity response that does not forbid it — which is
 * exactly the failure that forced `supabase-js` out of BITANE, only moved to
 * the server side. There is no opt-out for this.
 */

import type { Context } from 'hono';

export const NO_STORE = 'no-store, private';

/**
 * `Vary` names every request header the body depends on. Cookie covers session
 * auth; Authorization covers bearer/API-key auth, which changes the body just
 * as much.
 */
export const AUTH_VARY = 'Cookie, Authorization';

/** Marks the response uncacheable by anything between the Worker and the user. */
export function applyNoStore(c: Context): void {
  c.header('cache-control', NO_STORE);
  c.header('vary', AUTH_VARY);
}
