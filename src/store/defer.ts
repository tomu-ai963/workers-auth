/**
 * Shared by the session stores' `get()` for the cleanup of a session it has
 * already decided is expired.
 */

import type { WaitUntilContext } from '../types.js';

/**
 * Settles `pending` — a cleanup the caller has already *issued* — either by
 * awaiting it (no `executionCtx`: the pre-1.1 behaviour, failures included) or
 * by handing it to `executionCtx.waitUntil()` and returning at once.
 *
 * It takes a promise rather than a function on purpose: the statement goes out
 * now, on the request's own connection, and only the wait is skipped. An app
 * that closes its connection from `waitUntil` (`waitUntil(client.end())`) then
 * has the delete already queued ahead of the close instead of starting after it.
 *
 * A deferred failure is swallowed. The caller's answer (`null`) was decided
 * from the stored expiry before the delete was issued, so whether the delete
 * lands changes nothing about access — a leftover row or key is expired data
 * that `cleanup()` or KV's `expirationTtl` removes later. Nobody is left to
 * observe the rejection once the response is gone, and an unhandled one would
 * only be noise in the Worker's logs.
 */
export async function settle(executionCtx: WaitUntilContext | undefined, pending: Promise<unknown>): Promise<void> {
  if (!executionCtx) {
    await pending;
    return;
  }
  const quiet = pending.then(
    () => {},
    () => {},
  );
  try {
    executionCtx.waitUntil(quiet);
  } catch {
    // An unusable context (e.g. one kept past its request) must not turn a
    // clean `null` into an error; wait here instead, as without one.
    await quiet;
  }
}
