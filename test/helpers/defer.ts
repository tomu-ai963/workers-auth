/**
 * Plumbing for the session stores' `executionCtx` option: a fake
 * `ExecutionContext` and a switch that holds every cleanup delete open.
 */
import { expect, vi } from 'vitest';

import type { WaitUntilContext } from '../../src/types.js';

/** Records what `get()` hands to `waitUntil` instead of running it. */
export function fakeExecutionCtx(): WaitUntilContext & { promises: Promise<unknown>[] } {
  const promises: Promise<unknown>[] = [];
  return {
    promises,
    waitUntil(promise) {
      promises.push(promise);
    },
  };
}

/**
 * Counts deletes as they are issued and keeps each one pending until
 * `release()`. With `fail` set, a released delete rejects instead of running.
 */
export function deleteGate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  const gate = {
    issued: 0,
    fail: false,
    release: () => open(),
    /** Wraps one delete: counted now (synchronously), run after `release()`. */
    async hold<T>(run: () => Promise<T>): Promise<T> {
      gate.issued++;
      await opened;
      if (gate.fail) throw new Error('injected: cleanup delete fails');
      return run();
    },
  };
  return gate;
}

/** Whether `promise` has settled yet, without waiting for it. */
export function tracked<T>(promise: Promise<T>) {
  const state = { settled: false, promise };
  promise.then(
    () => {
      state.settled = true;
    },
    () => {
      state.settled = true;
    },
  );
  return state;
}

/** Waits until the store has issued `n` deletes (backends with real round trips need this). */
export async function issued(gate: { issued: number }, n: number): Promise<void> {
  await vi.waitFor(() => expect(gate.issued).toBe(n), { timeout: 30_000, interval: 5 });
}
