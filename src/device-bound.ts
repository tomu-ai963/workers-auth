/**
 * Which session stores are device-bound (see `deviceBoundSessionStore()`).
 *
 * A registry rather than a marker property: a marker is inherited, so
 * `Object.create(wrapped)` with its own `get()` — or any object that copies
 * the marker — would pass for a device-bound store while skipping the device
 * check. Only the exact objects `deviceBoundSessionStore()` returned are in
 * here, and nothing outside this package can add to it.
 *
 * Its own module so the cookie middleware and `sessionBearer()` can consult it
 * without importing the device-auth entry point.
 */

const deviceBound = new WeakSet<object>();

export function registerDeviceBoundStore(store: object): void {
  deviceBound.add(store);
}

export function isRegisteredDeviceBoundStore(store: unknown): boolean {
  return typeof store === 'object' && store !== null && deviceBound.has(store);
}
