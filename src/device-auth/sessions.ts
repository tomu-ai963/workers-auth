/**
 * Device-bound sessions: revoking a trusted device ends the sessions minted on it.
 *
 * A session minted by `deviceAuth` on a trusted device carries that device's
 * id in `meta.__auth.deviceId`. This wrapper makes every `get()` of such a
 * session also check the device — one D1 point read — and refuses (and
 * revokes) the session once the device is revoked, expired, or no longer the
 * account's. Both transports go through `SessionStore.get()` (the cookie
 * middleware and `sessionBearer()`), so wrapping the store once covers both.
 *
 * Sessions without a `deviceId` (an email login with `trustDevice: false`, or
 * any session not minted by `deviceAuth`) are passed through untouched and
 * cost nothing extra.
 *
 * `deviceAuth()` refuses an `Auth` whose store is not wrapped, so the
 * guarantee cannot be lost by forgetting this.
 */

import { AUTH_META_KEY } from '../middleware.js';
import type { Clock, Session, SessionStore } from '../types.js';
import type { DeviceAuthStore } from './store.js';

const DEVICE_BOUND = Symbol('workers-auth.device-bound-session-store');

export type DeviceBoundSessionStoreOptions = { clock?: Clock };

function boundDeviceId(session: Session): string | null {
  const auth = session.meta?.[AUTH_META_KEY] as { deviceId?: unknown } | undefined;
  return typeof auth?.deviceId === 'string' ? auth.deviceId : null;
}

export function isDeviceBoundSessionStore(store: SessionStore): boolean {
  return (store as { [DEVICE_BOUND]?: unknown })[DEVICE_BOUND] === true;
}

export function deviceBoundSessionStore<S extends SessionStore>(
  inner: S,
  devices: Pick<DeviceAuthStore, 'findDevice'>,
  options: DeviceBoundSessionStoreOptions = {},
): S {
  if (!inner || typeof inner.get !== 'function') {
    throw new TypeError('deviceBoundSessionStore: a SessionStore is required');
  }
  if (!devices || typeof devices.findDevice !== 'function') {
    throw new TypeError('deviceBoundSessionStore: a DeviceAuthStore is required');
  }
  if (isDeviceBoundSessionStore(inner)) return inner;
  const now: Clock = options.clock ?? Date.now;

  // A prototype-linked view keeps every other method of the inner store
  // (`cleanup()` on a D1 store, and anything added later) without listing it.
  const wrapped = Object.create(inner) as S;
  Object.defineProperties(wrapped, {
    [DEVICE_BOUND]: { value: true },
    canRevokeAllForUser: { get: () => inner.canRevokeAllForUser },
    get: {
      value: async (sid: string): Promise<Session | null> => {
        const session = await inner.get(sid);
        if (!session) return null;
        const deviceId = boundDeviceId(session);
        if (deviceId === null) return session;

        const device = await devices.findDevice(deviceId);
        const at = now();
        const live =
          device !== null &&
          device.accountId === session.userId &&
          device.revokedAt === null &&
          at < device.idleExpiresAt &&
          at < device.absoluteExpiresAt;
        if (live) return session;
        // Fail closed and make it stick: the session dies with its device.
        await inner.revoke(sid);
        return null;
      },
    },
  });
  return wrapped;
}
