import { createSessionId, createCsrfToken, verifyCsrfToken } from './sessionSecurity.js';

const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000;

/** In-memory, single-process session store. Restarting the backend revokes sessions. */
export function createSessionStore({ sessionSecret, ttlMs = DEFAULT_TTL_MS, now = Date.now } = {}) {
  if (!Buffer.isBuffer(sessionSecret) || sessionSecret.length !== 32) {
    throw new TypeError('Sessions require a validated 32-byte SESSION_SECRET.');
  }
  if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new TypeError('Session lifetime must be a positive integer.');
  const sessions = new Map();

  function create(authenticated = false) {
    const timestamp = now();
    for (const [id, session] of sessions) {
      if (session.expiresAt <= timestamp) sessions.delete(id);
    }
    const id = createSessionId();
    const session = { id, authenticated, expiresAt: timestamp + ttlMs };
    sessions.set(id, session);
    return { ...session, csrfToken: createCsrfToken(id, sessionSecret) };
  }

  function get(id) {
    if (typeof id !== 'string') return null;
    const session = sessions.get(id);
    if (!session) return null;
    if (session.expiresAt <= now()) {
      sessions.delete(id);
      return null;
    }
    return { ...session, csrfToken: createCsrfToken(id, sessionSecret) };
  }

  function destroy(id) {
    return sessions.delete(id);
  }

  function verifyCsrf(session, suppliedToken) {
    return Boolean(session && verifyCsrfToken(session.id, suppliedToken, sessionSecret));
  }

  return { create, get, destroy, verifyCsrf, ttlMs };
}
