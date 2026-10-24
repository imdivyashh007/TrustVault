import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** Create an opaque 256-bit session identifier. This is a primitive, not an active login. */
export function createSessionId() {
  return randomBytes(32).toString('base64url');
}

/** Derive a synchronizer CSRF token bound to one session and a server-only secret. */
export function createCsrfToken(sessionId, sessionSecret) {
  if (typeof sessionId !== 'string' || !TOKEN_PATTERN.test(sessionId)) {
    throw new TypeError('Session ID must be a 256-bit base64url value.');
  }
  if (!Buffer.isBuffer(sessionSecret) || sessionSecret.length !== 32) {
    throw new TypeError('CSRF tokens require a 32-byte session secret from validated local configuration.');
  }
  return createHmac('sha256', sessionSecret)
    .update(`trustvault-csrf:v1:${sessionId}`, 'utf8')
    .digest('base64url');
}

/** Constant-time token comparison; malformed or missing values fail closed. */
export function verifyCsrfToken(sessionId, suppliedToken, sessionSecret) {
  if (typeof suppliedToken !== 'string' || !TOKEN_PATTERN.test(suppliedToken)) return false;
  try {
    const expected = Buffer.from(createCsrfToken(sessionId, sessionSecret), 'base64url');
    const supplied = Buffer.from(suppliedToken, 'base64url');
    return supplied.length === expected.length && timingSafeEqual(supplied, expected);
  } catch {
    return false;
  }
}
