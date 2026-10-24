const DEFAULT_WINDOW_MS = 15 * 60 * 1000;
const DEFAULT_MAX_FAILURES = 5;
const DEFAULT_LOCKOUT_MS = 15 * 60 * 1000;

/** Process-local consecutive-failure throttle; callers must use the socket IP, not forwarded headers. */
export function createLoginRateLimiter({
  windowMs = DEFAULT_WINDOW_MS,
  maxFailures = DEFAULT_MAX_FAILURES,
  lockoutMs = DEFAULT_LOCKOUT_MS,
  now = Date.now,
} = {}) {
  if (![windowMs, maxFailures, lockoutMs].every(Number.isSafeInteger) || windowMs < 1 || maxFailures < 1 || lockoutMs < 1) {
    throw new TypeError('Login rate-limit settings must be positive integers.');
  }
  const failuresByClient = new Map();
  const inFlightByClient = new Map();

  function stateFor(clientKey) {
    const timestamp = now();
    let state = failuresByClient.get(clientKey);
    if (state?.lockedUntil && state.lockedUntil <= timestamp) {
      failuresByClient.delete(clientKey);
      state = null;
    }
    if (state && !state.lockedUntil && timestamp - state.windowStartedAt >= windowMs) {
      failuresByClient.delete(clientKey);
      state = null;
    }
    return state;
  }

  function check(clientKey) {
    const state = stateFor(clientKey);
    if (!state?.lockedUntil) return { allowed: true, retryAfterSeconds: 0 };
    return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((state.lockedUntil - now()) / 1000)) };
  }

  function recordFailure(clientKey) {
    const timestamp = now();
    let state = stateFor(clientKey);
    if (!state) state = { failures: 0, windowStartedAt: timestamp, lockedUntil: 0 };
    state.failures += 1;
    if (state.failures >= maxFailures) state.lockedUntil = timestamp + lockoutMs;
    failuresByClient.set(clientKey, state);
    return check(clientKey);
  }

  function recordSuccess(clientKey) {
    failuresByClient.delete(clientKey);
  }

  function begin(clientKey) {
    const result = check(clientKey);
    if (!result.allowed) return result;
    const inFlight = inFlightByClient.get(clientKey) || 0;
    if (inFlight >= 2) return { allowed: false, retryAfterSeconds: 1 };
    inFlightByClient.set(clientKey, inFlight + 1);
    return result;
  }

  function finish(clientKey, success) {
    const inFlight = inFlightByClient.get(clientKey) || 0;
    if (inFlight <= 1) inFlightByClient.delete(clientKey);
    else inFlightByClient.set(clientKey, inFlight - 1);
    if (success) {
      recordSuccess(clientKey);
      return check(clientKey);
    }
    return recordFailure(clientKey);
  }

  return { check, begin, finish, recordFailure, recordSuccess };
}
