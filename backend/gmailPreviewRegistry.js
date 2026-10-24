const PREVIEW_TTL_MS = 5 * 60_000;
const PREVIEW_MAX_IDS = 5;

/** Keeps the exact rendered preview IDs briefly and binds them to a live local session. */
export function createGmailPreviewRegistry({ ttlMs = PREVIEW_TTL_MS, now = Date.now, maxEntries = 100 } = {}) {
  if (![ttlMs, maxEntries].every(Number.isSafeInteger) || ttlMs < 1 || maxEntries < 1) {
    throw new TypeError('Gmail preview registry settings must be positive integers.');
  }
  const previews = new Map();

  function prune() {
    const timestamp = now();
    for (const [sessionId, preview] of previews) {
      if (preview.expiresAt <= timestamp) previews.delete(sessionId);
    }
  }

  return {
    remember(sessionId, ids) {
      if (typeof sessionId !== 'string' || !sessionId || !Array.isArray(ids) || ids.length > PREVIEW_MAX_IDS
        || ids.some((id) => typeof id !== 'string' || !/^[A-Za-z0-9_-]{1,512}$/.test(id))) {
        return false;
      }
      prune();
      previews.delete(sessionId);
      while (previews.size >= maxEntries) previews.delete(previews.keys().next().value);
      previews.set(sessionId, { ids: new Set(ids), expiresAt: now() + ttlMs });
      return true;
    },
    has(sessionId, messageId) {
      prune();
      return typeof sessionId === 'string' && Boolean(previews.get(sessionId)?.ids.has(messageId));
    },
    clear(sessionId) {
      if (typeof sessionId === 'string') previews.delete(sessionId);
    },
    clearAll() {
      previews.clear();
    },
  };
}
