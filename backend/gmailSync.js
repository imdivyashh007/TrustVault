import { GMAIL_READONLY_SCOPE } from './googleOAuth.js';
import { validateGoogleTokenBundle } from './googleTokenStore.js';

export const GMAIL_SYNC_MAX_RESULTS = 5;
export const GMAIL_SYNC_METADATA_HEADERS = Object.freeze(['From', 'Subject', 'Date']);

/** Simple process-local fixed-window limiter keyed by the socket's client address. */
export function createGmailSyncRateLimiter({ windowMs = 60_000, maxRequests = 5, now = Date.now } = {}) {
  if (![windowMs, maxRequests].every(Number.isSafeInteger) || windowMs < 1 || maxRequests < 1) {
    throw new TypeError('Gmail sync rate-limit settings must be positive integers.');
  }
  const clients = new Map();

  function take(clientKey) {
    const timestamp = now();
    let state = clients.get(clientKey);
    if (!state || timestamp - state.windowStartedAt >= windowMs) {
      state = { windowStartedAt: timestamp, requests: 0 };
      clients.set(clientKey, state);
    }
    if (state.requests >= maxRequests) {
      return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((state.windowStartedAt + windowMs - timestamp) / 1000)) };
    }
    state.requests += 1;
    return { allowed: true, retryAfterSeconds: 0 };
  }

  return { take };
}

/** Express handler for a metadata-only request. Call behind session and CSRF middleware. */
export function createGmailSyncHandler({ tokenStore, oauthClientFactory, gmailApiFactory, rateLimiter, oauthConfig, previewRegistry }) {
  return async (request, response) => {
    const clientKey = request.socket.remoteAddress || 'unknown-local-client';
    const rate = rateLimiter.take(clientKey);
    if (!rate.allowed) {
      response.set('Retry-After', String(rate.retryAfterSeconds));
      return response.status(429).json({ error: 'Gmail preview is temporarily rate limited. Wait briefly and try again.' });
    }

    let phase = 'storage';
    let tokenPersistenceFailed = false;
    let tokenWriteQueue = Promise.resolve();
    try {
      const storedBundle = await tokenStore.read();
      if (!storedBundle) return response.status(409).json({ error: 'Connect Gmail before requesting a metadata preview.', reconnectRequired: true });
      if (!Array.isArray(storedBundle.scopes) || storedBundle.scopes.length !== 1 || storedBundle.scopes[0] !== GMAIL_READONLY_SCOPE) {
        return response.status(403).json({ error: 'The saved Gmail authorization does not have the exact read-only scope required.', reconnectRequired: true });
      }
      const bundle = validateGoogleTokenBundle(storedBundle);
      phase = 'provider';

      const oauthClient = oauthClientFactory(oauthConfig);
      oauthClient.setCredentials({
        access_token: bundle.accessToken,
        refresh_token: bundle.refreshToken || undefined,
        expiry_date: bundle.expiryDate,
        scope: bundle.scopes.join(' '),
      });

      let currentBundle = bundle;
      oauthClient.on('tokens', (updates) => {
        tokenWriteQueue = tokenWriteQueue.then(async () => {
          currentBundle = mergeTokenUpdate(currentBundle, updates);
          await tokenStore.write(currentBundle);
        }).catch(() => {
          tokenPersistenceFailed = true;
        });
      });

      const gmail = gmailApiFactory(oauthClient);
      const listResponse = await gmail.users.messages.list({ userId: 'me', maxResults: GMAIL_SYNC_MAX_RESULTS, fields: 'messages(id)' });
      if (!listResponse?.data || typeof listResponse.data !== 'object' || Array.isArray(listResponse.data)) {
        throw new Error('Gmail returned an invalid message list.');
      }
      const listedMessages = listResponse?.data?.messages;
      if (listedMessages !== undefined && !Array.isArray(listedMessages)) {
        throw new Error('Gmail returned an invalid message list.');
      }
      const ids = (listedMessages || []).slice(0, GMAIL_SYNC_MAX_RESULTS).map((item) => {
        if (!item || typeof item.id !== 'string' || !/^[A-Za-z0-9_-]{1,512}$/.test(item.id)) {
          throw new Error('Gmail returned an invalid message identifier.');
        }
        return item.id;
      });

      const messages = [];
      for (const id of ids) {
        const detailResponse = await gmail.users.messages.get({
          userId: 'me',
          id,
          format: 'metadata',
          metadataHeaders: [...GMAIL_SYNC_METADATA_HEADERS],
          fields: 'id,payload/headers(name,value)',
        });
        messages.push(readMetadataOnly(detailResponse?.data, id));
      }

      await tokenWriteQueue;
      if (tokenPersistenceFailed) {
        return response.status(503).json({ error: 'Gmail authorization was refreshed but could not be safely saved locally. No preview was returned.' });
      }
      if (previewRegistry && !previewRegistry.remember(request.trustVaultSession?.id, messages.map((message) => message.id))) {
        return response.status(503).json({ error: 'TrustVault could not safely bind this Gmail preview to the local session. Refresh and try again.' });
      }
      return response.json({ messages });
    } catch (error) {
      await tokenWriteQueue;
      if (tokenPersistenceFailed) {
        return response.status(503).json({ error: 'Gmail authorization was refreshed but could not be safely saved locally. No preview was returned.' });
      }
      if (phase === 'storage') {
        return response.status(503).json({ error: 'The encrypted Gmail authorization could not be verified. Reconnect Gmail before trying again.' });
      }
      const status = providerStatus(error);
      if (status === 401 || status === 403) {
        return response.status(401).json({ error: 'Gmail authorization expired, was revoked, or was not accepted. Reconnect Gmail and try again.', reconnectRequired: true });
      }
      return response.status(502).json({ error: 'TrustVault could not retrieve a safe Gmail metadata preview. Try again later.' });
    }
  };
}

function mergeTokenUpdate(previous, updates) {
  if (!updates || typeof updates !== 'object' || Array.isArray(updates)) {
    throw new Error('Google returned an invalid token refresh update.');
  }
  const accessTokenUpdated = typeof updates.access_token === 'string' && updates.access_token.trim()
    && updates.access_token !== previous.accessToken;
  const expiryDate = Number.isFinite(updates.expiry_date)
    ? updates.expiry_date
    : Number.isFinite(updates.expires_in) && updates.expires_in > 0
      ? Date.now() + updates.expires_in * 1000
      : previous.expiryDate;
  if (accessTokenUpdated && !Number.isFinite(updates.expiry_date)
    && !(Number.isFinite(updates.expires_in) && updates.expires_in > 0)) {
    throw new Error('Google did not return an expiry for the rotated access token.');
  }
  return validateGoogleTokenBundle({
    version: 1,
    accessToken: typeof updates.access_token === 'string' && updates.access_token.trim()
      ? updates.access_token
      : previous.accessToken,
    refreshToken: typeof updates.refresh_token === 'string' && updates.refresh_token.trim()
      ? updates.refresh_token
      : previous.refreshToken,
    expiryDate,
    scopes: typeof updates.scope === 'string' ? updates.scope.trim().split(/\s+/) : previous.scopes,
  });
}

function readMetadataOnly(message, expectedId) {
  if (!message || typeof message !== 'object' || message.id !== expectedId
    || !message.payload || !Array.isArray(message.payload.headers)) {
    throw new Error('Gmail returned malformed message metadata.');
  }
  const headerValue = (name, fallback) => {
    const header = message.payload.headers.find((item) => item && typeof item.name === 'string'
      && item.name.toLowerCase() === name.toLowerCase());
    if (!header) return fallback;
    if (typeof header.value !== 'string' || header.value.length > 4096 || /[\r\n]/.test(header.value)) {
      throw new Error('Gmail returned malformed message headers.');
    }
    return header.value;
  };
  return {
    id: expectedId,
    sender: headerValue('From', 'Unknown sender'),
    subject: headerValue('Subject', '(no subject)'),
    date: headerValue('Date', 'Date unavailable'),
  };
}

function providerStatus(error) {
  const status = error?.response?.status ?? error?.code;
  return Number.isInteger(Number(status)) ? Number(status) : null;
}
