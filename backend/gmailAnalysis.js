import { analyzeMessage } from './scamAnalysis.js';
import { GMAIL_READONLY_SCOPE } from './googleOAuth.js';
import { validateGoogleTokenBundle } from './googleTokenStore.js';

export const GMAIL_ANALYSIS_MAX_BODY_BYTES = 64 * 1024;
export const GMAIL_ANALYSIS_MAX_REQUESTS = 3;

const GMAIL_ANALYSIS_HEADERS = Object.freeze(['From', 'Subject', 'Date', 'Content-Disposition']);
const PREVIEW_HEADER_FIELDS = 'id,payload/headers(name,value)';
const MIME_DISCOVERY_FIELDS = 'id,payload(mimeType,filename,body(attachmentId,size),parts(mimeType,filename,headers(name,value),body(attachmentId,size),parts(mimeType)))';
// Gmail's fields sub-selection returns these body fields for every direct part.
// The parser validates the alternative pair and only passes its text/plain bytes
// to the analyzer; it never parses or returns the HTML alternative.
const PLAIN_TEXT_BODY_FIELDS = 'id,payload(mimeType,filename,body(data,size,attachmentId),parts(mimeType,filename,headers(name,value),body(data,size,attachmentId),parts(mimeType)))';

export function createGmailAnalysisRateLimiter({ windowMs = 60_000, maxRequests = GMAIL_ANALYSIS_MAX_REQUESTS, now = Date.now } = {}) {
  if (![windowMs, maxRequests].every(Number.isSafeInteger) || windowMs < 1 || maxRequests < 1) {
    throw new TypeError('Gmail analysis rate-limit settings must be positive integers.');
  }
  const clients = new Map();
  return {
    take(clientKey) {
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
    },
  };
}

/** Handler must be mounted behind the existing authenticated-session and CSRF middleware. */
export function createGmailAnalysisHandler({ tokenStore, oauthClientFactory, gmailApiFactory, rateLimiter, oauthConfig, previewRegistry }) {
  return async (request, response) => {
    const rate = rateLimiter.take(request.socket.remoteAddress || 'unknown-local-client');
    if (!rate.allowed) {
      response.set('Retry-After', String(rate.retryAfterSeconds));
      return response.status(429).json({ error: 'Gmail analysis is temporarily rate limited. Wait briefly and try again.' });
    }

    let phase = 'storage';
    let tokenPersistenceFailed = false;
    let tokenWriteQueue = Promise.resolve();
    try {
      const messageId = request.body?.messageId;
      if (typeof messageId !== 'string' || !/^[A-Za-z0-9_-]{1,512}$/.test(messageId)) {
        return response.status(400).json({ error: 'Choose a message from the current Gmail metadata preview.' });
      }

      const storedBundle = await tokenStore.read();
      if (!storedBundle) return response.status(409).json({ error: 'Connect Gmail before analyzing a message.', reconnectRequired: true });
      if (!Array.isArray(storedBundle.scopes) || storedBundle.scopes.length !== 1 || storedBundle.scopes[0] !== GMAIL_READONLY_SCOPE) {
        return response.status(403).json({ error: 'The saved Gmail authorization does not have the exact read-only scope required.', reconnectRequired: true });
      }
      const bundle = validateGoogleTokenBundle(storedBundle);
      if (!previewRegistry?.has(request.trustVaultSession?.id, messageId)) {
        return response.status(404).json({ error: 'That message is no longer in the recent Gmail preview. Refresh the preview and try again.' });
      }
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
        }).catch(() => { tokenPersistenceFailed = true; });
      });

      const gmail = gmailApiFactory(oauthClient);
      const metadataResponse = await gmail.users.messages.get({
        userId: 'me', id: messageId, format: 'metadata', metadataHeaders: [...GMAIL_ANALYSIS_HEADERS], fields: PREVIEW_HEADER_FIELDS,
      });
      const metadata = readSelectedMetadata(metadataResponse?.data, messageId);
      if (metadata.attachmentDisposition) {
        throw new UnsafeGmailContentError('Attachment-bearing messages are not analyzed.');
      }

      // First inspect only the MIME structure. The partial-response mask excludes
      // snippet, body data, raw content, and attachment payloads.
      const discoveryResponse = await gmail.users.messages.get({
        userId: 'me', id: messageId, format: 'full', fields: MIME_DISCOVERY_FIELDS,
      });
      readPlainTextGate(discoveryResponse?.data, messageId, false);

      // Only a simple text/plain message or a two-part text/plain + text/html
      // multipart/alternative without attachment signals reaches this body request.
      const contentResponse = await gmail.users.messages.get({
        userId: 'me', id: messageId, format: 'full', fields: PLAIN_TEXT_BODY_FIELDS,
      });
      const content = readPlainTextGate(contentResponse?.data, messageId, true);
      const analysis = analyzeMessage({ sender: metadata.sender, subject: metadata.subject, body: content.body });

      await tokenWriteQueue;
      if (tokenPersistenceFailed) {
        return response.status(503).json({ error: 'Gmail authorization was refreshed but could not be safely saved locally. No analysis was returned.' });
      }
      return response.json({
        message: { id: messageId, sender: metadata.sender, subject: metadata.subject, date: metadata.date },
        analysis: {
          score: analysis.score,
          riskLevel: analysis.riskLevel,
          indicators: analysis.indicators.map(({ code, title, detail }) => ({ code, title, detail })),
          explanation: analysis.indicators.length
            ? analysis.indicators.map((indicator) => indicator.detail).join(' ')
            : 'No configured warning signals were detected in the selected plain-text message content. This limited heuristic check cannot establish that the message is safe.',
          uncertainty: 'This is a local heuristic assessment, not a probability and not proof that the email is or is not fraudulent.',
          recommendedActions: analysis.recommendedActions,
        },
        notice: 'Only the selected message’s supported plain-text content was analyzed locally. Nothing was saved to the vault.',
      });
    } catch (error) {
      await tokenWriteQueue;
      if (tokenPersistenceFailed) {
        return response.status(503).json({ error: 'Gmail authorization was refreshed but could not be safely saved locally. No analysis was returned.' });
      }
      if (phase === 'storage') return response.status(503).json({ error: 'The encrypted Gmail authorization could not be verified. Reconnect Gmail before trying again.' });
      if (error instanceof UnsafeGmailContentError) return response.status(422).json({ error: error.message });
      const status = error?.response?.status ?? error?.code;
      if (Number(status) === 401 || Number(status) === 403) {
        return response.status(401).json({ error: 'Gmail authorization expired, was revoked, or was not accepted. Reconnect Gmail and try again.', reconnectRequired: true });
      }
      return response.status(502).json({ error: 'TrustVault could not safely analyze this Gmail message. Try refreshing the preview or choose a supported plain-text message.' });
    }
  };
}

class UnsafeGmailContentError extends Error {}

function readPlainTextGate(message, expectedId, requireBody) {
  const reject = (reason) => { throw new UnsafeGmailContentError(reason); };
  if (!message || typeof message !== 'object' || message.id !== expectedId || !message.payload || typeof message.payload !== 'object') {
    reject('Gmail returned a malformed message. No content was analyzed.');
  }
  const payload = message.payload;
  assertNoFilename(payload, reject);
  if (payload.headers !== undefined) reject('Gmail returned unexpected message headers during content retrieval. No content was analyzed.');

  const mimeType = typeof payload.mimeType === 'string' ? payload.mimeType.toLowerCase() : '';
  let plainPart = payload;
  let htmlPart = null;
  if (mimeType === 'text/plain') {
    if (payload.parts !== undefined && (!Array.isArray(payload.parts) || payload.parts.length > 0)) {
      reject('This plain-text message contains unsupported nested MIME parts. No content was analyzed.');
    }
  } else if (mimeType === 'multipart/alternative') {
    if (!Array.isArray(payload.parts) || payload.parts.length !== 2) {
      reject('Only a plain-text and HTML alternative without attachments is supported. No content was analyzed.');
    }
    const plainParts = payload.parts.filter((part) => part && typeof part.mimeType === 'string'
      && part.mimeType.toLowerCase() === 'text/plain');
    const htmlParts = payload.parts.filter((part) => part && typeof part.mimeType === 'string'
      && part.mimeType.toLowerCase() === 'text/html');
    if (plainParts.length !== 1 || htmlParts.length !== 1) {
      reject('Only a plain-text and HTML alternative without attachments is supported. No content was analyzed.');
    }
    plainPart = plainParts[0];
    htmlPart = htmlParts[0];
    for (const part of payload.parts) assertSafeAlternativePart(part, reject, requireBody);
    assertContainerBody(payload.body, reject, requireBody);
  } else {
    reject('This message is not a supported plain-text or plain-text-plus-HTML alternative. No content was analyzed.');
  }

  const body = plainPart.body;
  assertBodyMetadata(body, reject);
  if (htmlPart) {
    assertBodyMetadata(htmlPart.body, reject);
    if (body.size + htmlPart.body.size > GMAIL_ANALYSIS_MAX_BODY_BYTES) {
      reject('The combined plain-text and HTML alternatives exceed TrustVault’s 64 KB retrieval limit.');
    }
  }
  if (!requireBody) {
    if (body.data !== undefined || (htmlPart && htmlPart.body.data !== undefined)) {
      reject('Gmail returned body data during the MIME safety check. No content was analyzed.');
    }
    if (body.size > GMAIL_ANALYSIS_MAX_BODY_BYTES) {
      reject('This message exceeds TrustVault’s 64 KB plain-text analysis limit.');
    }
    return {};
  }
  const bytes = decodeBody(body, reject);
  if (htmlPart) {
    // Validate the HTML alternative's encoded size without interpreting its content.
    if (htmlPart.body.size > 0) decodeBody(htmlPart.body, reject);
    else if (htmlPart.body.data !== undefined && htmlPart.body.data !== '') {
      reject('Gmail returned malformed HTML alternative data. No content was analyzed.');
    }
  }
  let decoded;
  try { decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
  catch { reject('This message is not valid UTF-8 plain text. No content was analyzed.'); }
  if (!decoded.trim()) reject('This message has no readable plain-text body to analyze.');
  if (/<\s*(?:!doctype\s+html|html|head|body|script|style|iframe|form)\b/i.test(decoded)) {
    reject('HTML-like content is not analyzed by this plain-text feature. No content was analyzed.');
  }
  return { body: decoded };
}

function assertNoFilename(part, reject) {
  if (part.filename !== undefined && typeof part.filename !== 'string') {
    reject('Gmail returned malformed MIME attachment metadata. No content was analyzed.');
  }
  if (typeof part.filename === 'string' && part.filename.trim()) {
    reject('Attachment-bearing messages are not analyzed.');
  }
}

function assertSafeAlternativePart(part, reject, requireBody) {
  if (!part || typeof part !== 'object') reject('Gmail returned malformed MIME structure. No content was analyzed.');
  assertNoFilename(part, reject);
  if (part.parts !== undefined && (!Array.isArray(part.parts) || part.parts.length > 0)) {
    reject('Nested MIME parts and attachments are not analyzed.');
  }
  if (!Array.isArray(part.headers)) reject('Gmail did not return the MIME headers needed to exclude attachments.');
  for (const header of part.headers) {
    if (!header || typeof header.name !== 'string' || typeof header.value !== 'string'
      || /[\r\n]/.test(header.name) || /[\r\n]/.test(header.value)) {
      reject('Gmail returned malformed MIME headers. No content was analyzed.');
    }
    if (header.name.toLowerCase() === 'content-disposition' && /\battachment\b/i.test(header.value)) {
      reject('Attachment-bearing messages are not analyzed.');
    }
  }
  assertBodyMetadata(part.body, reject);
  if (requireBody ? part.body.data === undefined && part.body.size > 0 : part.body.data !== undefined) {
    reject('Gmail returned incomplete MIME body data. No content was analyzed.');
  }
}

function assertBodyMetadata(body, reject) {
  if (!body || typeof body !== 'object' || body.attachmentId !== undefined
    || !Number.isSafeInteger(body.size) || body.size < 0 || body.size > GMAIL_ANALYSIS_MAX_BODY_BYTES) {
    reject('This message body cannot be safely isolated or exceeds the 64 KB limit. No content was analyzed.');
  }
}

function assertContainerBody(body, reject, requireBody) {
  if (body === undefined) return;
  if (!body || typeof body !== 'object' || body.attachmentId !== undefined
    || (body.size !== undefined && body.size !== 0)
    || (body.data !== undefined && (body.data !== '' || body.size !== 0))) {
    reject(requireBody
      ? 'The multipart container returned unexpected body data. No content was analyzed.'
      : 'The multipart container cannot be safely isolated. No content was analyzed.');
  }
}

function decodeBody(body, reject) {
  const encoded = body.data;
  if (typeof encoded !== 'string' || !encoded
    || encoded.length > Math.ceil(GMAIL_ANALYSIS_MAX_BODY_BYTES * 4 / 3) + 8
    || !/^[A-Za-z0-9_-]+={0,2}$/.test(encoded)) {
    reject('Gmail returned empty or malformed MIME body data. No content was analyzed.');
  }
  let bytes;
  try { bytes = Buffer.from(encoded, 'base64url'); }
  catch { reject('Gmail returned malformed MIME body data. No content was analyzed.'); }
  if (body.size !== bytes.length || bytes.length > GMAIL_ANALYSIS_MAX_BODY_BYTES
    || bytes.toString('base64url') !== encoded.replace(/=+$/, '')) {
    reject('This message exceeds the safe plain-text limit or has malformed encoding. No content was analyzed.');
  }
  return bytes;
}

function readSelectedMetadata(message, expectedId) {
  if (!message || typeof message !== 'object' || message.id !== expectedId
    || !message.payload || !Array.isArray(message.payload.headers)) {
    throw new UnsafeGmailContentError('Gmail returned malformed selected-message metadata. No content was analyzed.');
  }
  const headerValue = (name, fallback) => {
    const header = message.payload.headers.find((item) => item && typeof item.name === 'string'
      && item.name.toLowerCase() === name.toLowerCase());
    if (!header) return fallback;
    if (typeof header.value !== 'string' || header.value.length > 4096 || /[\r\n]/.test(header.value)) {
      throw new UnsafeGmailContentError('Gmail returned malformed selected-message metadata. No content was analyzed.');
    }
    return header.value;
  };
  return {
    sender: headerValue('From', 'Unknown sender'),
    subject: headerValue('Subject', '(no subject)'),
    date: headerValue('Date', 'Date unavailable'),
    attachmentDisposition: /\battachment\b/i.test(headerValue('Content-Disposition', '')),
  };
}

function mergeTokenUpdate(previous, updates) {
  if (!updates || typeof updates !== 'object' || Array.isArray(updates)) throw new Error('Invalid token refresh update.');
  const expiryDate = Number.isFinite(updates.expiry_date) ? updates.expiry_date
    : Number.isFinite(updates.expires_in) && updates.expires_in > 0 ? Date.now() + updates.expires_in * 1000 : previous.expiryDate;
  if (typeof updates.access_token === 'string' && updates.access_token.trim() && updates.access_token !== previous.accessToken
    && !Number.isFinite(updates.expiry_date) && !(Number.isFinite(updates.expires_in) && updates.expires_in > 0)) {
    throw new Error('Refreshed access token did not include expiry.');
  }
  const scopes = typeof updates.scope === 'string' ? updates.scope.trim().split(/\s+/) : previous.scopes;
  if (scopes.length !== 1 || scopes[0] !== GMAIL_READONLY_SCOPE) throw new Error('Unexpected refreshed scopes.');
  return validateGoogleTokenBundle({
    version: 1,
    accessToken: typeof updates.access_token === 'string' && updates.access_token.trim() ? updates.access_token : previous.accessToken,
    refreshToken: typeof updates.refresh_token === 'string' && updates.refresh_token.trim() ? updates.refresh_token : previous.refreshToken,
    expiryDate,
    scopes,
  });
}
