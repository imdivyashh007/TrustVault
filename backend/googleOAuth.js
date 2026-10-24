import { randomBytes, timingSafeEqual } from 'node:crypto';
import { google } from 'googleapis';

export const GMAIL_READONLY_SCOPE = 'https://www.googleapis.com/auth/gmail.readonly';
export const GOOGLE_OAUTH_REDIRECT_URI = 'http://localhost:4000/api/auth/google/callback';
export const TRUSTVAULT_FRONTEND_ORIGIN = 'http://localhost:5173';
export const GOOGLE_FLOW_COOKIE = 'tv_google_flow';
export const GOOGLE_FLOW_TTL_MS = 10 * 60 * 1000;

export function createGoogleOAuthClient({ clientId, clientSecret, redirectUri = GOOGLE_OAUTH_REDIRECT_URI }) {
  return new google.auth.OAuth2(clientId, clientSecret, redirectUri);
}

/** Create the official Gmail API client without issuing any request by itself. */
export function createGmailApiClient(oauthClient) {
  return google.gmail({ version: 'v1', auth: oauthClient });
}

/** In-memory, one-use state values bound to an authenticated local session. */
export function createGoogleOAuthFlow({ now = Date.now, ttlMs = GOOGLE_FLOW_TTL_MS, maxPending = 500 } = {}) {
  const pending = new Map();

  function prune() {
    const timestamp = now();
    for (const [state, flow] of pending) {
      if (flow.expiresAt <= timestamp) pending.delete(state);
    }
  }

  function begin(sessionId) {
    if (typeof sessionId !== 'string' || !sessionId) throw new TypeError('An authenticated session is required.');
    prune();
    for (const [state, flow] of pending) {
      if (flow.sessionId === sessionId) pending.delete(state);
    }
    if (pending.size >= maxPending) throw new Error('Too many pending Gmail authorization attempts.');
    const state = randomBytes(32).toString('base64url');
    const flowCookie = randomBytes(32).toString('base64url');
    pending.set(state, { sessionId, flowCookie, expiresAt: now() + ttlMs });
    return { state, flowCookie };
  }

  function consume(state, flowCookie) {
    if (typeof state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(state)) return null;
    const flow = pending.get(state);
    if (!flow) return null;
    if (flow.expiresAt <= now()) {
      pending.delete(state);
      return null;
    }
    if (!constantTimeMatches(flow.flowCookie, flowCookie)) return null;
    pending.delete(state);
    return { sessionId: flow.sessionId };
  }

  function cancel(state) {
    return pending.delete(state);
  }

  return { begin, consume, cancel, get pendingCount() { prune(); return pending.size; } };
}

function constantTimeMatches(expected, supplied) {
  if (typeof supplied !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(supplied)) return false;
  const expectedBytes = Buffer.from(expected, 'base64url');
  const suppliedBytes = Buffer.from(supplied, 'base64url');
  return expectedBytes.length === suppliedBytes.length && timingSafeEqual(expectedBytes, suppliedBytes);
}
