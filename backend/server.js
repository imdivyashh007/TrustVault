import express from 'express';
import cors from 'cors';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { MAX_CSV_BYTES, parseAndValidateCsv } from './csvImport.js';
import { analyzeMessages, withMessageAnalysis } from './scamAnalysis.js';
import { generateIncidentReport } from './incidentReport.js';
import { loadConfig } from './config.js';
import { verifyPassword } from './passwordAuth.js';
import { createSessionStore } from './sessionStore.js';
import { createEncryptedMessageStore } from './encryptedMessageStore.js';
import { createLoginRateLimiter } from './loginRateLimiter.js';
import { createGoogleTokenBundle, createGoogleTokenStore } from './googleTokenStore.js';
import { createGmailSyncHandler, createGmailSyncRateLimiter } from './gmailSync.js';
import { createGmailAnalysisHandler, createGmailAnalysisRateLimiter } from './gmailAnalysis.js';
import { createGmailPreviewRegistry } from './gmailPreviewRegistry.js';
import {
  createGmailApiClient,
  createGoogleOAuthClient,
  createGoogleOAuthFlow,
  GOOGLE_FLOW_COOKIE,
  GOOGLE_FLOW_TTL_MS,
  GMAIL_READONLY_SCOPE,
  TRUSTVAULT_FRONTEND_ORIGIN,
} from './googleOAuth.js';

export function createApp(store = defaultStore, config = {}) {
  if (!Buffer.isBuffer(config.sessionSecret) || config.sessionSecret.length !== 32
    || !Buffer.isBuffer(config.messageEncryptionKey) || config.messageEncryptionKey.length !== 32
    || typeof config.authPasswordHash !== 'string') {
    throw new Error('createApp requires validated local authentication settings.');
  }
  const app = express();
  const allowedOrigins = new Set(['http://localhost:5173', 'http://127.0.0.1:5173']);
  const sessions = createSessionStore({ sessionSecret: config.sessionSecret, ttlMs: config.sessionTtlMs });
  const loginRateLimiter = config.loginRateLimiter || createLoginRateLimiter(config.loginRateLimitOptions);
  const googleOAuthFlow = createGoogleOAuthFlow({ ttlMs: config.googleOAuthFlowTtlMs || GOOGLE_FLOW_TTL_MS });
  const googleOAuthClientFactory = config.googleOAuthClientFactory || createGoogleOAuthClient;
  const gmailApiFactory = config.gmailApiFactory || createGmailApiClient;
  const gmailSyncRateLimiter = config.gmailSyncRateLimiter || createGmailSyncRateLimiter(config.gmailSyncRateLimitOptions);
  const gmailAnalysisRateLimiter = config.gmailAnalysisRateLimiter || createGmailAnalysisRateLimiter(config.gmailAnalysisRateLimitOptions);
  const gmailPreviewRegistry = config.gmailPreviewRegistry || createGmailPreviewRegistry(config.gmailPreviewRegistryOptions);
  const googleTokenStore = config.googleTokenStore || createGoogleTokenStore({
    filePath: config.googleTokenFilePath,
    encryptionKey: config.tokenEncryptionKey,
  });
  const googleOAuth = {
    clientId: config.googleOAuthClientId,
    clientSecret: config.googleOAuthClientSecret,
    redirectUri: config.googleOAuthRedirectUri,
    enabled: Boolean(config.googleOAuthEnabled && config.googleOAuthClientId && config.googleOAuthClientSecret
      && Buffer.isBuffer(config.tokenEncryptionKey) && config.tokenEncryptionKey.length === 32),
    error: config.googleOAuthError || (Buffer.isBuffer(config.tokenEncryptionKey) && config.tokenEncryptionKey.length === 32
      ? 'Gmail connection is not configured. Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in the project .env file after configuring Google Cloud.'
      : 'Gmail connection is unavailable until TOKEN_ENCRYPTION_KEY is configured for encrypted local token storage.'),
  };
  app.use(cors({
    credentials: true,
    origin(origin, callback) {
      callback(null, !origin || allowedOrigins.has(origin));
    },
  }));
  // A 1 MB CSV is represented inside JSON on the local API, so allow a little encoding overhead.
  app.use(express.json({ limit: '1.5mb' }));
  app.use('/api', (_request, response, next) => {
    response.set('Cache-Control', 'no-store');
    next();
  });

  app.get('/api/health', (_request, response) => {
    response.json({ status: 'ok', app: 'TrustVault API' });
  });

  app.get('/api/auth/session', (request, response) => {
    const current = sessions.get(readCookie(request, 'tv_session'));
    const session = current || sessions.create(false);
    if (!current) setSessionCookie(response, session, request);
    response.set?.('Cache-Control', 'no-store');
    response.json({ authenticated: session.authenticated, csrfToken: session.csrfToken });
  });

  app.post('/api/auth/login', requireCsrf(sessions, allowedOrigins, false), async (request, response) => {
    const clientKey = request.socket.remoteAddress || 'unknown-local-client';
    const rate = loginRateLimiter.begin(clientKey);
    if (!rate.allowed) {
      response.set('Retry-After', String(rate.retryAfterSeconds));
      return response.status(429).json({ error: 'Too many failed sign-in attempts. Wait before trying again.' });
    }
    const password = request.body?.password;
    let valid;
    try {
      valid = await verifyPassword(password, config.authPasswordHash);
    } catch (error) {
      loginRateLimiter.finish(clientKey, false);
      throw error;
    }
    if (!valid) {
      const updatedRate = loginRateLimiter.finish(clientKey, false);
      if (!updatedRate.allowed) response.set('Retry-After', String(updatedRate.retryAfterSeconds));
      return response.status(401).json({ error: 'The password was not accepted.' });
    }
    loginRateLimiter.finish(clientKey, true);

    sessions.destroy(request.trustVaultSession.id);
    const session = sessions.create(true);
    setSessionCookie(response, session, request);
    response.set('Cache-Control', 'no-store');
    return response.json({ authenticated: true, csrfToken: session.csrfToken });
  });

  app.post('/api/auth/logout', requireCsrf(sessions, allowedOrigins, true), (request, response) => {
    gmailPreviewRegistry.clear(request.trustVaultSession.id);
    sessions.destroy(request.trustVaultSession.id);
    const session = sessions.create(false);
    setSessionCookie(response, session, request);
    response.set('Cache-Control', 'no-store');
    response.json({ authenticated: false, csrfToken: session.csrfToken });
  });

  // Google returns to this route through a cross-site top-level GET. Its short-lived
  // SameSite=Lax flow cookie is tied to a still-live authenticated session in memory.
  app.get('/api/auth/google/callback', async (request, response) => {
    response.set('Cache-Control', 'no-store');
    response.set('Referrer-Policy', 'no-referrer');
    const redirect = (result) => {
      clearGoogleFlowCookie(response, request);
      return response.redirect(303, `${TRUSTVAULT_FRONTEND_ORIGIN}/?gmail=${result}`);
    };

    const pending = googleOAuthFlow.consume(request.query.state, readCookie(request, GOOGLE_FLOW_COOKIE));
    if (!pending || !sessions.get(pending.sessionId)?.authenticated) return redirect('failed');
    if (request.query.error) return redirect(request.query.error === 'access_denied' ? 'cancelled' : 'failed');
    if (typeof request.query.code !== 'string' || request.query.code.length > 4096) return redirect('failed');
    if (!googleOAuth.enabled) return redirect('not-configured');

    let tokenBundle;
    try {
      const oauthClient = googleOAuthClientFactory(googleOAuth);
      const tokenResponse = await oauthClient.getToken(request.query.code);
      tokenBundle = createGoogleTokenBundle(tokenResponse?.tokens);
    } catch {
      return redirect('failed');
    }

    try {
      await googleTokenStore.write(tokenBundle);
      const savedBundle = await googleTokenStore.read();
      if (!sameGoogleTokenBundle(tokenBundle, savedBundle)) {
        return redirect('save-failed');
      }
      return redirect('authorized');
    } catch {
      return redirect('save-failed');
    }
  });

  app.use('/api', (request, response, next) => {
    const session = sessions.get(readCookie(request, 'tv_session'));
    if (!session?.authenticated) return response.status(401).json({ error: 'Log in to use the local vault.' });
    request.trustVaultSession = session;
    next();
  });
  app.use('/api', requireCsrf(sessions, allowedOrigins, true));

  app.get('/api/auth/google/status', async (_request, response, next) => {
    try {
      const bundle = googleOAuth.enabled ? await googleTokenStore.read() : null;
      response.json({
        enabled: googleOAuth.enabled,
        connected: Boolean(bundle),
        scope: GMAIL_READONLY_SCOPE,
        message: !googleOAuth.enabled
          ? googleOAuth.error
          : bundle
            ? 'Gmail authorization tokens are encrypted in the local app store. No messages have been fetched.'
            : 'Read-only Gmail authorization is ready. No account is connected yet.',
      });
    } catch {
      response.status(503).json({ error: 'The local Gmail token store could not be verified. The connection was not reported as active.' });
    }
  });

  app.delete('/api/auth/google/disconnect', async (request, response) => {
    try {
      const removed = await googleTokenStore.remove();
      gmailPreviewRegistry.clear(request.trustVaultSession.id);
      return response.json({ connected: false, removed, message: removed
        ? 'The encrypted local Gmail token bundle was removed. Google authorization was not revoked.'
        : 'No local Gmail token bundle was present. Google authorization was not revoked.' });
    } catch {
      return response.status(503).json({ error: 'The local Gmail token bundle could not be safely removed.' });
    }
  });

  app.post('/api/auth/google/sync', (request, response) => {
    // The UI discards its previous preview when a refresh starts; expire its IDs too.
    gmailPreviewRegistry.clear(request.trustVaultSession.id);
    if (!googleOAuth.enabled) return response.status(503).json({ error: googleOAuth.error });
    return createGmailSyncHandler({
      tokenStore: googleTokenStore,
      oauthClientFactory: googleOAuthClientFactory,
      gmailApiFactory,
      rateLimiter: gmailSyncRateLimiter,
      oauthConfig: googleOAuth,
      previewRegistry: gmailPreviewRegistry,
    })(request, response);
  });

  app.post('/api/auth/google/analyze', (request, response) => {
    if (!googleOAuth.enabled) return response.status(503).json({ error: googleOAuth.error });
    return createGmailAnalysisHandler({
      tokenStore: googleTokenStore,
      oauthClientFactory: googleOAuthClientFactory,
      gmailApiFactory,
      rateLimiter: gmailAnalysisRateLimiter,
      oauthConfig: googleOAuth,
      previewRegistry: gmailPreviewRegistry,
    })(request, response);
  });

  app.post('/api/auth/google/start', (request, response) => {
    if (!googleOAuth.enabled) return response.status(503).json({ error: googleOAuth.error });
    let flow;
    try {
      flow = googleOAuthFlow.begin(request.trustVaultSession.id);
      const oauthClient = googleOAuthClientFactory(googleOAuth);
      const authorizationUrl = oauthClient.generateAuthUrl({
        access_type: 'online',
        include_granted_scopes: false,
        scope: [GMAIL_READONLY_SCOPE],
        state: flow.state,
      });
      const authUrl = new URL(authorizationUrl);
      if (authUrl.protocol !== 'https:' || authUrl.hostname !== 'accounts.google.com') {
        throw new Error('The Google authorization endpoint was invalid.');
      }
      setGoogleFlowCookie(response, flow.flowCookie, request);
      response.set('Cache-Control', 'no-store');
      return response.json({ authorizationUrl: authUrl.toString() });
    } catch {
      if (flow) googleOAuthFlow.cancel(flow.state);
      return response.status(503).json({ error: 'Could not start Google authorization. Check the local OAuth configuration and try again.' });
    }
  });

  app.get('/api/messages', async (_request, response, next) => {
    response.set('Cache-Control', 'no-store');
    try {
      const messages = await store.read();
      response.json({ messages: analyzeMessages(messages), demo: true, notice: 'Demo records are fictional; imported messages are stored locally.' });
    } catch (error) {
      next(error);
    }
  });

  app.post('/api/messages/import', createImportHandler(store));
  app.post('/api/messages/:id/report', createIncidentReportHandler(store));

  app.use((error, _request, response, _next) => {
    if (error.type === 'entity.parse.failed') {
      return response.status(400).json({ error: 'The request body must contain valid JSON.' });
    }
    if (error.type === 'entity.too.large') {
      return response.status(413).json({ error: 'The upload exceeds the request size limit.' });
    }
    console.error('TrustVault API error:', error);
    return response.status(500).json({ error: 'The local TrustVault API could not complete the request.' });
  });

  return app;
}

export function createIncidentReportHandler(store) {
  return async (request, response, next) => {
    response.set?.('Cache-Control', 'no-store');
    try {
      const messages = await store.read();
      const message = messages.find((record) => record.id === request.params.id);
      if (!message) return response.status(404).json({ error: 'That message could not be found in the local vault.' });
      return response.json({ report: generateIncidentReport(message) });
    } catch (error) {
      next(error);
    }
  };
}

export function createImportHandler(store) {
  return async (request, response, next) => {
    try {
      const { filename, csv } = request.body || {};
      if (typeof filename !== 'string' || !filename.toLowerCase().endsWith('.csv')) {
        return response.status(400).json({ error: 'Choose a CSV file with a .csv extension.' });
      }
      if (typeof csv !== 'string') {
        return response.status(400).json({ error: 'The request must include the CSV file contents.' });
      }
      if (Buffer.byteLength(csv, 'utf8') > MAX_CSV_BYTES) {
        return response.status(413).json({ error: 'The CSV file exceeds the 1 MB size limit.' });
      }

      const currentMessages = await store.read();
      const result = parseAndValidateCsv(csv, currentMessages);
      if (!result.records.length) {
        const statusCode = result.errors.length && result.rejected === 0 && result.duplicates === 0 ? 400 : 200;
        return response.status(statusCode).json({
          imported: 0,
          // Duplicates are valid rows that already exist, not invalid/rejected rows.
          rejected: result.rejected,
          invalidRows: result.rejected,
          duplicates: result.duplicates,
          errors: result.errors,
          message: importSummaryMessage(0, result.rejected, result.duplicates),
        });
      }

      const analyzedRecords = result.records.map(withMessageAnalysis);
      await store.write([...currentMessages, ...analyzedRecords]);
      return response.json({
        imported: analyzedRecords.length,
        rejected: result.rejected,
        invalidRows: result.rejected,
        duplicates: result.duplicates,
        errors: result.errors,
        message: importSummaryMessage(result.records.length, result.rejected, result.duplicates),
      });
    } catch (error) {
      next(error);
    }
  };
}

function importSummaryMessage(imported, rejected, duplicates) {
  const parts = [];
  if (imported) parts.push(`${imported} ${imported === 1 ? 'record was' : 'records were'} saved to the local TrustVault data store`);
  else parts.push('No new records were imported');
  if (duplicates) parts.push(`${duplicates} ${duplicates === 1 ? 'duplicate was' : 'duplicates were'} already in your vault and skipped; duplicates are not counted as rejected`);
  if (rejected) parts.push(`${rejected} invalid ${rejected === 1 ? 'row was' : 'rows were'} rejected`);
  return `${parts.join('. ')}.`;
}

function sameGoogleTokenBundle(expected, saved) {
  return Boolean(saved
    && saved.version === expected.version
    && saved.accessToken === expected.accessToken
    && saved.refreshToken === expected.refreshToken
    && saved.expiryDate === expected.expiryDate
    && Array.isArray(saved.scopes)
    && saved.scopes.length === expected.scopes.length
    && saved.scopes.every((scope, index) => scope === expected.scopes[index]));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const config = loadConfig({ requireAuth: true });
  const encryptedStorePath = fileURLToPath(new URL('./data/messages.encrypted.json', import.meta.url));
  const encryptedStore = createEncryptedMessageStore(encryptedStorePath, config.messageEncryptionKey);
  encryptedStore.read().then(() => {
    createApp(encryptedStore, config).listen(config.port, config.host, () => {
      console.log(`TrustVault API listening at http://${config.host}:${config.port}`);
    });
  }).catch((error) => {
    console.error('TrustVault encrypted message store could not be verified. The API was not started.');
    console.error(error.message);
    process.exitCode = 1;
  });
}

function requireCsrf(sessions, allowedOrigins, requireAuthenticated) {
  return (request, response, next) => {
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(request.method)) return next();
    const origin = request.get('origin');
    if (!origin || !allowedOrigins.has(origin)) return response.status(403).json({ error: 'This local request did not come from the TrustVault app.' });
    const session = sessions.get(readCookie(request, 'tv_session'));
    if (!session || (requireAuthenticated && !session.authenticated)) {
      return response.status(401).json({ error: 'Your local session has expired. Log in again.' });
    }
    if (!sessions.verifyCsrf(session, request.get('x-csrf-token'))) {
      return response.status(403).json({ error: 'The request security token is missing or expired. Reload the app and try again.' });
    }
    request.trustVaultSession = session;
    next();
  };
}

function readCookie(request, name) {
  const prefix = `${name}=`;
  for (const part of (request.headers.cookie || '').split(';')) {
    const cookie = part.trim();
    if (cookie.startsWith(prefix)) {
      try {
        return decodeURIComponent(cookie.slice(prefix.length));
      } catch {
        return null;
      }
    }
  }
  return null;
}

function setSessionCookie(response, session, request) {
  const attributes = [
    `tv_session=${encodeURIComponent(session.id)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.floor(session.expiresAt / 1000) - Math.floor(Date.now() / 1000)}`,
  ];
  // Local development uses HTTP. Secure is applied automatically if TLS is enabled later.
  if (request.secure) attributes.push('Secure');
  response.set('Set-Cookie', attributes.join('; '));
}

function setGoogleFlowCookie(response, flowCookie, request) {
  const attributes = [
    `${GOOGLE_FLOW_COOKIE}=${encodeURIComponent(flowCookie)}`,
    'Path=/api/auth/google/callback',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(GOOGLE_FLOW_TTL_MS / 1000)}`,
  ];
  if (request.secure) attributes.push('Secure');
  response.append('Set-Cookie', attributes.join('; '));
}

function clearGoogleFlowCookie(response, request) {
  const attributes = [
    `${GOOGLE_FLOW_COOKIE}=`,
    'Path=/api/auth/google/callback',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (request.secure) attributes.push('Secure');
  response.append('Set-Cookie', attributes.join('; '));
}
