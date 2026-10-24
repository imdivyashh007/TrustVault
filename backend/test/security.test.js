import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { loadConfig, parseEnvFile } from '../config.js';
import { decryptToken, encryptToken } from '../tokenEncryption.js';
import { createCsrfToken, createSessionId, verifyCsrfToken } from '../sessionSecurity.js';
import { hashPassword, verifyPassword } from '../passwordAuth.js';
import { createSessionStore } from '../sessionStore.js';
import { readEncryptedToken, writeEncryptedToken } from '../encryptedTokenStore.js';
import { createLoginRateLimiter } from '../loginRateLimiter.js';

const secret = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8');
const encodedSecret = secret.toString('base64');

test('local env parsing supports simple values, comments, quoted values, and rejects duplicate keys', () => {
  assert.deepEqual(parseEnvFile('\uFEFF# local\nHOST=127.0.0.1\nPORT=4001 # API port\nLABEL="student app"\n'), {
    HOST: '127.0.0.1',
    PORT: '4001',
    LABEL: 'student app',
  });
  assert.throws(() => parseEnvFile('PORT=4000\nPORT=5000'), /Duplicate .env setting.*PORT/);
  assert.throws(() => parseEnvFile('not a setting'), /Invalid .env syntax/);
});

test('configuration reads the private .env format, favors process values, and accepts only loopback hosts', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-config-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const envFilePath = path.join(directory, '.env');
  await writeFile(envFilePath, `HOST=127.0.0.1\nPORT=4001\nSESSION_SECRET=${encodedSecret}\nTOKEN_ENCRYPTION_KEY=${encodedSecret}\nMESSAGE_ENCRYPTION_KEY=${encodedSecret}\n`);

  const config = loadConfig({ env: { PORT: '4002' }, envFilePath });
  assert.equal(config.host, '127.0.0.1');
  assert.equal(config.port, 4002);
  assert.deepEqual(config.sessionSecret, secret);
  assert.deepEqual(config.tokenEncryptionKey, secret);
  assert.deepEqual(config.messageEncryptionKey, secret);
  assert.equal(config.googleOAuthEnabled, false);
  assert.equal(loadConfig({ env: {}, envFilePath: path.join(directory, 'missing') }).host, '127.0.0.1');
  const exampleConfig = loadConfig({ env: {}, envFilePath: fileURLToPath(new URL('../../.env.example', import.meta.url)) });
  assert.equal(exampleConfig.host, '127.0.0.1');
  assert.equal(exampleConfig.port, 4000);
  assert.equal(exampleConfig.sessionSecret, null);
  assert.equal(exampleConfig.tokenEncryptionKey, null);
  assert.equal(exampleConfig.messageEncryptionKey, null);
  assert.equal(exampleConfig.authPasswordHash, null);
  assert.equal(exampleConfig.googleOAuthEnabled, false);
  assert.equal(exampleConfig.googleOAuthClientId, null);
  assert.equal(exampleConfig.googleOAuthClientSecret, null);

  assert.throws(() => loadConfig({ env: { HOST: '0.0.0.0' }, envFilePath }), /loopback address/);
  assert.throws(() => loadConfig({ env: { PORT: '70000' }, envFilePath }), /PORT must be an integer/);
  assert.throws(() => loadConfig({ env: { SESSION_SECRET: 'actual-secret-is-not-shown' }, envFilePath: path.join(directory, 'missing') }), /SESSION_SECRET must be a base64-encoded 32-byte value/);
  assert.throws(() => loadConfig({ envFilePath, env: {}, requireAuth: true }), /Local authentication or message encryption is not configured/);
  const authHash = `scrypt$32768$8$1$${Buffer.alloc(16, 3).toString('base64url')}$${Buffer.alloc(64, 4).toString('base64url')}`;
  const completeConfig = loadConfig({ envFilePath, env: { AUTH_PASSWORD_HASH: authHash }, requireAuth: true });
  assert.deepEqual(completeConfig.messageEncryptionKey, secret);
  assert.equal(completeConfig.authPasswordHash, authHash);
  assert.equal(completeConfig.googleOAuthEnabled, false);
  const googleConfig = loadConfig({ envFilePath, env: { GOOGLE_OAUTH_CLIENT_ID: 'fictional-client-id', GOOGLE_OAUTH_CLIENT_SECRET: 'fictional-client-secret' } });
  assert.equal(googleConfig.googleOAuthEnabled, true);
  assert.equal(googleConfig.googleOAuthRedirectUri, 'http://localhost:4000/api/auth/google/callback');
  const noTokenKey = loadConfig({ envFilePath, env: { TOKEN_ENCRYPTION_KEY: '', GOOGLE_OAUTH_CLIENT_ID: 'fictional-client-id', GOOGLE_OAUTH_CLIENT_SECRET: 'fictional-client-secret' } });
  assert.equal(noTokenKey.googleOAuthEnabled, false);
  assert.match(noTokenKey.googleOAuthError, /TOKEN_ENCRYPTION_KEY/);
  assert.equal(loadConfig({ envFilePath, env: { GOOGLE_OAUTH_CLIENT_ID: 'fictional-client-id' } }).googleOAuthEnabled, false);
  assert.throws(() => loadConfig({ envFilePath, env: { AUTH_PASSWORD_HASH: 'plaintext' } }), /AUTH_PASSWORD_HASH must be a valid scrypt/);
});

test('AES-256-GCM token encryption round-trips, randomizes nonces, and rejects tampering or wrong keys', () => {
  const token = 'fictional-refresh-token-for-unit-test';
  const first = encryptToken(token, secret);
  const second = encryptToken(token, secret);
  assert.equal(first.version, 1);
  assert.equal(first.algorithm, 'aes-256-gcm');
  assert.notEqual(first.iv, second.iv);
  assert.ok(!JSON.stringify(first).includes(token));
  assert.equal(decryptToken(first, secret), token);
  assert.throws(() => decryptToken(first, Buffer.alloc(32, 1)));
  assert.throws(() => decryptToken({ ...first, tag: Buffer.alloc(16).toString('base64url') }, secret));
  assert.throws(() => encryptToken(token, 'not-a-key'), /32-byte key/);
});

test('session and CSRF primitives are high entropy, session-bound, and fail closed', () => {
  const firstSession = createSessionId();
  const secondSession = createSessionId();
  assert.match(firstSession, /^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(firstSession, secondSession);

  const token = createCsrfToken(firstSession, secret);
  assert.match(token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(verifyCsrfToken(firstSession, token, secret), true);
  assert.equal(verifyCsrfToken(secondSession, token, secret), false);
  assert.equal(verifyCsrfToken(firstSession, token, Buffer.alloc(32, 2)), false);
  assert.equal(verifyCsrfToken(firstSession, 'malformed', secret), false);
  assert.equal(verifyCsrfToken(firstSession, undefined, secret), false);
});

test('password hashes use scrypt and verify only the matching password', async () => {
  const encoded = await hashPassword('local-test-password-123');
  assert.match(encoded, /^scrypt\$32768\$8\$1\$/);
  assert.equal(encoded.includes('local-test-password-123'), false);
  assert.equal(await verifyPassword('local-test-password-123', encoded), true);
  assert.equal(await verifyPassword('different-password', encoded), false);
  assert.equal(await verifyPassword('x', 'malformed'), false);
  await assert.rejects(hashPassword('short'), /12 and 1024/);
});

test('server-side sessions expire and revoke correctly', () => {
  let now = 1000;
  const sessions = createSessionStore({ sessionSecret: secret, ttlMs: 500, now: () => now });
  const session = sessions.create(true);
  assert.equal(sessions.get(session.id).authenticated, true);
  assert.equal(sessions.verifyCsrf(sessions.get(session.id), session.csrfToken), true);
  now += 500;
  assert.equal(sessions.get(session.id), null);
  const second = sessions.create(true);
  assert.equal(sessions.destroy(second.id), true);
  assert.equal(sessions.get(second.id), null);
});

test('login limiter locks after consecutive failures, expires the lock, and clears on success', () => {
  let now = 1000;
  const limiter = createLoginRateLimiter({ windowMs: 1000, maxFailures: 2, lockoutMs: 3000, now: () => now });
  assert.equal(limiter.check('127.0.0.1').allowed, true);
  limiter.recordFailure('127.0.0.1');
  const locked = limiter.recordFailure('127.0.0.1');
  assert.equal(locked.allowed, false);
  assert.equal(locked.retryAfterSeconds, 3);
  now += 3000;
  assert.equal(limiter.check('127.0.0.1').allowed, true);
  limiter.recordFailure('127.0.0.1');
  limiter.recordSuccess('127.0.0.1');
  assert.equal(limiter.check('127.0.0.1').allowed, true);
  assert.equal(limiter.begin('parallel-client').allowed, true);
  assert.equal(limiter.begin('parallel-client').allowed, true);
  assert.equal(limiter.begin('parallel-client').allowed, false);
  limiter.finish('parallel-client', false);
  limiter.finish('parallel-client', true);
});

test('encrypted token file stores no plaintext, uses owner-only mode, and detects tampering', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-token-store-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'tokens.enc');
  const token = 'fictional-refresh-token-used-only-by-this-test';
  await writeEncryptedToken(filePath, token, secret);
  const contents = await readFile(filePath, 'utf8');
  assert.equal(contents.includes(token), false);
  assert.equal((await stat(filePath)).mode & 0o777, 0o600);
  assert.equal(await readEncryptedToken(filePath, secret), token);
  await assert.rejects(readEncryptedToken(filePath, Buffer.alloc(32, 9)));
  await writeFile(filePath, `${contents.trim().slice(0, -2)}!}\n`);
  await assert.rejects(readEncryptedToken(filePath, secret));
});
