import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GOOGLE_OAUTH_REDIRECT_URI } from './googleOAuth.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const localEnvPath = path.join(projectRoot, '.env');
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1']);

/** Read the intentionally small KEY=value format used by the local .env file. */
export function parseEnvFile(contents) {
  const values = {};
  for (const [index, rawLine] of contents.replace(/^\uFEFF/, '').split(/\r?\n/).entries()) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const match = /^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!match) throw new Error(`Invalid .env syntax on line ${index + 1}.`);
    const [, name] = match;
    if (Object.hasOwn(values, name)) throw new Error(`Duplicate .env setting on line ${index + 1}: ${name}.`);
    let value = match[2].trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    } else {
      value = value.replace(/\s+#.*$/, '').trim();
    }
    values[name] = value;
  }
  return values;
}

/** Load and validate local server settings without logging secret values. */
export function loadConfig({ env = process.env, envFilePath = localEnvPath, requireAuth = false } = {}) {
  const fileValues = readEnvFile(envFilePath);
  const values = { ...fileValues, ...env };
  const host = values.HOST || '127.0.0.1';
  if (!LOOPBACK_HOSTS.has(host)) {
    throw new Error('HOST must be a loopback address (127.0.0.1, localhost, or ::1).');
  }

  const portText = values.PORT || '4000';
  if (!/^\d+$/.test(String(portText))) throw new Error('PORT must be an integer from 1 to 65535.');
  const port = Number(portText);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be an integer from 1 to 65535.');
  }

  const sessionSecret = parseOptionalKey('SESSION_SECRET', values.SESSION_SECRET);
  const tokenEncryptionKey = parseOptionalKey('TOKEN_ENCRYPTION_KEY', values.TOKEN_ENCRYPTION_KEY);
  const messageEncryptionKey = parseOptionalKey('MESSAGE_ENCRYPTION_KEY', values.MESSAGE_ENCRYPTION_KEY);
  const googleOAuthClientId = optionalString(values.GOOGLE_OAUTH_CLIENT_ID);
  const googleOAuthClientSecret = optionalString(values.GOOGLE_OAUTH_CLIENT_SECRET);
  const authPasswordHash = values.AUTH_PASSWORD_HASH || null;
  if (authPasswordHash && !isPasswordHashFormat(authPasswordHash)) {
    throw new Error('AUTH_PASSWORD_HASH must be a valid scrypt password hash created by npm run setup-auth.');
  }
  if (requireAuth && (!sessionSecret || !tokenEncryptionKey || !messageEncryptionKey || !authPasswordHash)) {
    throw new Error('Local authentication or message encryption is not configured. Run npm run setup-auth and npm run setup-message-key from the backend directory.');
  }

  return {
    host,
    port,
    sessionSecret,
    tokenEncryptionKey,
    messageEncryptionKey,
    authPasswordHash,
    googleOAuthClientId,
    googleOAuthClientSecret,
    googleOAuthRedirectUri: GOOGLE_OAUTH_REDIRECT_URI,
    googleOAuthEnabled: Boolean(googleOAuthClientId && googleOAuthClientSecret && tokenEncryptionKey),
    googleOAuthError: !tokenEncryptionKey
      ? 'Gmail connection is unavailable until TOKEN_ENCRYPTION_KEY is configured for encrypted local token storage.'
      : googleOAuthClientId && googleOAuthClientSecret
        ? null
        : 'Gmail connection is not configured. Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in the project .env file after configuring Google Cloud.',
  };
}

function optionalString(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim();
  return normalized || null;
}

function isPasswordHashFormat(value) {
  const parts = value.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [cost, blockSize, parallelization] = parts.slice(1, 4).map(Number);
  if (cost !== 32768 || blockSize !== 8 || parallelization !== 1) return false;
  if (!/^[A-Za-z0-9_-]{22}$/.test(parts[4]) || !/^[A-Za-z0-9_-]{86}$/.test(parts[5])) return false;
  return Buffer.from(parts[4], 'base64url').toString('base64url') === parts[4]
    && Buffer.from(parts[5], 'base64url').toString('base64url') === parts[5];
}

function readEnvFile(filePath) {
  try {
    return parseEnvFile(readFileSync(filePath, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return {};
    throw error;
  }
}

function parseOptionalKey(name, value) {
  if (value === undefined || value === '') return null;
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4}){10}[A-Za-z0-9+/]{3}=+$/.test(value)) {
    throw new Error(`${name} must be a base64-encoded 32-byte value.`);
  }
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32 || key.toString('base64') !== value) {
    throw new Error(`${name} must be a base64-encoded 32-byte value.`);
  }
  return key;
}
