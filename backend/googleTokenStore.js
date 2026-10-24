import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { GMAIL_READONLY_SCOPE } from './googleOAuth.js';
import { readEncryptedToken, removeEncryptedToken, writeEncryptedToken } from './encryptedTokenStore.js';

const defaultTokenFile = fileURLToPath(new URL('./data/private/gmail-tokens.enc', import.meta.url));

/** Convert the provider response into the small, allow-listed bundle TrustVault needs. */
export function createGoogleTokenBundle(tokens, now = Date.now()) {
  if (!tokens || typeof tokens !== 'object' || Array.isArray(tokens)) {
    throw new TypeError('Google did not return a valid token bundle.');
  }
  const scopes = parseGrantedScopes(tokens.scope);
  if (!Array.isArray(scopes) || scopes.length !== 1 || scopes[0] !== GMAIL_READONLY_SCOPE) {
    throw new Error('Google granted scopes outside the allowed Gmail read-only scope.');
  }
  if (typeof tokens.access_token !== 'string' || !tokens.access_token.trim()) {
    throw new Error('Google did not return an access token.');
  }
  if (tokens.refresh_token !== undefined && tokens.refresh_token !== null
    && (typeof tokens.refresh_token !== 'string' || !tokens.refresh_token.trim())) {
    throw new Error('Google returned an invalid refresh token.');
  }

  const expiryDate = Number.isFinite(tokens.expiry_date)
    ? tokens.expiry_date
    : Number.isFinite(tokens.expires_in) && tokens.expires_in > 0
      ? now + tokens.expires_in * 1000
      : NaN;
  if (!Number.isFinite(expiryDate) || expiryDate <= now) {
    throw new Error('Google did not return a valid token expiry.');
  }

  return validateGoogleTokenBundle({
    version: 1,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token || null,
    expiryDate,
    scopes,
  });
}

export function validateGoogleTokenBundle(bundle) {
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle) || bundle.version !== 1
    || typeof bundle.accessToken !== 'string' || !bundle.accessToken.trim()
    || !(bundle.refreshToken === null || (typeof bundle.refreshToken === 'string' && bundle.refreshToken.trim()))
    || !Number.isFinite(bundle.expiryDate) || bundle.expiryDate <= 0
    || !Array.isArray(bundle.scopes) || bundle.scopes.length !== 1 || bundle.scopes[0] !== GMAIL_READONLY_SCOPE) {
    throw new Error('The encrypted Google token bundle is invalid or has unexpected scopes.');
  }
  return {
    version: 1,
    accessToken: bundle.accessToken,
    refreshToken: bundle.refreshToken,
    expiryDate: bundle.expiryDate,
    scopes: [GMAIL_READONLY_SCOPE],
  };
}

/** Store or retrieve one serialized, allow-listed token bundle using AES-256-GCM. */
export function createGoogleTokenStore({ filePath = defaultTokenFile, encryptionKey } = {}) {
  const tokenPath = path.resolve(filePath);
  return {
    async read() {
      const serialized = await readEncryptedToken(tokenPath, encryptionKey);
      if (serialized === null) return null;
      let bundle;
      try {
        bundle = JSON.parse(serialized);
      } catch {
        throw new Error('The encrypted Google token file contains invalid data.');
      }
      return validateGoogleTokenBundle(bundle);
    },
    async write(bundle) {
      const safeBundle = validateGoogleTokenBundle(bundle);
      await writeEncryptedToken(tokenPath, JSON.stringify(safeBundle), encryptionKey);
    },
    async remove() {
      return removeEncryptedToken(tokenPath);
    },
    filePath: tokenPath,
  };
}

function parseGrantedScopes(scope) {
  if (typeof scope !== 'string' || !scope.trim()) return null;
  return scope.trim().split(/\s+/);
}
