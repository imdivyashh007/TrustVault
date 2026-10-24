import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

const VERSION = 1;
const ALGORITHM = 'aes-256-gcm';
const AUTHENTICATED_CONTEXT = Buffer.from('trustvault-token:v1', 'utf8');

/** Encrypt a token into a versioned JSON-safe envelope. Never log this value. */
export function encryptToken(token, key) {
  if (typeof token !== 'string' || token.length === 0) throw new TypeError('Token must be a non-empty string.');
  const encryptionKey = requireKey(key);
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, encryptionKey, iv);
  cipher.setAAD(AUTHENTICATED_CONTEXT);
  const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  return {
    version: VERSION,
    algorithm: ALGORITHM,
    iv: iv.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
  };
}

/** Decrypt only envelopes produced by the current format; authentication failures throw. */
export function decryptToken(envelope, key) {
  const encryptionKey = requireKey(key);
  if (!envelope || envelope.version !== VERSION || envelope.algorithm !== ALGORITHM) {
    throw new Error('Unsupported encrypted token format.');
  }
  const iv = decodeField(envelope.iv, 'initialization vector');
  const ciphertext = decodeField(envelope.ciphertext, 'ciphertext');
  const tag = decodeField(envelope.tag, 'authentication tag');
  if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid encrypted token format.');

  const decipher = createDecipheriv(ALGORITHM, encryptionKey, iv);
  decipher.setAAD(AUTHENTICATED_CONTEXT);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
}

function requireKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new TypeError('Token encryption requires a 32-byte key from validated local configuration.');
  }
  return key;
}

function decodeField(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new Error(`Invalid encrypted token ${label}.`);
  }
  return Buffer.from(value, 'base64url');
}
