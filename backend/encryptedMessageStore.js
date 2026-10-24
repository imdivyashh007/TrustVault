import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { link, mkdir, open, readFile, rename, rm, unlink } from 'node:fs/promises';
import path from 'node:path';

const VERSION = 1;
const ALGORITHM = 'aes-256-gcm';
const AAD = Buffer.from('trustvault-message-store:v1', 'utf8');

export function encryptMessageStore(messages, key) {
  if (!Array.isArray(messages)) throw new TypeError('The encrypted message store must contain an array.');
  const encryptionKey = requireKey(key);
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, encryptionKey, iv);
  cipher.setAAD(AAD);
  const plaintext = Buffer.from(`${JSON.stringify(messages, null, 2)}\n`, 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return {
    version: VERSION,
    algorithm: ALGORITHM,
    iv: iv.toString('base64url'),
    ciphertext: ciphertext.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
  };
}

export function decryptMessageStore(envelope, key) {
  const encryptionKey = requireKey(key);
  if (!envelope || envelope.version !== VERSION || envelope.algorithm !== ALGORITHM) {
    throw new Error('Unsupported encrypted message store format.');
  }
  const iv = decodeField(envelope.iv, 'initialization vector');
  const ciphertext = decodeField(envelope.ciphertext, 'ciphertext');
  const tag = decodeField(envelope.tag, 'authentication tag');
  if (iv.length !== 12 || tag.length !== 16) throw new Error('Invalid encrypted message store format.');

  const decipher = createDecipheriv(ALGORITHM, encryptionKey, iv);
  decipher.setAAD(AAD);
  decipher.setAuthTag(tag);
  const messages = JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
  if (!Array.isArray(messages)) throw new Error('Decrypted message store is not a JSON array.');
  return messages;
}

export function createEncryptedMessageStore(filePath, key) {
  requireKey(key);
  return {
    async read() {
      const envelope = JSON.parse(await readFile(filePath, 'utf8'));
      return decryptMessageStore(envelope, key);
    },

    async write(messages, { exclusive = false } = {}) {
      const directory = path.dirname(filePath);
      await mkdir(directory, { recursive: true, mode: 0o700 });
      const temporaryPath = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
      const serializedEnvelope = `${JSON.stringify(encryptMessageStore(messages, key))}\n`;
      let handle;
      let linkedDestination = false;
      try {
        handle = await open(temporaryPath, 'wx', 0o600);
        await handle.writeFile(serializedEnvelope, 'utf8');
        await handle.sync();
        await handle.close();
        handle = undefined;
        if (exclusive) {
          await link(temporaryPath, filePath);
          linkedDestination = true;
          await unlink(temporaryPath);
        } else {
          await rename(temporaryPath, filePath);
        }
        await syncDirectory(directory);
      } catch (error) {
        if (handle) await handle.close().catch(() => {});
        await rm(temporaryPath, { force: true }).catch(() => {});
        if (exclusive && linkedDestination) await rm(filePath, { force: true }).catch(() => {});
        throw error;
      }
    },
  };
}

function requireKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new TypeError('Message-store encryption requires a dedicated 32-byte MESSAGE_ENCRYPTION_KEY.');
  }
  return key;
}

function decodeField(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`Invalid encrypted message ${label}.`);
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new Error(`Invalid encrypted message ${label}.`);
  return decoded;
}

async function syncDirectory(directory) {
  let handle;
  try {
    handle = await open(directory, 'r');
    await handle.sync();
  } catch (error) {
    // Directory fsync is not supported by every filesystem; file data is already synced.
    if (!['EINVAL', 'ENOTSUP', 'EISDIR'].includes(error.code)) throw error;
  } finally {
    await handle?.close();
  }
}
