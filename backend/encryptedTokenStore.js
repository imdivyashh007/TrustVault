import { chmod, lstat, mkdir, open, readFile, rename, rm } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { decryptToken, encryptToken } from './tokenEncryption.js';

/** Persist one encrypted value as an owner-only file using an atomic replacement. */
export async function writeEncryptedToken(filePath, token, key) {
  // Validate the key and encrypt before touching the filesystem.
  const contents = `${JSON.stringify({ encryptedToken: encryptToken(token, key) })}\n`;
  const directory = path.dirname(filePath);
  await ensurePrivateDirectory(directory);
  const temporaryPath = `${filePath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  let handle;
  try {
    handle = await open(temporaryPath, 'wx', 0o600);
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporaryPath, filePath);
    await chmod(filePath, 0o600);
    await assertPrivateFile(filePath);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
}

/** Read and authenticate the encrypted envelope; absent files return null. */
export async function readEncryptedToken(filePath, key) {
  // Fail on a missing/invalid key even when there is no file to read.
  decryptTokenShapeKeyCheck(key);
  const directory = path.dirname(filePath);
  if (!await assertPrivateDirectoryIfPresent(directory)) return null;
  if (!await assertPrivateFileIfPresent(filePath)) return null;
  const stored = JSON.parse(await readFile(filePath, 'utf8'));
  return decryptToken(stored.encryptedToken, key);
}

/** Remove only the selected local token file; this does not revoke Google consent. */
export async function removeEncryptedToken(filePath) {
  const directory = path.dirname(filePath);
  if (!await assertPrivateDirectoryIfPresent(directory)) return false;
  if (!await assertPrivateFileIfPresent(filePath)) return false;
  await rm(filePath);
  return true;
}

async function ensurePrivateDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const info = await lstat(directory);
  if (!info.isDirectory() || (info.mode & 0o077) !== 0) {
    throw new Error('Encrypted token directory permissions are not private.');
  }
}

async function assertPrivateDirectoryIfPresent(directory) {
  let info;
  try {
    info = await lstat(directory);
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
  if (!info.isDirectory() || (info.mode & 0o077) !== 0) {
    throw new Error('Encrypted token directory permissions are not private.');
  }
  return true;
}

async function assertPrivateFile(filePath) {
  const info = await lstat(filePath);
  if (!info.isFile() || (info.mode & 0o077) !== 0) {
    throw new Error('Encrypted token file permissions are not private.');
  }
}

async function assertPrivateFileIfPresent(filePath) {
  let info;
  try {
    info = await lstat(filePath);
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
  if (!info.isFile() || (info.mode & 0o077) !== 0) {
    throw new Error('Encrypted token file permissions are not private.');
  }
  return true;
}

function decryptTokenShapeKeyCheck(key) {
  // Reuse the encryption module's canonical key validation without attempting a decrypt.
  if (!Buffer.isBuffer(key) || key.length !== 32) {
    throw new TypeError('Token encryption requires a 32-byte key from validated local configuration.');
  }
}
