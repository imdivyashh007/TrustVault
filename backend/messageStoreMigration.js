import { createHash } from 'node:crypto';
import { chmod, lstat, mkdir, mkdtemp, open, readFile, realpath, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createEncryptedMessageStore } from './encryptedMessageStore.js';

/** Back up, verify, encrypt, and verify again without altering the plaintext source. */
export async function migratePlaintextMessageStore({
  sourcePath,
  destinationPath,
  projectDirectory,
  backupParentDirectory = os.homedir(),
  key,
}) {
  requireKey(key);
  const source = path.resolve(sourcePath);
  const destination = path.resolve(destinationPath);
  const projectRoot = path.resolve(projectDirectory);
  const backupParent = path.resolve(backupParentDirectory);
  if (source === destination) throw new Error('The encrypted destination must be a separate file.');
  if (isWithin(backupParent, projectRoot)) throw new Error('The verified backup must be created outside the project directory.');

  const sourceInfo = await lstat(source);
  if (!sourceInfo.isFile() || sourceInfo.isSymbolicLink()) throw new Error('The plaintext source must be a regular file, not a symbolic link.');
  const originalMode = sourceInfo.mode & 0o777;
  const sourceBytes = await readFile(source);
  const sourceMessages = parseMessages(sourceBytes, 'source message store');
  const sourceIds = verifyMessageIds(sourceMessages);
  await ensureAbsent(destination, 'Encrypted destination');

  await mkdir(backupParent, { recursive: true, mode: 0o700 });
  const realProjectRoot = await realpath(projectRoot);
  const realBackupParent = await realpath(backupParent);
  if (isWithin(realBackupParent, realProjectRoot)) throw new Error('The resolved backup location is inside the project directory.');
  const backupDirectory = await mkdtemp(path.join(backupParent, '.trustvault-migration-'));
  await chmod(backupDirectory, 0o700);
  if (isWithin(await realpath(backupDirectory), realProjectRoot)) throw new Error('The resolved backup directory is inside the project directory.');
  const backupPath = path.join(backupDirectory, 'messages.json.backup');
  const manifestPath = path.join(backupDirectory, 'manifest.json');
  const sourceHash = sha256(sourceBytes);

  try {
    await writeExclusive(backupPath, sourceBytes, 0o600);
    const backupBytes = await readFile(backupPath);
    const backupHash = sha256(backupBytes);
    if (backupHash !== sourceHash) throw new Error('Backup SHA-256 does not match the original message file.');
    const backupMessages = parseMessages(backupBytes, 'verified backup');
    const backupIds = verifyMessageIds(backupMessages);
    assert.deepEqual(backupIds, sourceIds, 'Backup message IDs do not match the original.');
    assert.deepEqual(backupMessages, sourceMessages, 'Backup JSON records do not match the original.');
    if (sha256(await readFile(source)) !== sourceHash) throw new Error('The plaintext source changed while the backup was being verified.');

    const manifest = {
      format: 'trustvault-message-backup-v1',
      sha256: sourceHash,
      bytes: sourceBytes.length,
      recordCount: sourceMessages.length,
      ids: sourceIds,
      createdAt: new Date().toISOString(),
    };
    await writeExclusive(manifestPath, Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`), 0o600);

    await ensureAbsent(destination, 'Encrypted destination');
    const encryptedStore = createEncryptedMessageStore(destination, key);
    await encryptedStore.write(sourceMessages, { exclusive: true });
    try {
      const decryptedMessages = await encryptedStore.read();
      assert.deepEqual(decryptedMessages, sourceMessages, 'Decrypted encrypted store differs from the plaintext source.');
      assert.deepEqual(verifyMessageIds(decryptedMessages), sourceIds, 'Decrypted message IDs differ from the plaintext source.');
      const destinationInfo = await stat(destination);
      if ((destinationInfo.mode & 0o777) !== 0o600) throw new Error('Encrypted message store permissions are not owner-only.');
      if (sha256(await readFile(source)) !== sourceHash) throw new Error('The plaintext source changed during migration.');
      await chmod(source, 0o600);
    } catch (error) {
      await rm(destination, { force: true }).catch(() => {});
      await chmod(source, originalMode).catch(() => {});
      throw error;
    }

    return {
      sourcePath: source,
      destinationPath: destination,
      backupPath,
      manifestPath,
      sha256: sourceHash,
      recordCount: sourceMessages.length,
      ids: sourceIds,
    };
  } catch (error) {
    // Keep any verified backup for recovery; the plaintext source is never modified.
    throw error;
  }
}

/** Restore a verified backup to a new path. Existing files are never overwritten. */
export async function restoreVerifiedMessageBackup({ backupPath, manifestPath, destinationPath }) {
  const backupBytes = await readFile(backupPath);
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  if (manifest.format !== 'trustvault-message-backup-v1' || sha256(backupBytes) !== manifest.sha256 || backupBytes.length !== manifest.bytes) {
    throw new Error('Backup verification failed; recovery file was not written.');
  }
  const messages = parseMessages(backupBytes, 'verified backup');
  assert.equal(messages.length, manifest.recordCount, 'Backup record count does not match its manifest.');
  assert.deepEqual(verifyMessageIds(messages), manifest.ids, 'Backup message IDs do not match its manifest.');
  const restorePath = path.resolve(destinationPath);
  await ensureAbsent(restorePath, 'Recovery destination');
  await writeExclusive(restorePath, backupBytes, 0o600);
  const restoredBytes = await readFile(restorePath);
  if (sha256(restoredBytes) !== manifest.sha256) {
    await rm(restorePath, { force: true }).catch(() => {});
    throw new Error('Restored recovery file failed verification and was removed.');
  }
  return { destinationPath: restorePath, sha256: manifest.sha256, recordCount: messages.length, ids: manifest.ids };
}

function parseMessages(bytes, label) {
  let messages;
  try {
    messages = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`The ${label} is not valid JSON.`);
  }
  if (!Array.isArray(messages)) throw new Error(`The ${label} must contain a JSON array.`);
  return messages;
}

function verifyMessageIds(messages) {
  const ids = messages.map((message) => message?.id);
  if (ids.some((id) => typeof id !== 'string' || id.length === 0)) throw new Error('Every message must have a non-empty string ID before migration.');
  if (new Set(ids).size !== ids.length) throw new Error('Message IDs must be unique before migration.');
  return ids;
}

function requireKey(key) {
  if (!Buffer.isBuffer(key) || key.length !== 32) throw new TypeError('A dedicated 32-byte message-encryption key is required.');
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function isWithin(candidate, parent) {
  const relative = path.relative(parent, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function ensureAbsent(filePath, label) {
  try {
    await stat(filePath);
    throw new Error(`${label} already exists; migration will not overwrite it.`);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
}

async function writeExclusive(filePath, contents, mode) {
  const handle = await open(filePath, 'wx', mode);
  try {
    await handle.writeFile(contents);
    await handle.sync();
  } catch (error) {
    await handle.close().catch(() => {});
    await rm(filePath, { force: true }).catch(() => {});
    throw error;
  }
  await handle.close();
}
