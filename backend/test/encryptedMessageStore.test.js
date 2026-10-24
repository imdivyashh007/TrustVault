import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { createHash } from 'node:crypto';
import { createEncryptedMessageStore, decryptMessageStore, encryptMessageStore } from '../encryptedMessageStore.js';
import { migratePlaintextMessageStore, restoreVerifiedMessageBackup } from '../messageStoreMigration.js';

const key = Buffer.alloc(32, 42);
const records = [
  { id: 'fictional-1', type: 'SMS', sender: 'Campus Demo', subject: '', body: 'A fictional sample record.', date: '2026-10-20' },
  { id: 'fictional-2', type: 'Email', sender: 'Library Demo', subject: 'Example', body: 'Another fictional sample.', date: '2026-10-21' },
];

test('versioned AES-256-GCM message storage round-trips and randomizes nonces', () => {
  const first = encryptMessageStore(records, key);
  const second = encryptMessageStore(records, key);
  assert.equal(first.version, 1);
  assert.equal(first.algorithm, 'aes-256-gcm');
  assert.notEqual(first.iv, second.iv);
  assert.equal(JSON.stringify(first).includes(records[0].body), false);
  assert.deepEqual(decryptMessageStore(first, key), records);
});

test('message storage rejects modified ciphertext, wrong keys, malformed envelopes, and non-array content', () => {
  const envelope = encryptMessageStore(records, key);
  const firstCharacter = envelope.ciphertext[0];
  const changedCharacter = firstCharacter === 'A' ? 'B' : 'A';
  assert.throws(() => decryptMessageStore({ ...envelope, ciphertext: changedCharacter + envelope.ciphertext.slice(1) }, key));
  assert.throws(() => decryptMessageStore(envelope, Buffer.alloc(32, 7)));
  assert.throws(() => decryptMessageStore({ ...envelope, version: 2 }, key), /Unsupported encrypted/);
  assert.throws(() => encryptMessageStore({ message: 'not an array' }, key), /must contain an array/);
});

test('encrypted message store files are private and can be reloaded', async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'trustvault-encrypted-store-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'messages.encrypted.json');
  const store = createEncryptedMessageStore(filePath, key);
  await store.write(records, { exclusive: true });
  const stored = await readFile(filePath, 'utf8');
  assert.equal(stored.includes(records[0].body), false);
  assert.equal((await stat(filePath)).mode & 0o777, 0o600);
  assert.deepEqual(await store.read(), records);
  await store.write([...records, { id: 'fictional-3', body: 'Added later.' }]);
  assert.equal((await store.read()).length, 3);
});

test('migration makes a verified external backup, encrypts a separate copy, and leaves plaintext unchanged', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'trustvault-migration-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const project = path.join(root, 'project');
  const outside = path.join(root, 'outside');
  const data = path.join(project, 'backend', 'data');
  await mkdir(data, { recursive: true });
  const sourcePath = path.join(data, 'messages.json');
  const destinationPath = path.join(data, 'messages.encrypted.json');
  const originalBytes = Buffer.from(`${JSON.stringify(records, null, 2)}\n`);
  await writeFile(sourcePath, originalBytes, { mode: 0o644 });

  const result = await migratePlaintextMessageStore({ sourcePath, destinationPath, projectDirectory: project, backupParentDirectory: outside, key });
  assert.equal(path.relative(project, result.backupPath).startsWith('..'), true);
  assert.equal(result.recordCount, records.length);
  assert.deepEqual(result.ids, records.map((record) => record.id));
  assert.equal(result.sha256, createHash('sha256').update(originalBytes).digest('hex'));
  assert.deepEqual(await readFile(sourcePath), originalBytes);
  assert.equal((await stat(sourcePath)).mode & 0o777, 0o600);
  assert.deepEqual(await createEncryptedMessageStore(destinationPath, key).read(), records);
  const backup = await readFile(result.backupPath);
  assert.deepEqual(backup, originalBytes);
  assert.equal((await stat(result.backupPath)).mode & 0o777, 0o600);
  assert.equal((await stat(result.manifestPath)).mode & 0o777, 0o600);
});

test('verified backup recovery writes to a new path and refuses to overwrite existing files', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'trustvault-recovery-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const project = path.join(root, 'project');
  const data = path.join(project, 'backend', 'data');
  await mkdir(data, { recursive: true });
  const sourcePath = path.join(data, 'messages.json');
  const original = Buffer.from(`${JSON.stringify(records)}\n`);
  await writeFile(sourcePath, original, { mode: 0o600 });
  const migration = await migratePlaintextMessageStore({
    sourcePath,
    destinationPath: path.join(data, 'messages.encrypted.json'),
    projectDirectory: project,
    backupParentDirectory: root,
    key,
  });

  const recoveredPath = path.join(data, 'messages.recovered.json');
  const recovered = await restoreVerifiedMessageBackup({ backupPath: migration.backupPath, manifestPath: migration.manifestPath, destinationPath: recoveredPath });
  assert.equal(recovered.sha256, migration.sha256);
  assert.deepEqual(await readFile(recoveredPath), original);
  await assert.rejects(restoreVerifiedMessageBackup({ backupPath: migration.backupPath, manifestPath: migration.manifestPath, destinationPath: recoveredPath }), /already exists/);
  assert.deepEqual(await readFile(sourcePath), original);
});

test('migration stops before creating output for invalid source or an existing encrypted target', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'trustvault-migration-stop-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const project = path.join(root, 'project');
  const data = path.join(project, 'backend', 'data');
  await mkdir(data, { recursive: true });
  const sourcePath = path.join(data, 'messages.json');
  const destinationPath = path.join(data, 'messages.encrypted.json');
  const invalid = Buffer.from('{bad json');
  await writeFile(sourcePath, invalid);
  await assert.rejects(migratePlaintextMessageStore({ sourcePath, destinationPath, projectDirectory: project, backupParentDirectory: root, key }), /not valid JSON/);
  assert.deepEqual(await readFile(sourcePath), invalid);
  assert.equal((await stat(destinationPath).catch(() => null)), null);

  await writeFile(sourcePath, `${JSON.stringify(records)}\n`);
  await writeFile(destinationPath, 'existing encrypted data');
  await assert.rejects(migratePlaintextMessageStore({ sourcePath, destinationPath, projectDirectory: project, backupParentDirectory: root, key }), /already exists/);
  assert.equal(await readFile(destinationPath, 'utf8'), 'existing encrypted data');
});
