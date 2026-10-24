import { createServer } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig } from './config.js';
import { migratePlaintextMessageStore } from './messageStoreMigration.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourcePath = path.join(projectRoot, 'backend/data/messages.json');
const destinationPath = path.join(projectRoot, 'backend/data/messages.encrypted.json');

async function assertBackendStopped(host, port) {
  const probe = createServer();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(port, host, () => probe.close((error) => error ? reject(error) : resolve()));
  }).catch((error) => {
    if (error.code === 'EADDRINUSE') throw new Error('Stop the TrustVault backend before migrating, so no import can race the backup.');
    throw error;
  });
}

async function main() {
  const config = loadConfig({ requireAuth: true });
  await assertBackendStopped(config.host, config.port);
  const result = await migratePlaintextMessageStore({
    sourcePath,
    destinationPath,
    projectDirectory: projectRoot,
    backupParentDirectory: os.homedir(),
    key: config.messageEncryptionKey,
  });
  process.stdout.write([
    'Message-store migration verified.',
    `Records: ${result.recordCount}`,
    `SHA-256: ${result.sha256}`,
    `Verified backup: ${result.backupPath}`,
    `Backup manifest: ${result.manifestPath}`,
    `Encrypted store: ${result.destinationPath}`,
    'The original plaintext messages.json was left unchanged.',
    '',
  ].join('\n'));
}

main().catch((error) => {
  process.stderr.write(`Message-store migration stopped safely: ${error.message}\n`);
  process.exitCode = 1;
});
