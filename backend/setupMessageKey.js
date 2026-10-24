import { lstat, open, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { parseEnvFile } from './config.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(projectRoot, '.env');

async function main() {
  if (process.env.MESSAGE_ENCRYPTION_KEY) {
    throw new Error('MESSAGE_ENCRYPTION_KEY is already set in the process environment. No file was changed.');
  }
  const contents = await readFile(envPath, 'utf8');
  const values = parseEnvFile(contents);
  if (values.MESSAGE_ENCRYPTION_KEY) throw new Error('MESSAGE_ENCRYPTION_KEY already exists in .env. No file was changed.');
  const fileInfo = await lstat(envPath);
  if (!fileInfo.isFile() || fileInfo.isSymbolicLink()) throw new Error('.env must be a regular file. No file was changed.');
  if ((fileInfo.mode & 0o077) !== 0) throw new Error('.env permissions must be owner-only (600) before adding a key. No file was changed.');
  if (!contents.endsWith('\n')) throw new Error('.env must end with a newline before adding a key. No file was changed.');

  const key = randomBytes(32).toString('base64');
  const handle = await open(envPath, 'a');
  try {
    const current = parseEnvFile(await readFile(envPath, 'utf8'));
    if (current.MESSAGE_ENCRYPTION_KEY) throw new Error('MESSAGE_ENCRYPTION_KEY was added concurrently. No key was appended.');
    await handle.writeFile(`\n# Dedicated key for the local encrypted message store. Keep this value private.\nMESSAGE_ENCRYPTION_KEY=${key}\n`);
    await handle.sync();
  } finally {
    await handle.close();
  }
  process.stdout.write('A dedicated message-encryption key was added to the owner-only .env file. Its value was not displayed.\n');
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
