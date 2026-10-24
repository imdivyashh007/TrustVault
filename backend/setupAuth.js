import { open, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { hashPassword } from './passwordAuth.js';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const envPath = path.join(projectRoot, '.env');

async function readHiddenPassword(prompt) {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error('Run setup-auth in an interactive terminal so the password stays hidden.');
  process.stdout.write(prompt);
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolve, reject) => {
    let value = '';
    const finish = (error) => {
      process.stdin.setRawMode(false);
      process.stdin.pause();
      process.stdin.removeListener('data', onData);
      process.stdout.write('\n');
      if (error) reject(error);
      else resolve(value);
    };
    const onData = (chunk) => {
      for (const character of chunk.toString('utf8')) {
        if (character === '\u0003') return finish(new Error('Setup cancelled.'));
        if (character === '\r' || character === '\n') return finish();
        if (character === '\u007f' || character === '\b') value = value.slice(0, -1);
        else if (character >= ' ') value += character;
      }
    };
    process.stdin.on('data', onData);
  });
}

async function main() {
  try {
    await stat(envPath);
    throw new Error('A .env file already exists. It was not changed. Review it manually before continuing.');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }

  const password = await readHiddenPassword('Choose a local TrustVault password (12+ characters): ');
  const confirmation = await readHiddenPassword('Confirm password: ');
  if (password !== confirmation) throw new Error('The passwords did not match. No file was created.');
  const authPasswordHash = await hashPassword(password);
  const sessionSecret = randomBytes(32).toString('base64');
  const tokenEncryptionKey = randomBytes(32).toString('base64');
  const contents = [
    '# Local TrustVault configuration. Keep this file private.',
    'HOST=127.0.0.1',
    'PORT=4000',
    `AUTH_PASSWORD_HASH=${authPasswordHash}`,
    `SESSION_SECRET=${sessionSecret}`,
    `TOKEN_ENCRYPTION_KEY=${tokenEncryptionKey}`,
    '',
  ].join('\n');

  // Exclusive creation prevents replacing secrets or configuration made by the user.
  const handle = await open(envPath, 'wx', 0o600);
  try {
    await handle.writeFile(contents, 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  process.stdout.write('Local authentication configured. The .env file was created with owner-only permissions.\n');
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
