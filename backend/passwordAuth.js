import { promisify } from 'node:util';
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from 'node:crypto';

const scrypt = promisify(scryptCallback);
const COST = 32768;
const BLOCK_SIZE = 8;
const PARALLELIZATION = 1;
const KEY_LENGTH = 64;
const MAX_MEMORY = 64 * 1024 * 1024;

/** Derive a password verifier using Node's memory-hard scrypt implementation. */
export async function hashPassword(password) {
  validatePasswordInput(password);
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, KEY_LENGTH, {
    N: COST,
    r: BLOCK_SIZE,
    p: PARALLELIZATION,
    maxmem: MAX_MEMORY,
  });
  return `scrypt$${COST}$${BLOCK_SIZE}$${PARALLELIZATION}$${salt.toString('base64url')}$${derived.toString('base64url')}`;
}

/** Verify a password without revealing whether the stored verifier matched. */
export async function verifyPassword(password, encodedHash) {
  if (typeof password !== 'string' || password.length > 1024 || typeof encodedHash !== 'string') return false;
  const parts = encodedHash.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt' || parts[1] !== String(COST) || parts[2] !== String(BLOCK_SIZE) || parts[3] !== String(PARALLELIZATION)) return false;
  let salt;
  let expected;
  try {
    salt = Buffer.from(parts[4], 'base64url');
    expected = Buffer.from(parts[5], 'base64url');
  } catch {
    return false;
  }
  if (salt.length !== 16 || expected.length !== KEY_LENGTH) return false;
  if (salt.toString('base64url') !== parts[4] || expected.toString('base64url') !== parts[5]) return false;
  const actual = await scrypt(password, salt, KEY_LENGTH, {
    N: COST,
    r: BLOCK_SIZE,
    p: PARALLELIZATION,
    maxmem: MAX_MEMORY,
  });
  return timingSafeEqual(actual, expected);
}

function validatePasswordInput(password) {
  if (typeof password !== 'string' || password.length < 12 || password.length > 1024) {
    throw new TypeError('Choose a password between 12 and 1024 characters.');
  }
}
