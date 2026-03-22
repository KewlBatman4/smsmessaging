/**
 * Generate APP_PASSWORD_HASH for .env (never commit real passwords).
 *
 * Usage:
 *   node scripts/hash-password.mjs
 *   node scripts/hash-password.mjs "your-password"
 *
 * Prefer stdin / prompted input on shared machines so the password is not in shell history.
 */
import bcrypt from 'bcrypt';
import * as readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

const rounds = 12;
let plain = process.argv[2];

if (!plain) {
  const rl = readline.createInterface({ input, output });
  plain = await rl.question('Enter password to hash: ');
  await rl.close();
}

plain = plain?.trim();
if (!plain) {
  console.error('Password cannot be empty.');
  process.exit(1);
}

const hash = await bcrypt.hash(plain, rounds);
console.log('\nAdd this to backend .env (quote if your shell treats $ specially):\n');
console.log(`APP_PASSWORD_HASH=${hash}\n`);
