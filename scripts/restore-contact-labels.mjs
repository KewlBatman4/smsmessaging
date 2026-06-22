// Restore contact labels from a backup file by re-PUTting each into a running backend.
// Use this once after switching to a persistent volume (the new volume starts empty).
//
// Usage (run from the backend folder so it loads backend/.env):
//   node scripts/restore-contact-labels.mjs [inputPath] [baseUrl]
//
// Defaults: inputPath = contact-labels.backup.json, baseUrl = the Railway prod URL.
import 'dotenv/config';
import jwt from 'jsonwebtoken';
import fs from 'node:fs';

const secret = process.env.SESSION_JWT_SECRET;
const inPath = process.argv[2] || 'contact-labels.backup.json';
const base = process.argv[3] || process.env.BACKUP_BASE || 'https://smsmessaging-production.up.railway.app';

if (!secret) {
  console.error('SESSION_JWT_SECRET is required (run from the backend folder with its .env).');
  process.exit(1);
}
let labels;
try {
  labels = JSON.parse(fs.readFileSync(inPath, 'utf8'));
} catch (e) {
  console.error('Cannot read/parse', inPath, '-', e.message);
  process.exit(2);
}
if (!labels || typeof labels !== 'object' || Array.isArray(labels)) {
  console.error('Backup must be a JSON object of { conversationSid: { name, details } }.');
  process.exit(2);
}
const token = jwt.sign({ sub: 'labels-restore' }, secret, { expiresIn: '30m' });

let ok = 0;
let fail = 0;
for (const [conversationSid, v] of Object.entries(labels)) {
  try {
    const res = await fetch(`${base}/api/contact-labels`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ conversationSid, name: v?.name, details: v?.details }),
    });
    if (res.ok) {
      ok++;
    } else {
      fail++;
      console.error('FAILED', conversationSid, res.status, (await res.text()).slice(0, 120));
    }
  } catch (e) {
    fail++;
    console.error('FAILED', conversationSid, '-', e.message);
  }
}
console.log(`Restored ${ok} label(s), ${fail} failed, into ${base}`);
