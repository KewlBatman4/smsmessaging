// Download all contact labels from a running backend and save them to a JSON file.
//
// Usage (run from the backend folder so it loads backend/.env):
//   node scripts/backup-contact-labels.mjs [outputPath] [baseUrl]
//
// Defaults: outputPath = contact-labels.backup.json, baseUrl = the Railway prod URL.
// Auth: mints a short-lived session JWT from SESSION_JWT_SECRET (the same secret the
// server verifies with), so no password is needed when run locally with the prod env.
import 'dotenv/config';
import jwt from 'jsonwebtoken';
import fs from 'node:fs';

const secret = process.env.SESSION_JWT_SECRET;
const out = process.argv[2] || 'contact-labels.backup.json';
const base = process.argv[3] || process.env.BACKUP_BASE || 'https://smsmessaging-production.up.railway.app';

if (!secret) {
  console.error('SESSION_JWT_SECRET is required (run from the backend folder with its .env).');
  process.exit(1);
}

const token = jwt.sign({ sub: 'labels-backup' }, secret, { expiresIn: '10m' });
const res = await fetch(`${base}/api/contact-labels`, {
  headers: { Authorization: `Bearer ${token}` },
});
console.log('GET', `${base}/api/contact-labels`, '->', res.status);
const text = await res.text();
if (!res.ok) {
  console.error('Failed:', text.slice(0, 300));
  process.exit(2);
}
const labels = JSON.parse(text).labels || {};
fs.writeFileSync(out, JSON.stringify(labels, null, 2), 'utf8');
console.log(`Saved ${Object.keys(labels).length} contact label(s) to ${out}`);
