import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Default to ./data, but allow an absolute override so contact labels can live on
// a persistent disk that survives redeploys. On Railway: add a Volume mounted at
// e.g. /data, then set CONTACT_LABELS_DIR=/data. Without this, the container's
// filesystem is ephemeral and labels are wiped on every deploy/restart.
const DATA_DIR = process.env.CONTACT_LABELS_DIR
  ? path.resolve(process.env.CONTACT_LABELS_DIR)
  : path.join(__dirname, '..', 'data');
const FILE = path.join(DATA_DIR, 'contact-labels.json');

function ensureFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  if (!fs.existsSync(FILE)) {
    fs.writeFileSync(FILE, '{}', 'utf8');
  }
}

/**
 * @returns {Record<string, { name: string, details: string }>}
 */
export function readAllContactLabels() {
  ensureFile();
  try {
    const raw = fs.readFileSync(FILE, 'utf8');
    const j = JSON.parse(raw);
    return j && typeof j === 'object' ? j : {};
  } catch {
    return {};
  }
}

function writeAll(map) {
  ensureFile();
  fs.writeFileSync(FILE, JSON.stringify(map, null, 0), 'utf8');
}

/**
 * @returns {{ name: string, details: string } | null}  null if entry removed
 */
export function upsertContactLabel(conversationSid, { name, details }) {
  const sid = String(conversationSid || '').trim();
  if (!sid) {
    throw new Error('conversationSid required');
  }
  const n = String(name ?? '').trim();
  const d = String(details ?? '').trim();
  const all = readAllContactLabels();
  if (!n && !d) {
    delete all[sid];
    writeAll(all);
    return null;
  }
  all[sid] = { name: n, details: d };
  writeAll(all);
  return all[sid];
}

export function removeContactLabel(conversationSid) {
  const sid = String(conversationSid || '').trim();
  if (!sid) return;
  const all = readAllContactLabels();
  if (sid in all) {
    delete all[sid];
    writeAll(all);
  }
}
