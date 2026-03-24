import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, '..', 'data');
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
