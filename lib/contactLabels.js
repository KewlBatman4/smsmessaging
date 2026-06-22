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

// Keys are Twilio Conversation SIDs ("CH" + 32 hex). Validating this blocks
// garbage/unbounded keys (and prototype-pollution-style keys like __proto__)
// from ever reaching the persisted store.
const SID_RE = /^CH[0-9a-fA-F]{32}$/;
const MAX_NAME_LEN = 200;
const MAX_DETAILS_LEN = 2000;
const MAX_ENTRIES = 50000;

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
 * @throws if the file exists but is not parseable JSON — surfacing corruption
 *   rather than silently returning {} (a subsequent write would otherwise
 *   overwrite the corrupt file and permanently lose every label).
 */
export function readAllContactLabels() {
  ensureFile();
  const raw = fs.readFileSync(FILE, 'utf8');
  if (raw.trim() === '') return {};
  let j;
  try {
    j = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `contact-labels store is corrupt (${FILE}): ${err.message}. ` +
        'Refusing to read so a write cannot wipe it; restore from backup or fix the file.'
    );
  }
  return j && typeof j === 'object' && !Array.isArray(j) ? j : {};
}

/**
 * Atomic write: serialise to a temp file on the same filesystem, then rename
 * over the target. A crash/restart mid-write can no longer truncate or corrupt
 * the live file (the rename either fully happens or it doesn't).
 */
function writeAll(map) {
  ensureFile();
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(map, null, 0), 'utf8');
  fs.renameSync(tmp, FILE);
}

/**
 * @returns {{ name: string, details: string } | null}  null if entry removed
 */
export function upsertContactLabel(conversationSid, { name, details }) {
  const sid = String(conversationSid || '').trim();
  if (!sid) {
    throw new Error('conversationSid required');
  }
  if (!SID_RE.test(sid)) {
    throw new Error('conversationSid must be a Twilio Conversation SID (CH + 32 hex).');
  }
  const n = String(name ?? '').trim();
  const d = String(details ?? '').trim();
  if (n.length > MAX_NAME_LEN) {
    throw new Error(`name too long (max ${MAX_NAME_LEN} characters).`);
  }
  if (d.length > MAX_DETAILS_LEN) {
    throw new Error(`details too long (max ${MAX_DETAILS_LEN} characters).`);
  }
  const all = readAllContactLabels();
  if (!n && !d) {
    if (sid in all) {
      delete all[sid];
      writeAll(all);
    }
    return null;
  }
  if (!(sid in all) && Object.keys(all).length >= MAX_ENTRIES) {
    throw new Error('contact label store is full.');
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
