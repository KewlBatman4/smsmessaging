import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Share the same persistent dir as contact labels (set CONTACT_LABELS_DIR to a
// Railway volume so this survives redeploys).
const DATA_DIR = process.env.CONTACT_LABELS_DIR
  ? path.resolve(process.env.CONTACT_LABELS_DIR)
  : path.join(__dirname, '..', 'data');
const FILE = path.join(DATA_DIR, 'app-settings.json');

// Shared, server-side app settings (apply to every browser/session).
const DEFAULTS = { hideRecruitment: false };

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

/** @returns {{ hideRecruitment: boolean }} */
export function readSettings() {
  ensureDir();
  if (!fs.existsSync(FILE)) return { ...DEFAULTS };
  try {
    const raw = fs.readFileSync(FILE, 'utf8');
    if (!raw.trim()) return { ...DEFAULTS };
    const j = JSON.parse(raw);
    if (!j || typeof j !== 'object' || Array.isArray(j)) return { ...DEFAULTS };
    return { ...DEFAULTS, hideRecruitment: Boolean(j.hideRecruitment) };
  } catch {
    // Settings are non-critical UI prefs; fall back to defaults rather than
    // throwing (unlike contact labels, there is nothing irreplaceable here).
    return { ...DEFAULTS };
  }
}

/**
 * Merge a partial patch into the stored settings and persist atomically.
 * @returns {{ hideRecruitment: boolean }}
 */
export function updateSettings(patch) {
  ensureDir();
  const next = readSettings();
  if (patch && typeof patch === 'object' && 'hideRecruitment' in patch) {
    next.hideRecruitment = Boolean(patch.hideRecruitment);
  }
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(next, null, 0), 'utf8');
  fs.renameSync(tmp, FILE);
  return next;
}
