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
// Templates support {name} (the contact) and {me} (the signed-in staff member),
// filled in by the client on insert.
const DEFAULT_TEMPLATES = [
  {
    id: 'greeting',
    name: 'Greeting',
    text: 'Hi {name},\n\n{me} here from The Positive Behaviour Support Group. ',
  },
  {
    id: 'referral',
    name: 'Referral Follow-up',
    text: 'Hi {name},\n\n{me} from The Positive Behaviour Support Group here. We received a referral and just have a couple of quick questions before we can proceed. Do you have a good time in which I could call? Thanks.',
  },
  {
    id: 'service-agreement',
    name: 'Sent Service Agreement',
    text: "Hi {name},\n\nI've just sent the service agreement to your email. If you can't find it, be sure to check your junk folder. Please feel free to reach out with any questions.",
  },
];

// Shared inbound-ding volume, 0 (muted) .. 1 (full). Default to a moderate level.
const DEFAULT_SOUND_VOLUME = 0.7;

const DEFAULTS = {
  hideRecruitment: false,
  templates: DEFAULT_TEMPLATES,
  soundVolume: DEFAULT_SOUND_VOLUME,
};

const MAX_TEMPLATES = 50;
const MAX_TPL_NAME = 80;
const MAX_TPL_TEXT = 2000;

/**
 * Clamp an incoming volume to [0,1]; returns a number, or null if not a real
 * number. Rejects null/""/[]/false/true rather than letting Number() coerce
 * them to 0 or 1 — a malformed write must NOT silently mute (or max) the shared,
 * cross-profile setting. Numeric strings (e.g. "0.5") are accepted.
 */
function sanitizeVolume(v) {
  let n;
  if (typeof v === 'number') n = v;
  else if (typeof v === 'string' && v.trim() !== '') n = Number(v);
  else return null;
  if (!Number.isFinite(n)) return null;
  return Math.min(1, Math.max(0, n));
}

function ensureDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

/** Validate/clamp an incoming templates array; returns a clean array or null if not an array. */
function sanitizeTemplates(arr) {
  if (!Array.isArray(arr)) return null;
  const out = [];
  for (const t of arr.slice(0, MAX_TEMPLATES)) {
    if (!t || typeof t !== 'object') continue;
    const name = String(t.name ?? '').trim().slice(0, MAX_TPL_NAME);
    const text = String(t.text ?? '').slice(0, MAX_TPL_TEXT);
    if (!name && !text) continue;
    const id = String(t.id ?? '').trim().slice(0, 64) || `tpl-${out.length + 1}`;
    out.push({ id, name, text });
  }
  return out;
}

/** @returns {{ hideRecruitment: boolean, templates: Array<{id,name,text}>, soundVolume: number }} */
export function readSettings() {
  ensureDir();
  if (!fs.existsSync(FILE)) return { ...DEFAULTS };
  try {
    const raw = fs.readFileSync(FILE, 'utf8');
    if (!raw.trim()) return { ...DEFAULTS };
    const j = JSON.parse(raw);
    if (!j || typeof j !== 'object' || Array.isArray(j)) {
      return { ...DEFAULTS };
    }
    // Respect a stored templates array (even empty = "user deleted them all");
    // only fall back to defaults when none was ever saved.
    const stored = sanitizeTemplates(j.templates);
    const vol = sanitizeVolume(j.soundVolume);
    return {
      hideRecruitment: Boolean(j.hideRecruitment),
      templates: stored !== null ? stored : DEFAULT_TEMPLATES,
      soundVolume: vol !== null ? vol : DEFAULT_SOUND_VOLUME,
    };
  } catch {
    // Non-critical UI prefs; fall back rather than throwing.
    return { ...DEFAULTS };
  }
}

/**
 * Merge a partial patch into the stored settings and persist atomically.
 * @returns the full settings object.
 */
export function updateSettings(patch) {
  ensureDir();
  const next = readSettings();
  if (patch && typeof patch === 'object') {
    if ('hideRecruitment' in patch) next.hideRecruitment = Boolean(patch.hideRecruitment);
    if ('templates' in patch) {
      const clean = sanitizeTemplates(patch.templates);
      if (clean !== null) next.templates = clean;
    }
    if ('soundVolume' in patch) {
      const vol = sanitizeVolume(patch.soundVolume);
      if (vol !== null) next.soundVolume = vol;
    }
  }
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(next, null, 0), 'utf8');
  fs.renameSync(tmp, FILE);
  return next;
}
