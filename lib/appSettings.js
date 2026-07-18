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

// Templates support {name} (the contact) and {me} (the signed-in staff member),
// filled in by the client on insert. They are stored per authenticated user;
// the other settings in this file remain shared across the team.
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

// Per-user inbound-ding volume, 0 (muted) .. 1 (full). Default to a moderate level.
const DEFAULT_SOUND_VOLUME = 0.7;

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

function normalizeUserKey(userKey) {
  return String(userKey || 'pbsg').trim().toLowerCase().slice(0, 128) || 'pbsg';
}

function readStoredObject() {
  ensureDir();
  if (!fs.existsSync(FILE)) return {};
  try {
    const raw = fs.readFileSync(FILE, 'utf8');
    if (!raw.trim()) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function sanitizeTemplatesByUser(value) {
  const out = Object.create(null);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  for (const [rawKey, templates] of Object.entries(value).slice(0, 100)) {
    const clean = sanitizeTemplates(templates);
    if (clean !== null) out[normalizeUserKey(rawKey)] = clean;
  }
  return out;
}

function sanitizeVolumesByUser(value) {
  const out = Object.create(null);
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  for (const [rawKey, volume] of Object.entries(value).slice(0, 100)) {
    const clean = sanitizeVolume(volume);
    if (clean !== null) out[normalizeUserKey(rawKey)] = clean;
  }
  return out;
}

/** @returns {{ hideRecruitment: boolean, templates: Array<{id,name,text}>, soundVolume: number }} */
export function readSettings(userKey = 'pbsg') {
  const stored = readStoredObject();
  const templatesByUser = sanitizeTemplatesByUser(stored.templatesByUser);
  const soundVolumeByUser = sanitizeVolumesByUser(stored.soundVolumeByUser);
  const owner = normalizeUserKey(userKey);
  const ownTemplates = Object.prototype.hasOwnProperty.call(templatesByUser, owner)
    ? templatesByUser[owner]
    : null;
  // Migration: an existing shared list becomes the starting list for users who
  // have not saved their own list yet. Once saved, their own list always wins.
  const legacyTemplates = sanitizeTemplates(stored.templates);
  const ownVolume = Object.prototype.hasOwnProperty.call(soundVolumeByUser, owner)
    ? soundVolumeByUser[owner]
    : null;
  const legacyVolume = sanitizeVolume(stored.soundVolume);
  return {
    hideRecruitment: Boolean(stored.hideRecruitment),
    templates: ownTemplates ?? legacyTemplates ?? DEFAULT_TEMPLATES,
    soundVolume: ownVolume ?? legacyVolume ?? DEFAULT_SOUND_VOLUME,
  };
}

/**
 * Merge a partial patch into the stored settings and persist atomically.
 * @returns the full settings object.
 */
export function updateSettings(patch, userKey = 'pbsg') {
  ensureDir();
  const stored = readStoredObject();
  const current = readSettings(userKey);
  const templatesByUser = sanitizeTemplatesByUser(stored.templatesByUser);
  const soundVolumeByUser = sanitizeVolumesByUser(stored.soundVolumeByUser);
  const owner = normalizeUserKey(userKey);
  let hideRecruitment = current.hideRecruitment;
  if (patch && typeof patch === 'object') {
    if ('hideRecruitment' in patch) hideRecruitment = Boolean(patch.hideRecruitment);
    if ('templates' in patch) {
      const clean = sanitizeTemplates(patch.templates);
      if (clean !== null) templatesByUser[owner] = clean;
    }
    if ('soundVolume' in patch) {
      const vol = sanitizeVolume(patch.soundVolume);
      if (vol !== null) soundVolumeByUser[owner] = vol;
    }
  }
  const nextStored = { hideRecruitment, templatesByUser, soundVolumeByUser };
  // Keep the old shared list only as a migration seed for users who have not
  // created a personal list yet. It is never changed by new template edits.
  const legacyTemplates = sanitizeTemplates(stored.templates);
  if (legacyTemplates !== null) nextStored.templates = legacyTemplates;
  // Likewise, retain the former team volume only as an initial value for users
  // who have not chosen a personal volume yet.
  const legacyVolume = sanitizeVolume(stored.soundVolume);
  if (legacyVolume !== null) nextStored.soundVolume = legacyVolume;
  const tmp = `${FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(nextStored, null, 0), 'utf8');
  fs.renameSync(tmp, FILE);
  return readSettings(userKey);
}
