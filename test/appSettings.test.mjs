import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pbsg-settings-'));
process.env.CONTACT_LABELS_DIR = dir;
const { readSettings, updateSettings } = await import('../lib/appSettings.js');

test('defaults: hideRecruitment false + seeded templates + moderate volume', () => {
  const s = readSettings();
  assert.equal(s.hideRecruitment, false);
  assert.ok(Array.isArray(s.templates) && s.templates.length >= 1);
  assert.ok(s.templates.every((t) => t.id && typeof t.name === 'string' && typeof t.text === 'string'));
  assert.equal(s.soundVolume, 0.7);
});

test('update hideRecruitment persists, coerces to boolean, keeps templates', () => {
  const r = updateSettings({ hideRecruitment: 'yes' });
  assert.equal(r.hideRecruitment, true);
  assert.equal(readSettings().hideRecruitment, true);
  assert.ok(readSettings().templates.length >= 1); // templates untouched
  updateSettings({ hideRecruitment: false });
  assert.equal(readSettings().hideRecruitment, false);
});

test('templates: save, clamp, and round-trip', () => {
  updateSettings({ templates: [{ id: 'a', name: 'Custom', text: 'Hi {name}, {me} here' }] });
  const s = readSettings();
  assert.deepEqual(s.templates, [{ id: 'a', name: 'Custom', text: 'Hi {name}, {me} here' }]);
  assert.equal(s.hideRecruitment, false); // templates-only update did not reset it
});

test('templates: empty array is respected (user deleted all)', () => {
  updateSettings({ templates: [] });
  assert.deepEqual(readSettings().templates, []);
});

test('soundVolume: save, clamp to [0,1], and round-trip; 0 = muted', () => {
  updateSettings({ soundVolume: 0.42 });
  assert.equal(readSettings().soundVolume, 0.42);
  // clamps out-of-range
  updateSettings({ soundVolume: 2 });
  assert.equal(readSettings().soundVolume, 1);
  updateSettings({ soundVolume: -3 });
  assert.equal(readSettings().soundVolume, 0); // muted persists, not coerced to a default
  // a soundVolume-only update leaves other keys alone
  updateSettings({ hideRecruitment: true });
  updateSettings({ soundVolume: 0.5 });
  assert.equal(readSettings().hideRecruitment, true);
  updateSettings({ hideRecruitment: false });
});

test('soundVolume: non-numeric input is ignored (keeps prior value)', () => {
  updateSettings({ soundVolume: 0.33 });
  updateSettings({ soundVolume: 'loud' });
  assert.equal(readSettings().soundVolume, 0.33);
});

test('settings object only exposes known keys', () => {
  updateSettings({ hideRecruitment: true, evil: '__proto__' });
  assert.deepEqual(Object.keys(readSettings()).sort(), ['hideRecruitment', 'soundVolume', 'templates']);
});

test('corrupt file falls back to defaults (non-critical)', () => {
  fs.writeFileSync(path.join(dir, 'app-settings.json'), '{not json', 'utf8');
  const s = readSettings();
  assert.equal(s.hideRecruitment, false);
  assert.ok(s.templates.length >= 1);
});
