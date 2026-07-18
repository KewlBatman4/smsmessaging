import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pbsg-settings-'));
process.env.CONTACT_LABELS_DIR = dir;
const { readSettings, updateSettings } = await import('../lib/appSettings.js');

test('defaults: hideRecruitment false + seeded templates + moderate volume', () => {
  const s = readSettings('mylene');
  assert.equal(s.hideRecruitment, false);
  assert.ok(Array.isArray(s.templates) && s.templates.length >= 1);
  assert.ok(s.templates.every((t) => t.id && typeof t.name === 'string' && typeof t.text === 'string'));
  assert.equal(s.soundVolume, 0.7);
});

test('update hideRecruitment persists, coerces to boolean, keeps templates', () => {
  const r = updateSettings({ hideRecruitment: 'yes' }, 'mylene');
  assert.equal(r.hideRecruitment, true);
  assert.equal(readSettings().hideRecruitment, true);
  assert.ok(readSettings().templates.length >= 1); // templates untouched
  updateSettings({ hideRecruitment: false });
  assert.equal(readSettings().hideRecruitment, false);
});

test('templates: save, clamp, and round-trip per user', () => {
  const defaults = readSettings('mylene').templates;
  updateSettings(
    { templates: [{ id: 'a', name: 'Custom', text: 'Hi {name}, {me} here' }] },
    'matt'
  );
  const s = readSettings('matt');
  assert.deepEqual(s.templates, [{ id: 'a', name: 'Custom', text: 'Hi {name}, {me} here' }]);
  assert.deepEqual(readSettings('mylene').templates, defaults);
  assert.equal(s.hideRecruitment, false); // templates-only update did not reset it
});

test('templates: empty array is respected (user deleted all)', () => {
  updateSettings({ templates: [] }, 'mylene');
  assert.deepEqual(readSettings('mylene').templates, []);
  assert.equal(readSettings('matt').templates.length, 1);
});

test('soundVolume: save, clamp, and round-trip per user; 0 = muted', () => {
  updateSettings({ soundVolume: 0.42 }, 'matt');
  assert.equal(readSettings('matt').soundVolume, 0.42);
  assert.equal(readSettings('mylene').soundVolume, 0.7);
  // clamps out-of-range
  updateSettings({ soundVolume: 2 }, 'matt');
  assert.equal(readSettings('matt').soundVolume, 1);
  updateSettings({ soundVolume: -3 }, 'matt');
  assert.equal(readSettings('matt').soundVolume, 0); // muted persists, not coerced to a default
  // a soundVolume-only update leaves other keys alone
  updateSettings({ hideRecruitment: true });
  updateSettings({ soundVolume: 0.5 }, 'matt');
  assert.equal(readSettings().hideRecruitment, true);
  updateSettings({ hideRecruitment: false });
});

test('soundVolume: non-numeric / coercible junk is ignored (never silently mutes/maxes)', () => {
  updateSettings({ soundVolume: 0.33 }, 'matt');
  // Each of these would Number()-coerce to 0 or 1 — they must be REJECTED so a
  // malformed write cannot mute or max the shared setting for everyone.
  for (const junk of ['loud', null, '', '   ', [], [0.5], false, true, {}, NaN, Infinity]) {
    updateSettings({ soundVolume: junk }, 'matt');
    assert.equal(readSettings('matt').soundVolume, 0.33, `should ignore ${JSON.stringify(junk)}`);
  }
  // A numeric string is still accepted.
  updateSettings({ soundVolume: '0.5' }, 'matt');
  assert.equal(readSettings('matt').soundVolume, 0.5);
});

test('settings object only exposes known keys', () => {
  updateSettings({ hideRecruitment: true, evil: '__proto__' });
  assert.deepEqual(Object.keys(readSettings()).sort(), ['hideRecruitment', 'soundVolume', 'templates']);
});

test('legacy shared templates seed each user without linking their later edits', () => {
  const file = path.join(dir, 'app-settings.json');
  const legacy = [{ id: 'legacy', name: 'Old shared template', text: 'Hello' }];
  fs.writeFileSync(file, JSON.stringify({ templates: legacy, soundVolume: 0.7 }), 'utf8');

  assert.deepEqual(readSettings('matt').templates, legacy);
  assert.deepEqual(readSettings('mylene').templates, legacy);

  const personal = [{ id: 'mine', name: 'Matt only', text: 'Personal text' }];
  updateSettings({ templates: personal }, 'matt');
  updateSettings({ soundVolume: 0.2 }, 'matt');
  assert.deepEqual(readSettings('matt').templates, personal);
  assert.equal(readSettings('matt').soundVolume, 0.2);
  assert.deepEqual(readSettings('mylene').templates, legacy);
  assert.equal(readSettings('mylene').soundVolume, 0.7);
  const persisted = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.deepEqual(persisted.templates, legacy);
  assert.equal(persisted.soundVolume, 0.7);
});

test('corrupt file falls back to defaults (non-critical)', () => {
  fs.writeFileSync(path.join(dir, 'app-settings.json'), '{not json', 'utf8');
  const s = readSettings();
  assert.equal(s.hideRecruitment, false);
  assert.ok(s.templates.length >= 1);
});
