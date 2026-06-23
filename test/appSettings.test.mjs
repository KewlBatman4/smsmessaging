import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pbsg-settings-'));
process.env.CONTACT_LABELS_DIR = dir;
const { readSettings, updateSettings } = await import('../lib/appSettings.js');

test('defaults: hideRecruitment false + seeded templates', () => {
  const s = readSettings();
  assert.equal(s.hideRecruitment, false);
  assert.ok(Array.isArray(s.templates) && s.templates.length >= 1);
  assert.ok(s.templates.every((t) => t.id && typeof t.name === 'string' && typeof t.text === 'string'));
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

test('settings object only exposes known keys', () => {
  updateSettings({ hideRecruitment: true, evil: '__proto__' });
  assert.deepEqual(Object.keys(readSettings()).sort(), ['hideRecruitment', 'templates']);
});

test('corrupt file falls back to defaults (non-critical)', () => {
  fs.writeFileSync(path.join(dir, 'app-settings.json'), '{not json', 'utf8');
  const s = readSettings();
  assert.equal(s.hideRecruitment, false);
  assert.ok(s.templates.length >= 1);
});
