import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pbsg-settings-'));
process.env.CONTACT_LABELS_DIR = dir;
const { readSettings, updateSettings } = await import('../lib/appSettings.js');

test('defaults when no file exists', () => {
  assert.deepEqual(readSettings(), { hideRecruitment: false });
});

test('update persists and coerces to boolean', () => {
  const r = updateSettings({ hideRecruitment: 'yes' });
  assert.equal(r.hideRecruitment, true);
  assert.equal(readSettings().hideRecruitment, true);
  updateSettings({ hideRecruitment: false });
  assert.equal(readSettings().hideRecruitment, false);
});

test('ignores unknown keys', () => {
  updateSettings({ hideRecruitment: true, evil: '__proto__' });
  const s = readSettings();
  assert.deepEqual(Object.keys(s), ['hideRecruitment']);
  assert.equal(s.hideRecruitment, true);
});

test('corrupt file falls back to defaults (settings are non-critical)', () => {
  fs.writeFileSync(path.join(dir, 'app-settings.json'), '{not json', 'utf8');
  assert.deepEqual(readSettings(), { hideRecruitment: false });
});
