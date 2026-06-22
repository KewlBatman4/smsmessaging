import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Isolate the store in a temp dir BEFORE importing the module (it reads
// CONTACT_LABELS_DIR at load time). Never touches real data.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pbsg-labels-'));
process.env.CONTACT_LABELS_DIR = dir;
const FILE = path.join(dir, 'contact-labels.json');
const { readAllContactLabels, upsertContactLabel, removeContactLabel } = await import(
  '../lib/contactLabels.js'
);

const SID = 'CH' + 'a'.repeat(32);
const SID2 = 'CH' + 'b'.repeat(32);

test('upsert + read roundtrip', () => {
  const r = upsertContactLabel(SID, { name: 'Liz', details: "Emily's Mum" });
  assert.deepEqual(r, { name: 'Liz', details: "Emily's Mum" });
  assert.deepEqual(readAllContactLabels()[SID], { name: 'Liz', details: "Emily's Mum" });
});

test('empty name+details removes entry', () => {
  upsertContactLabel(SID, { name: '  ', details: '' });
  assert.equal(SID in readAllContactLabels(), false);
});

test('removeContactLabel removes entry', () => {
  upsertContactLabel(SID, { name: 'Temp', details: '' });
  removeContactLabel(SID);
  assert.equal(SID in readAllContactLabels(), false);
});

test('rejects non-SID keys (prototype pollution / garbage)', () => {
  assert.throws(() => upsertContactLabel('__proto__', { name: 'x' }), /Conversation SID/);
  assert.throws(() => upsertContactLabel('not-a-sid', { name: 'x' }), /Conversation SID/);
  assert.throws(() => upsertContactLabel('CHshort', { name: 'x' }), /Conversation SID/);
  assert.equal({}.polluted, undefined); // Object.prototype intact
});

test('length caps reject oversized name/details', () => {
  assert.throws(() => upsertContactLabel(SID, { name: 'x'.repeat(201) }), /name too long/);
  assert.throws(() => upsertContactLabel(SID, { details: 'y'.repeat(2001) }), /details too long/);
});

test('atomic write leaves no .tmp file and valid JSON', () => {
  upsertContactLabel(SID2, { name: 'Bob', details: '' });
  assert.equal(fs.existsSync(FILE + '.tmp'), false);
  assert.doesNotThrow(() => JSON.parse(fs.readFileSync(FILE, 'utf8')));
});

test('corrupt file is surfaced, not silently wiped', () => {
  fs.writeFileSync(FILE, '{ this is not valid json', 'utf8');
  assert.throws(() => readAllContactLabels(), /corrupt/);
  // an upsert must also throw, so it does NOT overwrite/wipe the corrupt file
  assert.throws(() => upsertContactLabel(SID, { name: 'z' }), /corrupt/);
  // content preserved for recovery
  assert.equal(fs.readFileSync(FILE, 'utf8'), '{ this is not valid json');
});
