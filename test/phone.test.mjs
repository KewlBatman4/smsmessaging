import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toE164Australian } from '../lib/phone.js';

const ok = (input, e164) =>
  test(`"${input}" -> ${e164}`, () => {
    const r = toE164Australian(input);
    assert.equal(r.ok, true, r.error);
    assert.equal(r.e164, e164);
  });

const bad = (input) =>
  test(`"${input}" -> rejected`, () => {
    assert.equal(toE164Australian(input).ok, false);
  });

// Valid AU formats — MUST be unchanged by the fix
ok('0412345678', '+61412345678');
ok('0412 345 678', '+61412345678');
ok('+61412345678', '+61412345678');
ok('61412345678', '+61412345678');
ok('412345678', '+61412345678'); // 9-digit mobile, no leading 0
ok('0298765432', '+61298765432'); // AU landline

// International number with country code, pasted without + (best effort, kept)
ok('+1 415 555 1234', '+14155551234');
ok('14155551234', '+14155551234');

// FIXED: Australian international dialling prefixes (were mangled before)
ok('0061412345678', '+61412345678'); // 00 + 61...  (was +61061412345678)
ok('0061 412 345 678', '+61412345678');
ok('001114155551234', '+14155551234'); // 0011 (AU IDD) + 1 (US) + national
ok('0011 1 415 555 1234', '+14155551234');

// Rejected: empty / too short / absurdly long (> E.164 max 15 digits)
bad('');
bad('   ');
bad('12345');
bad('12345678901234567'); // 17 digits
bad(null);
