import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MISSED_CALL_SMS_COOLDOWN_MS,
  evaluateMissedCall,
  parseConversationAttributes,
  withAutoSmsFields,
  withMissedCallMarker,
} from '../lib/missedCall.js';

const NOW = Date.parse('2026-07-18T03:00:00.000Z');
const iso = (ms) => new Date(ms).toISOString();
const attrsWith = (pbsgMissedCall) => JSON.stringify({ keep: 'me', pbsgMissedCall });

test('parseConversationAttributes: junk inputs -> {}', () => {
  assert.deepEqual(parseConversationAttributes(null), {});
  assert.deepEqual(parseConversationAttributes(''), {});
  assert.deepEqual(parseConversationAttributes('not json'), {});
  assert.deepEqual(parseConversationAttributes('[1,2]'), {});
  assert.deepEqual(parseConversationAttributes('"str"'), {});
  assert.deepEqual(parseConversationAttributes({ a: 1 }), { a: 1 });
  assert.deepEqual(parseConversationAttributes('{"a":1}'), { a: 1 });
});

test('first missed call ever: send allowed', () => {
  const r = evaluateMissedCall('{}', { callSid: 'CA1', now: NOW });
  assert.deepEqual(r, { deduped: false, canSendSms: true, skipReason: null, nextAllowedAt: null });
});

test('same CallSid twice: deduped, no send', () => {
  const raw = attrsWith({ lastCallSid: 'CA1', lastMissedCallAt: iso(NOW - 1000) });
  const r = evaluateMissedCall(raw, { callSid: 'CA1', now: NOW });
  assert.equal(r.deduped, true);
  assert.equal(r.canSendSms, false);
  assert.equal(r.skipReason, 'duplicate_call');
});

test('missing CallSid never dedupes', () => {
  const raw = attrsWith({ lastCallSid: '', lastMissedCallAt: iso(NOW - 1000) });
  const r = evaluateMissedCall(raw, { callSid: '', now: NOW });
  assert.equal(r.deduped, false);
  assert.equal(r.canSendSms, true);
});

test('sent 1ms under 7 days ago: blocked with nextAllowedAt', () => {
  const sentAt = NOW - MISSED_CALL_SMS_COOLDOWN_MS + 1;
  const raw = attrsWith({ autoSmsLastSentAt: iso(sentAt) });
  const r = evaluateMissedCall(raw, { callSid: 'CA2', now: NOW });
  assert.equal(r.canSendSms, false);
  assert.equal(r.skipReason, 'cooldown');
  assert.equal(r.nextAllowedAt, iso(sentAt + MISSED_CALL_SMS_COOLDOWN_MS));
});

test('sent exactly 7 days ago: allowed again ("at least 7 days")', () => {
  const raw = attrsWith({ autoSmsLastSentAt: iso(NOW - MISSED_CALL_SMS_COOLDOWN_MS) });
  const r = evaluateMissedCall(raw, { callSid: 'CA2', now: NOW });
  assert.equal(r.canSendSms, true);
  assert.equal(r.skipReason, null);
});

test('garbled autoSmsLastSentAt does not block sending', () => {
  const raw = attrsWith({ autoSmsLastSentAt: 'yesterday-ish' });
  const r = evaluateMissedCall(raw, { callSid: 'CA2', now: NOW });
  assert.equal(r.canSendSms, true);
});

test('cooldown applies across different CallSids (per-number, not per-call)', () => {
  const raw = attrsWith({
    lastCallSid: 'CA1',
    autoSmsLastSentAt: iso(NOW - 3 * 24 * 60 * 60 * 1000), // 3 days ago
  });
  const r = evaluateMissedCall(raw, { callSid: 'CA9', now: NOW });
  assert.equal(r.deduped, false);
  assert.equal(r.canSendSms, false);
  assert.equal(r.skipReason, 'cooldown');
});

test('withMissedCallMarker: records call, preserves other attrs and guard fields', () => {
  const raw = attrsWith({ autoSmsLastSentAt: iso(NOW - 1000), autoSmsLastCallSid: 'CA0' });
  const out = withMissedCallMarker(raw, { callSid: 'CA5', now: NOW });
  assert.equal(out.keep, 'me');
  assert.equal(out.pbsgMissedCall.lastCallSid, 'CA5');
  assert.equal(out.pbsgMissedCall.lastMissedCallAt, iso(NOW));
  assert.equal(out.pbsgMissedCall.autoSmsLastSentAt, iso(NOW - 1000));
  assert.equal(out.pbsgMissedCall.autoSmsLastCallSid, 'CA0');
});

test('withMissedCallMarker: empty callSid stored as null', () => {
  const out = withMissedCallMarker('{}', { callSid: '  ', now: NOW });
  assert.equal(out.pbsgMissedCall.lastCallSid, null);
});

test('withAutoSmsFields: reservation sets guard fields', () => {
  const marker = withMissedCallMarker(attrsWith({}), { callSid: 'CA5', now: NOW });
  const out = withAutoSmsFields(marker, { lastSentAt: iso(NOW), lastCallSid: 'CA5' });
  assert.equal(out.keep, 'me');
  assert.equal(out.pbsgMissedCall.lastCallSid, 'CA5');
  assert.equal(out.pbsgMissedCall.autoSmsLastSentAt, iso(NOW));
  assert.equal(out.pbsgMissedCall.autoSmsLastCallSid, 'CA5');
});

test('withAutoSmsFields: rollback restores previous values', () => {
  const reserved = withAutoSmsFields(attrsWith({ lastCallSid: 'CA5' }), {
    lastSentAt: iso(NOW),
    lastCallSid: 'CA5',
  });
  const prevSentAt = iso(NOW - 10 * 24 * 60 * 60 * 1000);
  const rolledBack = withAutoSmsFields(reserved, { lastSentAt: prevSentAt, lastCallSid: 'CA0' });
  assert.equal(rolledBack.pbsgMissedCall.autoSmsLastSentAt, prevSentAt);
  assert.equal(rolledBack.pbsgMissedCall.autoSmsLastCallSid, 'CA0');
  assert.equal(rolledBack.pbsgMissedCall.lastCallSid, 'CA5');
});

test('withAutoSmsFields: rollback with no prior send clears guard fields', () => {
  const reserved = withAutoSmsFields(attrsWith({}), { lastSentAt: iso(NOW), lastCallSid: 'CA5' });
  const rolledBack = withAutoSmsFields(reserved, { lastSentAt: null, lastCallSid: null });
  assert.equal('autoSmsLastSentAt' in rolledBack.pbsgMissedCall, false);
  assert.equal('autoSmsLastCallSid' in rolledBack.pbsgMissedCall, false);
  // after rollback a fresh evaluation must allow sending again
  const r = evaluateMissedCall(JSON.stringify(rolledBack), { callSid: 'CA6', now: NOW });
  assert.equal(r.canSendSms, true);
});
