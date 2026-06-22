import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseTrelloRelaySmsBody, normalizeRelayReplyText } from '../lib/trelloRelay.js';

test('parses FROM + REPLY payload', () => {
  const p = parseTrelloRelaySmsBody('&&FROM +61412345678&&\nhi there\n&& REPLY &&\nthanks!');
  assert.equal(p.customerE164, '+61412345678');
  assert.equal(p.fromBody, 'hi there');
  assert.equal(p.replyBody, 'thanks!');
});

test('parses a phone number written with spaces', () => {
  const p = parseTrelloRelaySmsBody('&&FROM +61 412 345 678&&\nhi\n&& REPLY &&\nok');
  assert.equal(p.customerE164, '+61412345678');
});

test('returns null when markers are missing', () => {
  assert.equal(parseTrelloRelaySmsBody('just a normal message'), null);
  assert.equal(parseTrelloRelaySmsBody('&&FROM +61412345678&& no reply marker'), null);
});

test('strips Trello-style brackets around reply text', () => {
  assert.equal(normalizeRelayReplyText("['hello']"), 'hello');
  assert.equal(normalizeRelayReplyText('["hello"]'), 'hello');
  assert.equal(normalizeRelayReplyText('plain'), 'plain');
});

test('large all-whitespace body returns quickly without hanging', () => {
  const huge = '&&FROM ' + ' '.repeat(200000) + '&&'; // no REPLY marker -> null
  const start = process.hrtime.bigint();
  const p = parseTrelloRelaySmsBody(huge);
  const ms = Number(process.hrtime.bigint() - start) / 1e6;
  assert.equal(p, null);
  assert.ok(ms < 250, `parse took ${ms}ms (should be bounded)`);
});
