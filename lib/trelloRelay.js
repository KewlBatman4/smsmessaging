/**
 * Inbound self-SMS on TRELLO_RELAY_E164 carrying a structured body so the web inbox
 * can show a customer thread without writing to Twilio Conversations (no SMS relay).
 *
 * Format:
 *   &&FROM +61xxxxxxxx&&
 *
 *   (customer message text)
 *
 *   && REPLY &&
 *
 *   (your reply text)
 */

import { toE164Australian } from './phone.js';

const threads = new Map();

function randomSuffix() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

/** SMS / rich text often uses Unicode apostrophes; normalize for bracket matching. */
function normalizeRelaySmsInput(raw) {
  return String(raw || '')
    .replace(/\uFEFF/g, '')
    .replace(/[\u200B-\u200D]/g, '')
    .replace(/\u00A0/g, ' ')
    .replace(/[\u2018\u2019\u201A\u201B\u2032\u2035]/g, "'");
}

/** Strip Trello-style `['one line']` or `["..."]` around reply text. */
export function normalizeRelayReplyText(replyRaw) {
  let t = normalizeRelaySmsInput(replyRaw).trim();
  if (t.startsWith("['") && t.endsWith("']")) return t.slice(2, -2).trim();
  if (t.startsWith('["') && t.endsWith('"]')) return t.slice(2, -2).trim();
  if (t.startsWith('[') && t.endsWith(']')) {
    t = t.slice(1, -1).trim();
    if (
      (t.startsWith("'") && t.endsWith("'")) ||
      (t.startsWith('"') && t.endsWith('"'))
    ) {
      return t.slice(1, -1).trim();
    }
    return t;
  }
  return t;
}

/** A real relay payload is a single SMS; cap input so the regexes below can't
 *  be made to stall the event loop on a large (e.g. forged) body. */
const MAX_RELAY_BODY_LEN = 8000;

export function parseTrelloRelaySmsBody(raw) {
  let body = normalizeRelaySmsInput(raw).trim();
  if (body.length > MAX_RELAY_BODY_LEN) body = body.slice(0, MAX_RELAY_BODY_LEN);
  body = body.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  // The capture group is bounded ({1,40}) and lazy, and starts with +/digit so
  // it doesn't overlap the preceding \s+. Without this, `\s+` and an unbounded
  // `[\d\s]+` over a long whitespace run cause catastrophic backtracking
  // (a forged body could stall the event loop for minutes).
  const fromMatch = body.match(/&&\s*FROM\s+(\+?[\d][\d\s]{0,40}?)&&/i);
  if (!fromMatch) return null;
  const afterFrom = body.slice(fromMatch.index + fromMatch[0].length).trim();
  // SMS / Studio sometimes collapse newlines to spaces; do not require \n before && REPLY &&.
  // Leading/trailing \s* dropped (parts are trimmed below) so a whitespace run
  // before the marker can't trigger O(n^2) scanning.
  const parts = afterFrom.split(/&&\s*REPLY\s*&&/i);
  if (parts.length < 2) return null;
  const fromBody = parts[0].trim();
  const replyBody = normalizeRelayReplyText(parts.slice(1).join('\n').trim());
  const digits = fromMatch[1].replace(/\s/g, '');
  const parsed = toE164Australian(digits.startsWith('+') ? digits : `+${digits}`);
  if (!parsed.ok) return null;
  return {
    customerE164: parsed.e164,
    fromBody,
    replyBody,
  };
}

/**
 * Same parse, plus fields Twilio Studio HTTP widgets can use directly.
 */
export function parseRelayPayloadForStudio(raw) {
  const p = parseTrelloRelaySmsBody(raw);
  if (!p) return null;
  return {
    customerE164: p.customerE164,
    friendlyName: p.customerE164,
    inboundBody: p.fromBody,
    replyBody: p.replyBody,
  };
}

export function appendTrelloRelayMessages(customerE164, fromBody, replyBody) {
  const t = randomSuffix();
  const now = Date.now();
  const row = threads.get(customerE164) || { messages: [] };
  row.messages.push({
    sid: `${t}-in`,
    author: 'relay-customer',
    body: fromBody,
    dateCreated: new Date(now),
    attributes: { fromAddress: customerE164 },
  });
  row.messages.push({
    sid: `${t}-out`,
    author: 'system',
    body: replyBody,
    dateCreated: new Date(now + 1),
    attributes: { pbsgOutbound: true },
  });
  row.updated = new Date(now + 1);
  threads.set(customerE164, row);
}

export function listTrelloRelayThreads() {
  const out = [];
  for (const [customerE164, row] of threads) {
    const last = row.messages[row.messages.length - 1];
    out.push({
      customerE164,
      lastMessageBody: last?.body || '',
      updated: (row.updated || last?.dateCreated || new Date()).toISOString(),
      messageCount: row.messages.length,
    });
  }
  out.sort((a, b) => String(b.updated).localeCompare(String(a.updated)));
  return out;
}

export function getTrelloRelayThread(customerE164) {
  const row = threads.get(customerE164);
  if (!row) return { messages: [] };
  const messages = row.messages.map((m) => ({
    sid: m.sid,
    author: m.author,
    body: m.body,
    dateCreated: m.dateCreated.toISOString(),
    attributes: m.attributes,
  }));
  return { messages };
}
