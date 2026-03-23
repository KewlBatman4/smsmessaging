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

export function parseTrelloRelaySmsBody(raw) {
  const body = String(raw || '').trim();
  const fromMatch = body.match(/&&\s*FROM\s+(\+?[\d\s]+)&&/i);
  if (!fromMatch) return null;
  const afterFrom = body.slice(fromMatch.index + fromMatch[0].length).trim();
  const parts = afterFrom.split(/\n\s*&&\s*REPLY\s*&&\s*/i);
  if (parts.length < 2) return null;
  const fromBody = parts[0].trim();
  const replyBody = parts.slice(1).join('\n').trim();
  const digits = fromMatch[1].replace(/\s/g, '');
  const parsed = toE164Australian(digits.startsWith('+') ? digits : `+${digits}`);
  if (!parsed.ok) return null;
  return {
    customerE164: parsed.e164,
    fromBody,
    replyBody,
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
