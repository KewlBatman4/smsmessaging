import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import twilio from 'twilio';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { toE164Australian } from './lib/phone.js';

const { AccessToken } = twilio.jwt;
const { ChatGrant } = AccessToken;

const PORT = Number(process.env.PORT) || 3001;
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const apiKey = process.env.TWILIO_API_KEY;
const apiSecret = process.env.TWILIO_API_SECRET;
const serviceSid = process.env.TWILIO_CONVERSATIONS_SERVICE_SID;
const twilioPhone = process.env.TWILIO_PHONE_NUMBER;

const sessionJwtSecret = process.env.SESSION_JWT_SECRET;
const appPasswordHash = process.env.APP_PASSWORD_HASH;
const sessionMaxAgeSec = Number(process.env.SESSION_MAX_AGE_SECONDS) || 604800; // 7 days
/** Single Twilio chat identity for this inbox (alphanumeric + underscore/hyphen). */
const twilioChatIdentity = (process.env.TWILIO_CONVERSATIONS_IDENTITY || 'pbsg-inbox').trim();

function validateTwilioIdentity(identity) {
  if (!identity || identity.length < 1 || identity.length > 64) {
    return { ok: false, error: 'TWILIO_CONVERSATIONS_IDENTITY must be 1–64 characters.' };
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(identity)) {
    return {
      ok: false,
      error:
        'TWILIO_CONVERSATIONS_IDENTITY may only contain letters, numbers, underscores, and hyphens.',
    };
  }
  return { ok: true, identity };
}

function requireEnv() {
  const missing = [];
  if (!accountSid) missing.push('TWILIO_ACCOUNT_SID');
  if (!apiKey) missing.push('TWILIO_API_KEY');
  if (!apiSecret) missing.push('TWILIO_API_SECRET');
  if (!serviceSid) missing.push('TWILIO_CONVERSATIONS_SERVICE_SID');
  if (!twilioPhone) missing.push('TWILIO_PHONE_NUMBER');
  if (!sessionJwtSecret || sessionJwtSecret.length < 32) {
    console.error(
      'SESSION_JWT_SECRET is required and must be at least 32 characters (use a long random string).'
    );
    process.exit(1);
  }
  if (!appPasswordHash || !appPasswordHash.startsWith('$2')) {
    console.error(
      'APP_PASSWORD_HASH is required (bcrypt hash). Run: npm run hash-password'
    );
    process.exit(1);
  }
  const idv = validateTwilioIdentity(twilioChatIdentity);
  if (!idv.ok) {
    console.error(idv.error);
    process.exit(1);
  }
  if (missing.length) {
    console.error('Missing env:', missing.join(', '));
    process.exit(1);
  }
}

requireEnv();

const twilioClient = twilio(apiKey, apiSecret, { accountSid });
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN;

/** Browser Origin never has a trailing slash; strip so CORS matches Netlify exactly. */
function corsOriginOption() {
  const raw = process.env.CORS_ORIGIN;
  if (!raw?.trim()) return true;
  return raw
    .split(',')
    .map((s) => s.trim().replace(/\/+$/, ''))
    .filter(Boolean);
}

/**
 * Inbound SMS / autocreated Conversations often only have an SMS participant.
 * Without this chat participant, the web app (same identity as the token) never sees the thread.
 */
async function ensureChatParticipantInConversation(conversationSid) {
  try {
    await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(conversationSid)
      .participants.create({ identity: twilioChatIdentity });
  } catch (err) {
    const code = err?.code;
    const msg = String(err?.message || '').toLowerCase();
    if (
      code === 409 ||
      code === 50215 ||
      msg.includes('already exists') ||
      msg.includes('duplicate') ||
      msg.includes('is already')
    ) {
      return;
    }
    throw err;
  }
}

function validateTwilioWebhookSignature(req) {
  if (!twilioAuthToken) {
    console.warn(
      'TWILIO_AUTH_TOKEN not set; Twilio webhook signature verification is disabled.'
    );
    return true;
  }
  const sig = req.headers['x-twilio-signature'];
  if (!sig) return false;
  const url = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  return twilio.validateRequest(twilioAuthToken, sig, url, req.body);
}

function proxyNumberE164() {
  const t = twilioPhone.trim();
  return t.startsWith('+') ? t : `+${t.replace(/\D/g, '')}`;
}

function digitsOnly(phone) {
  return String(phone || '').replace(/\D/g, '');
}

function fromMatchesOurTwilioNumber(from) {
  return digitsOnly(from) === digitsOnly(twilioPhone);
}

/** Extra "From" numbers treated as this inbox (Messaging Service pool, secondary long codes). */
const ourSenderDigitSets = (process.env.TWILIO_SMS_FROM_ALIASES || '')
  .split(',')
  .map((s) => digitsOnly(s))
  .filter(Boolean);

function fromMatchesAnyOurSender(from) {
  if (fromMatchesOurTwilioNumber(from)) return true;
  const d = digitsOnly(from);
  return ourSenderDigitSets.some((x) => x === d);
}

/** E.164 for every number we send SMS from (primary + TWILIO_SMS_FROM_ALIASES). */
function collectOurOutboundSenderE164List() {
  const out = [proxyNumberE164()];
  const raw = (process.env.TWILIO_SMS_FROM_ALIASES || '').split(',');
  for (const part of raw) {
    const t = part.trim();
    if (!t) continue;
    let e164 = null;
    if (t.startsWith('+')) {
      e164 = `+${digitsOnly(t)}`;
    } else {
      const p = toE164Australian(t);
      e164 = p.ok ? p.e164 : null;
      if (!e164 && digitsOnly(t).length >= 10) e164 = `+${digitsOnly(t)}`;
    }
    if (e164 && digitsOnly(e164).length >= 10) out.push(e164);
  }
  return [...new Set(out)];
}

/**
 * Use Twilio Message `direction` when present; else From/To vs our senders.
 * Prefer classifyBySmsLogQuery() during sync — it uses which API query returned the SID.
 */
function classifyProgrammableSms(sm) {
  const d = String(sm.direction || '').trim().toLowerCase();
  const from = rawPhoneFromTwilioAddr(sm.from);
  const to = rawPhoneFromTwilioAddr(sm.to);

  if (d === 'inbound' && from) {
    return { kind: 'inbound', customer: from };
  }
  if (
    (d === 'outbound-api' || d === 'outbound-call' || d === 'outbound-reply') &&
    to
  ) {
    return { kind: 'outbound', customer: to };
  }

  if (fromMatchesAnyOurSender(sm.from) && to) {
    return { kind: 'outbound', customer: to };
  }
  if (fromMatchesOurTwilioNumber(sm.to) && from) {
    return { kind: 'inbound', customer: from };
  }

  return { kind: 'unknown', customer: null };
}

/**
 * Definitive for sync: message was listed under To=our → inbound; under From=one-of-ours → outbound.
 * Fixes Zapier + Messaging Service when From is a pool number not in TWILIO_PHONE_NUMBER.
 */
function classifyBySmsLogQuery(sm, inboundSidSet, outboundSidSet) {
  const inIn = inboundSidSet.has(sm.sid);
  const inOut = outboundSidSet.has(sm.sid);
  if (inIn && !inOut) {
    return {
      kind: 'inbound',
      customer: rawPhoneFromTwilioAddr(sm.from),
    };
  }
  if (inOut && !inIn) {
    return {
      kind: 'outbound',
      customer: rawPhoneFromTwilioAddr(sm.to),
    };
  }
  if (inIn && inOut) {
    return classifyProgrammableSms(sm);
  }
  return { kind: 'unknown', customer: null };
}

/** Dedupe Programmable Messaging status callbacks (sent + delivered, retries). */
const mirroredProgrammableMessageSids = new Set();
const MIRROR_SID_CAP = 8000;
function rememberMirroredSid(sid) {
  mirroredProgrammableMessageSids.add(sid);
  if (mirroredProgrammableMessageSids.size > MIRROR_SID_CAP) {
    mirroredProgrammableMessageSids.clear();
  }
}

async function listParticipantConversationRowsForAddress(address) {
  const rows = [];
  let page = await twilioClient.conversations.v1
    .services(serviceSid)
    .participantConversations.page({ address, pageSize: 50 });
  for (;;) {
    rows.push(...page.instances);
    if (!page.nextPageUrl) break;
    page = await page.nextPage();
  }
  return rows;
}

function pickConversationSidForCustomer(rows) {
  const active = rows.filter((r) => r.conversationState !== 'closed');
  const pool = active.length ? active : rows;
  if (!pool.length) return null;
  pool.sort(
    (a, b) =>
      (b.conversationDateUpdated?.getTime?.() ?? 0) -
      (a.conversationDateUpdated?.getTime?.() ?? 0)
  );
  return pool[0].conversationSid || null;
}

/**
 * One E.164 form for the same mobile everywhere (lookup + messagingBinding).
 * Without this, +61… vs 61… vs 04… hits different ParticipantConversation rows and splits the sidebar.
 */
function canonicalCustomerE164(customerAddress) {
  if (!customerAddress || typeof customerAddress !== 'string') return null;
  const stripped =
    rawPhoneFromTwilioAddr(customerAddress.trim()) || customerAddress.trim();
  if (!stripped) return null;
  const parsed = toE164Australian(stripped);
  if (parsed.ok) return parsed.e164;
  const d = digitsOnly(stripped);
  if (d.length >= 10) return `+${d}`;
  return null;
}

/**
 * Create a new SMS conversation with chat + SMS participants (same as POST /api/conversations).
 */
async function createSmsConversationForCustomerE164(customerE164) {
  const proxy = proxyNumberE164();
  const conversation = await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations.create({
      friendlyName: `SMS ${customerE164}`,
    });
  const sid = conversation.sid;
  await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(sid)
    .participants.create({ identity: twilioChatIdentity });
  await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(sid)
    .participants.create({
      'messagingBinding.address': customerE164,
      'messagingBinding.proxyAddress': proxy,
    });
  return sid;
}

/**
 * Find an existing conversation for this customer address, or create one (Zapier-first outbound).
 * @returns {{ conversationSid: string, created: boolean }}
 */
async function findOrCreateConversationForCustomerAddress(customerAddress) {
  const e164 = canonicalCustomerE164(customerAddress);
  if (!e164) {
    throw new Error(`Invalid customer phone address: ${String(customerAddress)}`);
  }
  const raw =
    rawPhoneFromTwilioAddr(String(customerAddress).trim()) ||
    String(customerAddress).trim();
  const lookupAddresses = [e164];
  if (raw && raw !== e164 && !lookupAddresses.includes(raw)) {
    lookupAddresses.push(raw);
  }
  const d = digitsOnly(raw);
  const plusDigits = d.length >= 10 ? `+${d}` : null;
  if (plusDigits && !lookupAddresses.includes(plusDigits)) {
    lookupAddresses.push(plusDigits);
  }
  const rows = [];
  for (const addr of lookupAddresses) {
    rows.push(...(await listParticipantConversationRowsForAddress(addr)));
  }
  const existing = pickConversationSidForCustomer(rows);
  if (existing) return { conversationSid: existing, created: false };
  const sid = await createSmsConversationForCustomerE164(e164);
  return { conversationSid: sid, created: true };
}

function parseConversationAttributes(raw) {
  if (!raw || typeof raw !== 'string') return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function mirrorProgrammableOutboundToConversation(
  conversationSid,
  bodyText,
  messageSid,
  dateCreated
) {
  const attrs = JSON.stringify({
    pbsgOutbound: true,
    programmaticMessageSid: messageSid,
  });
  // Do not use the browser chat identity here: Twilio relays chat-participant messages as SMS.
  // Omit Author so Twilio defaults to system; the web app uses attributes.pbsgOutbound for the right bubble.
  const createParams = {
    body: bodyText,
    attributes: attrs,
    xTwilioWebhookEnabled: 'false',
  };
  if (dateCreated) createParams.dateCreated = dateCreated;
  await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(conversationSid)
    .messages.create(createParams);
}

async function mirrorProgrammableInboundToConversation(
  conversationSid,
  bodyText,
  messageSid,
  customerE164,
  dateCreated
) {
  const attrs = JSON.stringify({
    pbsgInbound: true,
    programmaticMessageSid: messageSid,
    fromAddress: customerE164,
  });
  const params = {
    author: 'system',
    body: bodyText,
    attributes: attrs,
  };
  if (dateCreated) params.dateCreated = dateCreated;
  params.xTwilioWebhookEnabled = 'false';
  await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(conversationSid)
    .messages.create(params);
}

function rawPhoneFromTwilioAddr(addr) {
  if (!addr || typeof addr !== 'string') return null;
  const s = addr.trim();
  if (s.toLowerCase().startsWith('whatsapp:')) {
    const rest = s.slice('whatsapp:'.length);
    return rest.split(':')[0]?.trim() || null;
  }
  if (/^[a-z]+:/i.test(s)) return null;
  return s;
}

async function conversationAlreadyHasMirroredProgrammableSid(conversationSid, smSid) {
  let page = await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(conversationSid)
    .messages.page({ order: 'desc', pageSize: 100 });
  for (let i = 0; i < 10; i++) {
    for (const msg of page.instances) {
      const a = parseConversationAttributes(msg.attributes);
      if (a?.programmaticMessageSid === smSid) return true;
    }
    if (!page.nextPageUrl) break;
    page = await page.nextPage();
  }
  return false;
}

/** Skip mirror when Conversations already has the same inbound from Twilio’s native SMS path. */
async function likelyNativeInboundDuplicate(conversationSid, bodyText, smDate) {
  const want = (bodyText || '').trim();
  if (!want) return false;
  const smT = smDate?.getTime?.() ?? 0;
  if (!smT) return false;
  const page = await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(conversationSid)
    .messages.page({ order: 'desc', pageSize: 40 });
  for (const msg of page.instances) {
    const a = parseConversationAttributes(msg.attributes);
    if (a?.programmaticMessageSid || a?.pbsgOutbound) continue;
    if ((msg.body || '').trim() !== want) continue;
    const t = msg.dateCreated?.getTime?.() ?? 0;
    if (t > 0 && Math.abs(t - smT) < 120_000) return true;
  }
  return false;
}

const SMS_LOG_MAX_PAGES_PER_DIRECTION = 60;

/** Set true by POST /api/sync-sms-log/cancel; cleared when a sync run finishes. */
let smsLogSyncCancelRequested = false;

async function pageAllProgrammableMessages(listParams, shouldCancel = () => false) {
  const out = [];
  if (shouldCancel()) return out;
  let page = await twilioClient.messages.page({
    ...listParams,
    pageSize: 100,
  });
  for (let i = 0; i < SMS_LOG_MAX_PAGES_PER_DIRECTION; i++) {
    if (shouldCancel()) return out;
    out.push(...page.instances);
    if (!page.nextPageUrl) break;
    if (shouldCancel()) return out;
    page = await page.nextPage();
  }
  return out;
}

/**
 * Pull Twilio Programmable Messaging (SMS log) and append missing rows into Conversations
 * so the web app can show traffic that never entered the Conversation service.
 */
async function syncProgrammableSmsLogIntoConversations(
  daysBack,
  shouldCancel = () => false,
  { maxMessages } = {}
) {
  const our = proxyNumberE164();
  const dateSentAfter = new Date(Date.now() - Math.min(Math.max(daysBack, 1), 90) * 86400000);
  /**
   * Outbound log mirror: OFF by default — importing outbound rows can surprise-bill if anything
   * misbehaves; use the programmable-messaging webhook + set SMS_LOG_SYNC_OUTBOUND_MIRROR=true when needed.
   */
  const outboundMirrorEnv = String(process.env.SMS_LOG_SYNC_OUTBOUND_MIRROR ?? 'false').toLowerCase();
  const allowOutboundMirror = ['true', '1', 'yes', 'on'].includes(outboundMirrorEnv);

  const ourSenders = collectOurOutboundSenderE164List();
  const toUs = await pageAllProgrammableMessages({ to: our, dateSentAfter }, shouldCancel);
  if (shouldCancel()) {
    return {
      imported: 0,
      skipped: 0,
      skippedOutboundPolicy: 0,
      outboundMirrorEnabled: allowOutboundMirror,
      programmableMirrorAuthor: 'system',
      scanned: 0,
      conversationsTouched: 0,
      cancelled: true,
    };
  }
  /** Sequential (not Promise.all) so cancel can land between sender queries. */
  const fromLists = [];
  for (const fromNum of ourSenders) {
    if (shouldCancel()) {
      return {
        imported: 0,
        skipped: 0,
        skippedOutboundPolicy: 0,
        outboundMirrorEnabled: allowOutboundMirror,
        programmableMirrorAuthor: 'system',
        scanned: 0,
        conversationsTouched: 0,
        cancelled: true,
      };
    }
    fromLists.push(
      await pageAllProgrammableMessages({ from: fromNum, dateSentAfter }, shouldCancel)
    );
  }
  if (shouldCancel()) {
    return {
      imported: 0,
      skipped: 0,
      skippedOutboundPolicy: 0,
      outboundMirrorEnabled: allowOutboundMirror,
      programmableMirrorAuthor: 'system',
      scanned: 0,
      conversationsTouched: 0,
      cancelled: true,
    };
  }

  const inboundSidSet = new Set(toUs.map((m) => m.sid));
  const outboundSidSet = new Set();
  for (const list of fromLists) {
    for (const m of list) outboundSidSet.add(m.sid);
  }

  const bySid = new Map();
  for (const m of toUs) bySid.set(m.sid, m);
  for (const list of fromLists) {
    for (const m of list) bySid.set(m.sid, m);
  }
  let merged = [...bySid.values()].sort(
    (a, b) => (a.dateSent?.getTime?.() ?? 0) - (b.dateSent?.getTime?.() ?? 0)
  );
  if (Number.isFinite(maxMessages) && maxMessages > 0) {
    const cap = Math.min(Math.floor(maxMessages), merged.length);
    merged = merged.slice(-cap);
  }

  let imported = 0;
  let skipped = 0;
  let skippedOutboundPolicy = 0;
  const convTouched = new Set();

  for (const sm of merged) {
    if (shouldCancel()) {
      return {
        imported,
        skipped,
        skippedOutboundPolicy,
        outboundMirrorEnabled: allowOutboundMirror,
        programmableMirrorAuthor: 'system',
        scanned: merged.length,
        conversationsTouched: convTouched.size,
        cancelled: true,
      };
    }
    const { kind, customer } = classifyBySmsLogQuery(sm, inboundSidSet, outboundSidSet);
    if (!customer || kind === 'unknown') {
      skipped++;
      continue;
    }

    let bodyText = sm.body != null ? String(sm.body) : '';
    if (!bodyText.trim() && (sm.numMedia ?? 0) > 0) bodyText = '[Media]';
    if (!bodyText.trim()) bodyText = ' ';

    try {
      if (shouldCancel()) {
        return {
          imported,
          skipped,
          skippedOutboundPolicy,
          outboundMirrorEnabled: allowOutboundMirror,
          programmableMirrorAuthor: 'system',
          scanned: merged.length,
          conversationsTouched: convTouched.size,
          cancelled: true,
        };
      }
      const { conversationSid: convSid } =
        await findOrCreateConversationForCustomerAddress(customer);
      if (shouldCancel()) {
        return {
          imported,
          skipped,
          skippedOutboundPolicy,
          outboundMirrorEnabled: allowOutboundMirror,
          programmableMirrorAuthor: 'system',
          scanned: merged.length,
          conversationsTouched: convTouched.size,
          cancelled: true,
        };
      }
      await ensureChatParticipantInConversation(convSid);
      convTouched.add(convSid);

      if (await conversationAlreadyHasMirroredProgrammableSid(convSid, sm.sid)) {
        skipped++;
        continue;
      }

      if (kind === 'outbound') {
        if (!allowOutboundMirror) {
          skippedOutboundPolicy++;
          skipped++;
          continue;
        }
        const skipWebDup = await recentChatAuthorMessageMatchesBody(
          convSid,
          bodyText,
          25_000
        );
        if (skipWebDup) {
          skipped++;
          continue;
        }
        if (shouldCancel()) {
          return {
            imported,
            skipped,
            skippedOutboundPolicy,
            outboundMirrorEnabled: allowOutboundMirror,
            programmableMirrorAuthor: 'system',
            scanned: merged.length,
            conversationsTouched: convTouched.size,
            cancelled: true,
          };
        }
        await mirrorProgrammableOutboundToConversation(
          convSid,
          bodyText,
          sm.sid,
          sm.dateSent
        );
      } else {
        const skipNative = await likelyNativeInboundDuplicate(convSid, bodyText, sm.dateSent);
        if (skipNative) {
          skipped++;
          continue;
        }
        if (shouldCancel()) {
          return {
            imported,
            skipped,
            skippedOutboundPolicy,
            outboundMirrorEnabled: allowOutboundMirror,
            programmableMirrorAuthor: 'system',
            scanned: merged.length,
            conversationsTouched: convTouched.size,
            cancelled: true,
          };
        }
        const parsed = toE164Australian(customer);
        const customerE164 = parsed.ok ? parsed.e164 : customer.trim();
        await mirrorProgrammableInboundToConversation(
          convSid,
          bodyText,
          sm.sid,
          customerE164,
          sm.dateSent
        );
      }
      imported++;
    } catch (e) {
      console.warn('sync sms log row failed', sm.sid, e?.message);
      skipped++;
    }
  }

  return {
    imported,
    skipped,
    skippedOutboundPolicy,
    outboundMirrorEnabled: allowOutboundMirror,
    /** Helps verify deploy: mirrors must use "system" or customers get duplicate SMS. */
    programmableMirrorAuthor: 'system',
    scanned: merged.length,
    conversationsTouched: convTouched.size,
    cancelled: false,
  };
}

/** Avoid duplicating messages the user just sent from the web app (same SMS hits this webhook). */
async function recentChatAuthorMessageMatchesBody(conversationSid, bodyText, windowMs) {
  const want = (bodyText || '').trim();
  if (!want) return false;
  const page = await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(conversationSid)
    .messages.page({ order: 'desc', pageSize: 25 });
  const now = Date.now();
  for (const msg of page.instances) {
    if (msg.author !== twilioChatIdentity) continue;
    if ((msg.body || '').trim() !== want) continue;
    const t = msg.dateCreated?.getTime?.() ?? 0;
    if (t > 0 && now - t >= 0 && now - t <= windowMs) return true;
  }
  return false;
}

const app = express();
app.set('trust proxy', 1);
app.use(
  cors({
    origin: corsOriginOption(),
    credentials: true,
  })
);

/**
 * Twilio Conversations post-action webhook: add browser identity to new conversations
 * (e.g. inbound SMS autocreate) so PBSG Messenger can load them.
 *
 * Console: your Conversation Service → Webhooks → Post-Event URL:
 *   https://YOUR-API/api/webhooks/twilio/conversations
 * Enable events: onConversationAdded, onMessageAdded (post-event URL must be public).
 * onMessageAdded covers SMS threads created before this app existed — each new inbound
 * message adds the browser identity so the inbox can subscribe.
 *
 * Also ensure inbound SMS can reach Conversations (see Twilio "Inbound autocreation"
 * and avoid a conflicting "A message comes in" handler on the number when possible).
 */
app.post(
  '/api/webhooks/twilio/conversations',
  express.urlencoded({ extended: false }),
  async (req, res) => {
    if (!validateTwilioWebhookSignature(req)) {
      return res.status(403).send('Forbidden');
    }
    const event = req.body.EventType || req.body.eventType;
    const convSid = req.body.ConversationSid || req.body.conversationSid;
    const shouldEnsure =
      convSid &&
      (event === 'onConversationAdded' || event === 'onMessageAdded');
    if (shouldEnsure) {
      try {
        await ensureChatParticipantInConversation(convSid);
      } catch (e) {
        console.error('Conversations webhook ensureChatParticipant:', e);
        return res.status(500).send('Error');
      }
    }
    res.status(200).end();
  }
);

/**
 * Programmable Messaging (Zapier, Messages API) status callback: mirror outbound SMS into
 * Twilio Conversations so PBSG Messenger shows the same thread. Author must be "system"
 * (not the browser chat identity) or Twilio will relay each message as another SMS to the
 * customer. JSON attributes.pbsgOutbound drives right-aligned bubbles in the web app.
 *
 * Fetches the Message resource so direction and pool "From" numbers are correct (Zapier /
 * Messaging Service senders need not match TWILIO_PHONE_NUMBER).
 *
 * Configure Status Callback URL (phone number, Messaging Service, or per Zapier send) to:
 *   https://YOUR-API/api/webhooks/twilio/programmable-messaging
 * TWILIO_AUTH_TOKEN should be set so Twilio can sign requests.
 */
app.post(
  '/api/webhooks/twilio/programmable-messaging',
  express.urlencoded({ extended: false }),
  async (req, res) => {
    if (!validateTwilioWebhookSignature(req)) {
      return res.status(403).send('Forbidden');
    }

    const messageSid = req.body.MessageSid || req.body.SmsSid;
    const statusRaw = (req.body.MessageStatus || req.body.SmsStatus || '').toLowerCase();

    if (!messageSid || statusRaw !== 'sent') {
      return res.status(200).end();
    }

    let fetched = null;
    try {
      fetched = await twilioClient.messages(messageSid).fetch();
    } catch (e) {
      console.warn('programmable-messaging webhook: could not fetch message', messageSid, e?.message);
    }

    const dir = String(fetched?.direction ?? req.body.Direction ?? '').toLowerCase();
    if (!dir.startsWith('outbound')) {
      return res.status(200).end();
    }

    const from = fetched?.from || req.body.From;
    const to = fetched?.to || req.body.To;
    if (!from || !to) {
      return res.status(200).end();
    }
    // Pool / Messaging Service "From" may not match TWILIO_PHONE_NUMBER; API direction is authoritative.
    if (!fetched && !fromMatchesAnyOurSender(from)) {
      return res.status(200).end();
    }

    if (mirroredProgrammableMessageSids.has(messageSid)) {
      return res.status(200).end();
    }

    let bodyText = typeof req.body.Body === 'string' ? req.body.Body : '';
    if (!bodyText && req.body.NumMedia && Number(req.body.NumMedia) > 0) {
      bodyText = '[Media]';
    }
    if (!bodyText && fetched?.body) {
      bodyText = String(fetched.body);
    }

    try {
      const { conversationSid: convSid } =
        await findOrCreateConversationForCustomerAddress(to);
      await ensureChatParticipantInConversation(convSid);
      const skipDuplicateWebSend = await recentChatAuthorMessageMatchesBody(
        convSid,
        bodyText,
        25_000
      );
      if (!skipDuplicateWebSend) {
        let dateCreated;
        const ds = req.body.DateSent;
        if (ds) {
          const t = Date.parse(String(ds));
          if (!Number.isNaN(t)) dateCreated = new Date(t);
        }
        await mirrorProgrammableOutboundToConversation(
          convSid,
          bodyText,
          messageSid,
          dateCreated
        );
      }
      rememberMirroredSid(messageSid);
    } catch (e) {
      console.error('programmable-messaging mirror error:', e);
      return res.status(500).send('Error');
    }

    res.status(200).end();
  }
);

app.use(express.json({ limit: '100kb' }));

function requireSession(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  const token = h.slice(7).trim();
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }
  try {
    jwt.verify(token, sessionJwtSecret);
    next();
  } catch {
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }
}

/**
 * POST /api/login
 * Body: { password: string }
 * Returns a signed session JWT (store in browser; use as Bearer for /api/token and /api/conversations).
 */
app.post('/api/login', (req, res) => {
  const password = req.body?.password;
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required.' });
  }

  try {
    const ok = bcrypt.compareSync(password, appPasswordHash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    const sessionToken = jwt.sign(
      { v: 1 },
      sessionJwtSecret,
      { expiresIn: sessionMaxAgeSec, subject: 'pbsg' }
    );
    return res.json({
      token: sessionToken,
      expiresIn: sessionMaxAgeSec,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Sign-in failed.' });
  }
});

/**
 * POST /api/token
 * Header: Authorization: Bearer <sessionJwt>
 * Returns Twilio access token for Conversations (Chat grant + service SID).
 */
app.post('/api/token', requireSession, (_req, res) => {
  try {
    const token = new AccessToken(accountSid, apiKey, apiSecret, {
      identity: twilioChatIdentity,
      ttl: 3600,
    });
    token.addGrant(
      new ChatGrant({
        serviceSid,
      })
    );
    const twilioJwt = token.toJwt();
    return res.json({
      token: twilioJwt,
      identity: twilioChatIdentity,
      expiresIn: 3600,
    });
  } catch (err) {
    console.error('Token error:', err);
    return res.status(500).json({ error: 'Failed to create access token.' });
  }
});

/**
 * POST /api/conversations
 * Header: Authorization: Bearer <sessionJwt>
 * Body: { to: string (phone) }
 */
/** Customer E.164 values to omit from GET /api/conversation-sids (comma-separated in HIDDEN_SMS_CUSTOMER_E164). */
function hiddenCustomerE164Set() {
  const set = new Set();
  for (const part of String(process.env.HIDDEN_SMS_CUSTOMER_E164 || '').split(',')) {
    const c = canonicalCustomerE164(part.trim());
    if (c) set.add(c);
  }
  return set;
}

/**
 * Best-effort customer number for filtering (friendlyName "SMS +61…" or SMS participant binding).
 */
async function resolveConversationCustomerE164(conversationSid) {
  try {
    const conv = await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(conversationSid)
      .fetch();
    const fn = (conv.friendlyName || '').trim();
    const m = fn.match(/^SMS\s+(.+)$/i);
    if (m) {
      const c = canonicalCustomerE164(m[1].trim());
      if (c) return c;
    } else if (/^SMS/i.test(fn)) {
      const rest = fn.replace(/^SMS\s*/i, '').trim();
      const c = canonicalCustomerE164(rest);
      if (c) return c;
    }
    const parts = await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(conversationSid)
      .participants.list();
    for (const p of parts) {
      const mb = p.messagingBinding;
      const addr =
        mb &&
        (mb.address ||
          mb.Address ||
          mb.participant_address ||
          mb.participantAddress);
      if (addr) {
        const c = canonicalCustomerE164(addr);
        if (c) return c;
      }
    }
  } catch (e) {
    console.warn('resolveConversationCustomerE164', conversationSid, e?.message);
  }
  return null;
}

/**
 * List every Conversation SID where this service's chat identity is a participant.
 * Used so the inbox can show full history, not only what the JS SDK synced first.
 */
async function listConversationSidsForIdentity() {
  const sids = [];
  let page = await twilioClient.conversations.v1
    .services(serviceSid)
    .participantConversations.page({
      identity: twilioChatIdentity,
      pageSize: 100,
    });
  for (;;) {
    for (const row of page.instances) {
      if (row.conversationSid) sids.push(row.conversationSid);
    }
    if (!page.nextPageUrl) break;
    page = await page.nextPage();
  }
  const unique = [...new Set(sids)];
  const hidden = hiddenCustomerE164Set();
  if (!hidden.size) return unique;
  const out = [];
  for (const sid of unique) {
    const cust = await resolveConversationCustomerE164(sid);
    if (cust && hidden.has(cust)) continue;
    out.push(sid);
  }
  return out;
}

/**
 * GET /api/conversation-sids
 * Header: Authorization: Bearer <sessionJwt>
 */
app.get('/api/conversation-sids', requireSession, async (_req, res) => {
  try {
    const conversationSids = await listConversationSidsForIdentity();
    /** Also returned so the web client can drop the same threads from Twilio SDK’s subscribed list. */
    const hiddenCustomerE164 = [...hiddenCustomerE164Set()];
    return res.json({ conversationSids, hiddenCustomerE164 });
  } catch (err) {
    console.error('List conversations error:', err);
    return res.status(500).json({ error: 'Failed to list conversations.' });
  }
});

/**
 * Add the web inbox identity to every Conversation in this service that lacks it.
 * Use once after deploy or when old SMS-only threads never triggered onConversationAdded.
 */
/**
 * POST /api/sync-sms-log
 * Header: Authorization: Bearer <sessionJwt>
 * Body (optional): { daysBack?: number } — default 30, max 90.
 * Optional maxMessages?: number — after loading the window, only process the N newest log rows (cap 500).
 * Reads Twilio Programmable Messaging (the SMS/MMS log in Console) and mirrors each
 * message into the matching Conversation so the inbox matches what you see under Logs.
 */
app.post('/api/sync-sms-log/cancel', requireSession, (_req, res) => {
  smsLogSyncCancelRequested = true;
  return res.json({ ok: true });
});

app.post('/api/sync-sms-log', requireSession, async (req, res) => {
  const raw = req.body?.daysBack;
  const daysBack =
    typeof raw === 'number' && Number.isFinite(raw)
      ? raw
      : typeof raw === 'string'
        ? Number.parseInt(raw, 10)
        : 30;
  const rawMax = req.body?.maxMessages;
  let maxMessages;
  if (typeof rawMax === 'number' && Number.isFinite(rawMax)) {
    maxMessages = Math.min(Math.max(Math.floor(rawMax), 1), 500);
  } else if (typeof rawMax === 'string') {
    const p = Number.parseInt(rawMax, 10);
    if (Number.isFinite(p)) maxMessages = Math.min(Math.max(p, 1), 500);
  }
  smsLogSyncCancelRequested = false;
  try {
    /** Only the explicit cancel endpoint — req.aborted/socket flags are flaky behind proxies and caused instant "cancelled" syncs. */
    const shouldCancel = () => smsLogSyncCancelRequested;
    const result = await syncProgrammableSmsLogIntoConversations(
      Number.isFinite(daysBack) ? daysBack : 30,
      shouldCancel,
      maxMessages != null ? { maxMessages } : {}
    );
    return res.json(result);
  } catch (err) {
    console.error('Sync SMS log error:', err);
    return res.status(500).json({ error: err?.message || 'SMS log sync failed.' });
  } finally {
    smsLogSyncCancelRequested = false;
  }
});

app.post('/api/repair-chat-participants', requireSession, async (_req, res) => {
  let scanned = 0;
  let added = 0;
  try {
    let page = await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations.page({ pageSize: 50 });
    for (;;) {
      for (const conv of page.instances) {
        scanned++;
        const sid = conv.sid;
        const parts = await twilioClient.conversations.v1
          .services(serviceSid)
          .conversations(sid)
          .participants.list();
        const hasOurIdentity = parts.some((p) => p.identity === twilioChatIdentity);
        if (!hasOurIdentity) {
          await ensureChatParticipantInConversation(sid);
          added++;
        }
      }
      if (!page.nextPageUrl) break;
      page = await page.nextPage();
    }
    return res.json({ scanned, added });
  } catch (err) {
    console.error('Repair chat participants error:', err);
    return res.status(500).json({ error: err?.message || 'Repair failed.' });
  }
});

app.post('/api/conversations', requireSession, async (req, res) => {
  const phone = toE164Australian(req.body?.to);
  if (!phone.ok) {
    return res.status(400).json({ error: phone.error });
  }

  try {
    const { conversationSid: sid, created } =
      await findOrCreateConversationForCustomerAddress(phone.e164);
    const conv = await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(sid)
      .fetch();
    return res.status(created ? 201 : 200).json({
      conversationSid: sid,
      friendlyName: conv.friendlyName,
    });
  } catch (err) {
    console.error('Create conversation error:', err);
    const msg =
      err?.message || 'Failed to create conversation. Check Twilio configuration.';
    return res.status(500).json({ error: msg });
  }
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'pbsg-messenger-backend' });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`PBSG Messenger API listening on http://localhost:${PORT}`);
});
