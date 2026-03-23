import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import twilio from 'twilio';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import webpush from 'web-push';
import { cert, getApps, initializeApp } from 'firebase-admin/app';
import { getMessaging } from 'firebase-admin/messaging';
import { toE164Australian } from './lib/phone.js';
import {
  appendTrelloRelayMessages,
  getTrelloRelayThread,
  listTrelloRelayThreads,
  parseTrelloRelaySmsBody,
} from './lib/trelloRelay.js';

const { AccessToken } = twilio.jwt;
const { ChatGrant } = AccessToken;

const PORT = Number(process.env.PORT) || 3001;
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const apiKey = process.env.TWILIO_API_KEY;
const apiSecret = process.env.TWILIO_API_SECRET;
const serviceSid = process.env.TWILIO_CONVERSATIONS_SERVICE_SID;
const twilioPhone = process.env.TWILIO_PHONE_NUMBER;
const pushVapidPublicKey = process.env.PUSH_VAPID_PUBLIC_KEY;
const pushVapidPrivateKey = process.env.PUSH_VAPID_PRIVATE_KEY;
const pushVapidSubject = process.env.PUSH_VAPID_SUBJECT || 'mailto:admin@example.com';
const firebaseProjectId = process.env.FIREBASE_PROJECT_ID;
const firebaseClientEmail = process.env.FIREBASE_CLIENT_EMAIL;
const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');

/** E.164 for the number that receives self-SMS Trello relay payloads (default: your Trello SMS number). */
function trelloRelayE164() {
  const raw = (process.env.TRELLO_RELAY_E164 || '+61468167025').trim();
  const p = toE164Australian(raw.startsWith('+') ? raw : `+${raw.replace(/\D/g, '')}`);
  return p.ok ? p.e164 : '+61468167025';
}

/** E.164 sender number used to forward relay payloads into TRELLO_RELAY_E164. */
function trelloRelaySourceE164() {
  const raw = (process.env.TRELLO_RELAY_SOURCE_E164 || '+61468162324').trim();
  const p = toE164Australian(raw.startsWith('+') ? raw : `+${raw.replace(/\D/g, '')}`);
  return p.ok ? p.e164 : '+61468162324';
}

const sessionJwtSecret = process.env.SESSION_JWT_SECRET;
const appPasswordHash = process.env.APP_PASSWORD_HASH;
const sessionMaxAgeSec = Number(process.env.SESSION_MAX_AGE_SECONDS) || 31536000; // 365 days
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
const pushSubscriptions = new Map();
const nativePushTokens = new Set();
let nativePushLastAttemptAt = null;
let nativePushLastSuccessAt = null;
let nativePushLastError = null;
let nativePushLastResult = null;

/** Status-callback → Conversations mirror is opt-in (default off) so misconfigured relay cannot resend SMS. */
function programmableStatusMirrorEnabled() {
  return ['true', '1', 'yes', 'on'].includes(
    String(process.env.TWILIO_PROGRAMMABLE_STATUS_MIRROR ?? 'false').toLowerCase()
  );
}

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

function webPushEnabled() {
  return Boolean(pushVapidPublicKey && pushVapidPrivateKey);
}

function nativePushEnabled() {
  return Boolean(firebaseProjectId && firebaseClientEmail && firebasePrivateKey);
}

let firebaseMessaging = null;
if (nativePushEnabled()) {
  try {
    if (!getApps().length) {
      initializeApp({
        credential: cert({
          projectId: firebaseProjectId,
          clientEmail: firebaseClientEmail,
          privateKey: firebasePrivateKey,
        }),
      });
    }
    firebaseMessaging = getMessaging();
  } catch (err) {
    console.warn('Firebase init error:', err?.message || err);
    firebaseMessaging = null;
  }
}

if (webPushEnabled()) {
  webpush.setVapidDetails(pushVapidSubject, pushVapidPublicKey, pushVapidPrivateKey);
}

function pushSubscriptionKey(sub) {
  if (!sub || typeof sub.endpoint !== 'string') return null;
  return sub.endpoint.trim();
}

function normalizePushSubscription(input) {
  if (!input || typeof input !== 'object') return null;
  const endpoint = typeof input.endpoint === 'string' ? input.endpoint.trim() : '';
  const p256dh = input?.keys?.p256dh;
  const auth = input?.keys?.auth;
  if (!endpoint || !p256dh || !auth) return null;
  return {
    endpoint,
    expirationTime: input.expirationTime ?? null,
    keys: { p256dh, auth },
  };
}

async function sendWebPushToAll(payload) {
  const deadKeys = [];
  const sends = [];
  for (const [key, sub] of pushSubscriptions.entries()) {
    sends.push(
      webpush.sendNotification(sub, JSON.stringify(payload)).catch((err) => {
        const code = Number(err?.statusCode || 0);
        if (code === 404 || code === 410) {
          deadKeys.push(key);
          return;
        }
        throw err;
      })
    );
  }
  await Promise.all(sends);
  for (const key of deadKeys) {
    pushSubscriptions.delete(key);
  }
}

function normalizeNativePushToken(input) {
  const token = String(input || '').trim();
  if (!token) return null;
  if (token.length < 32) return null;
  return token;
}

async function sendNativePushToAll(payload) {
  if (!firebaseMessaging || !nativePushTokens.size) return;
  nativePushLastAttemptAt = new Date().toISOString();
  const tokens = [...nativePushTokens];
  const message = {
    tokens,
    notification: {
      title: String(payload?.title || 'New message'),
      body: String(payload?.body || ''),
    },
    data: {
      url: String(payload?.url || '/'),
      conversationSid: String(payload?.conversationSid || ''),
      messageSid: String(payload?.messageSid || ''),
    },
    android: {
      priority: 'high',
      notification: {},
    },
  };
  const result = await firebaseMessaging.sendEachForMulticast(message);
  nativePushLastResult = {
    successCount: result.successCount,
    failureCount: result.failureCount,
    tokenCount: tokens.length,
  };
  nativePushLastSuccessAt = new Date().toISOString();
  nativePushLastError = null;
  result.responses.forEach((r, idx) => {
    if (r.success) return;
    const code = r.error?.code || '';
    if (
      code.includes('registration-token-not-registered') ||
      code.includes('invalid-registration-token')
    ) {
      nativePushTokens.delete(tokens[idx]);
    }
  });
}

function pushPreviewText(raw, maxLen = 140) {
  const s = String(raw || '').replace(/\s+/g, ' ').trim();
  if (!s) return '';
  return s.length > maxLen ? `${s.slice(0, maxLen)}...` : s;
}

function extractInternalDraftSegment(bodyText) {
  const raw = String(bodyText || '');
  const m = raw.match(/\[\[PBSG_INTERNAL_DRAFT\]\]([\s\S]*?)\[\[\/PBSG_INTERNAL_DRAFT\]\]/i);
  if (!m) return null;
  const draftBody = String(m[1] || '').trim();
  return draftBody || null;
}

function parseAttributesJson(raw) {
  if (!raw) return null;
  if (typeof raw === 'object') return raw;
  if (typeof raw !== 'string') return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

async function ensureInternalDraftMirrorMessage(conversationSid, sourceMessageSid, draftBody) {
  if (!conversationSid || !draftBody) return;
  const page = await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(conversationSid)
    .messages.page({ order: 'desc', pageSize: 30 });
  for (const msg of page.instances) {
    const attrs = parseAttributesJson(msg.attributes);
    if (attrs?.pbsgInternalDraftSourceMessageSid === sourceMessageSid) {
      return;
    }
  }
  const attrs = JSON.stringify({
    pbsgOutbound: true,
    pbsgInternalDraft: true,
    pbsgInternalDraftSourceMessageSid: sourceMessageSid || null,
  });
  await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations(conversationSid)
    .messages.create({
      author: 'system',
      body: draftBody,
      attributes: attrs,
      xTwilioWebhookEnabled: 'false',
    });
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
 * Shared ParticipantConversation lookup (multi-variant address).
 * @returns {{ ok: true, e164: string, rows: unknown[] } | { ok: false, error: string }}
 */
async function resolveCustomerConversationLookup(customerAddress) {
  const e164 = canonicalCustomerE164(customerAddress);
  if (!e164) {
    return { ok: false, error: `Invalid customer phone address: ${String(customerAddress)}` };
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
  return { ok: true, e164, rows };
}

/**
 * Find an existing conversation for this customer address, or create one (Zapier-first outbound).
 * @returns {{ conversationSid: string, created: boolean }}
 */
async function findOrCreateConversationForCustomerAddress(customerAddress) {
  const r = await resolveCustomerConversationLookup(customerAddress);
  if (!r.ok) throw new Error(r.error);
  const existing = pickConversationSidForCustomer(r.rows);
  if (existing) return { conversationSid: existing, created: false };
  const sid = await createSmsConversationForCustomerE164(r.e164);
  return { conversationSid: sid, created: true };
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
  // Never use TWILIO_CONVERSATIONS_IDENTITY here — Twilio relays chat-participant messages as SMS.
  // Author "system" + attributes.pbsgOutbound for right-aligned bubbles in the web app.
  const createParams = {
    author: 'system',
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
    const messageSid = req.body.MessageSid || req.body.messageSid;
    const bodyText = req.body.Body || req.body.body || '';
    const author = req.body.Author || req.body.author || '';
    const shouldEnsure =
      convSid &&
      (event === 'onConversationAdded' || event === 'onMessageAdded');
    if (shouldEnsure) {
      try {
        await ensureChatParticipantInConversation(convSid);
        // Display-only helper: if inbound message embeds [[PBSG_INTERNAL_DRAFT]], add a synthetic
        // pbsgOutbound row so the draft text appears as a right-aligned "sent" bubble in the app.
        if (event === 'onMessageAdded' && author !== 'system') {
          const draftBody = extractInternalDraftSegment(bodyText);
          if (draftBody) {
            await ensureInternalDraftMirrorMessage(convSid, messageSid, draftBody);
          }
        }
        // Phone push notification for new inbound customer messages.
        // Skip system/web-app-authored messages to avoid notifying on our own sends.
        if (
          event === 'onMessageAdded' &&
          author &&
          author !== 'system' &&
          author !== twilioChatIdentity &&
          ((webPushEnabled() && pushSubscriptions.size > 0) ||
            (firebaseMessaging && nativePushTokens.size > 0))
        ) {
          try {
            const preview = pushPreviewText(bodyText) || 'New message received';
            const notifyPayload = {
              title: 'New message',
              body: preview,
              url: '/',
              conversationSid: convSid || null,
              messageSid: messageSid || null,
            };
            if (webPushEnabled() && pushSubscriptions.size > 0) {
              await sendWebPushToAll(notifyPayload);
            }
            if (firebaseMessaging && nativePushTokens.size > 0) {
              await sendNativePushToAll(notifyPayload);
            }
          } catch (pushErr) {
            // Never fail Twilio webhook for push transport issues.
            console.warn('Conversations webhook push notify error:', pushErr?.message || pushErr);
          }
        }
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
 *
 * Mirroring into Conversations is OFF by default. Set TWILIO_PROGRAMMABLE_STATUS_MIRROR=true only after
 * you confirm mirrored rows do not relay as new SMS (test on a sandbox number first).
 */
app.post(
  '/api/webhooks/twilio/programmable-messaging',
  express.urlencoded({ extended: false }),
  async (req, res) => {
    if (!validateTwilioWebhookSignature(req)) {
      return res.status(403).send('Forbidden');
    }

    if (!programmableStatusMirrorEnabled()) {
      return res.status(200).end();
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

/**
 * Inbound SMS webhook: relay SMS from TRELLO_RELAY_SOURCE_E164 to TRELLO_RELAY_E164
 * with &&FROM…&& / && REPLY && body.
 * Stores display-only messages in memory for GET /api/trello-relay/* — does not call Conversations API.
 *
 * Twilio Console → Phone number → A message comes in → Webhook URL:
 *   https://YOUR-API/api/webhooks/twilio/trello-relay  (HTTP POST)
 * Prefer this path instead of duplicating into Conversations if you only need the web inbox preview.
 */
app.post(
  '/api/webhooks/twilio/trello-relay',
  express.urlencoded({ extended: false }),
  (req, res) => {
    if (!validateTwilioWebhookSignature(req)) {
      return res.status(403).send('Forbidden');
    }
    const relay = trelloRelayE164();
    const relaySource = trelloRelaySourceE164();
    const from = req.body.From || req.body.from;
    const to = req.body.To || req.body.to;
    if (
      !from ||
      !to ||
      canonicalCustomerE164(from) !== relaySource ||
      canonicalCustomerE164(to) !== relay
    ) {
      return res.status(200).type('text/xml').send('<Response></Response>');
    }
    const bodyText = typeof req.body.Body === 'string' ? req.body.Body : '';
    const parsed = parseTrelloRelaySmsBody(bodyText);
    if (parsed) {
      appendTrelloRelayMessages(
        parsed.customerE164,
        parsed.fromBody,
        parsed.replyBody
      );
    }
    return res.status(200).type('text/xml').send('<Response></Response>');
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
 * GET /api/push/public-key
 * Returns VAPID public key for browser PushManager.subscribe().
 */
app.get('/api/push/public-key', (_req, res) => {
  if (!webPushEnabled()) {
    return res.status(503).json({ error: 'Web push is not configured.' });
  }
  return res.json({ publicKey: pushVapidPublicKey });
});

/**
 * POST /api/push/subscribe
 * Body: { subscription: PushSubscriptionJSON }
 */
app.post('/api/push/subscribe', (req, res) => {
  if (!webPushEnabled()) {
    return res.status(503).json({ error: 'Web push is not configured.' });
  }
  const sub = normalizePushSubscription(req.body?.subscription);
  const key = pushSubscriptionKey(sub);
  if (!sub || !key) {
    return res.status(400).json({ error: 'Invalid push subscription.' });
  }
  pushSubscriptions.set(key, sub);
  return res.json({ ok: true, subscribed: pushSubscriptions.size });
});

/**
 * POST /api/push/fcm/subscribe
 * Header: Authorization: Bearer <sessionJwt>
 * Body: { token: string }
 */
app.post('/api/push/fcm/subscribe', (req, res) => {
  if (!firebaseMessaging) {
    return res.status(503).json({ error: 'Native push is not configured.' });
  }
  const token = normalizeNativePushToken(req.body?.token);
  if (!token) {
    return res.status(400).json({ error: 'Invalid FCM token.' });
  }
  nativePushTokens.add(token);
  return res.json({ ok: true, subscribed: nativePushTokens.size });
});

/**
 * POST /api/push/fcm/unsubscribe
 * Header: Authorization: Bearer <sessionJwt>
 * Body: { token: string }
 */
app.post('/api/push/fcm/unsubscribe', (req, res) => {
  const token = normalizeNativePushToken(req.body?.token);
  if (!token) {
    return res.status(400).json({ error: 'Invalid FCM token.' });
  }
  nativePushTokens.delete(token);
  return res.json({ ok: true, subscribed: nativePushTokens.size });
});

/**
 * GET /api/push/fcm/status
 * Header: Authorization: Bearer <sessionJwt>
 */
app.get('/api/push/fcm/status', requireSession, (_req, res) => {
  return res.json({
    ok: true,
    configured: Boolean(firebaseMessaging),
    subscribed: nativePushTokens.size,
    lastAttemptAt: nativePushLastAttemptAt,
    lastSuccessAt: nativePushLastSuccessAt,
    lastError: nativePushLastError,
    lastResult: nativePushLastResult,
  });
});

/**
 * POST /api/push/fcm/test
 * Body: { title?: string, body?: string, url?: string }
 */
app.post('/api/push/fcm/test', async (req, res) => {
  if (!firebaseMessaging) {
    return res.status(503).json({ error: 'Native push is not configured.' });
  }
  if (!nativePushTokens.size) {
    return res.status(400).json({ error: 'No native push tokens subscribed yet.' });
  }
  const title = String(req.body?.title || 'PBSG Messenger').trim() || 'PBSG Messenger';
  const body = String(req.body?.body || 'Native FCM test').trim() || 'Native FCM test';
  const url = String(req.body?.url || '/').trim() || '/';
  try {
    await sendNativePushToAll({ title, body, url });
    return res.json({
      ok: true,
      subscribed: nativePushTokens.size,
      lastResult: nativePushLastResult,
    });
  } catch (err) {
    nativePushLastError = err?.message || String(err);
    console.error('Native push test send error:', err);
    return res.status(500).json({ error: 'Native FCM test failed.', detail: nativePushLastError });
  }
});

/**
 * POST /api/push/unsubscribe
 * Body: { endpoint: string }
 */
app.post('/api/push/unsubscribe', (req, res) => {
  const endpoint = typeof req.body?.endpoint === 'string' ? req.body.endpoint.trim() : '';
  if (!endpoint) {
    return res.status(400).json({ error: 'Missing endpoint.' });
  }
  pushSubscriptions.delete(endpoint);
  return res.json({ ok: true, subscribed: pushSubscriptions.size });
});

/**
 * POST /api/push/test
 * Header: Authorization: Bearer <sessionJwt>
 * Body: { title?: string, body?: string, url?: string }
 */
app.post('/api/push/test', requireSession, async (req, res) => {
  if (!webPushEnabled()) {
    return res.status(503).json({ error: 'Web push is not configured.' });
  }
  const title = String(req.body?.title || 'PBSG Messenger').trim() || 'PBSG Messenger';
  const body = String(req.body?.body || 'Test push notification').trim() || 'Test push notification';
  const url = String(req.body?.url || '/').trim() || '/';
  try {
    await sendWebPushToAll({ title, body, url });
    return res.json({ ok: true, sentTo: pushSubscriptions.size });
  } catch (err) {
    console.error('Push test send error:', err);
    return res.status(500).json({ error: 'Failed to send push notification.' });
  }
});

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
/**
 * List every Conversation SID where this service's chat identity is a participant.
 * Used so the REST client can open the same threads the Conversations SDK subscribes to.
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
  const known = new Set(sids);

  /**
   * Fallback for service-created threads that exist but missed the post-event webhook:
   * attach the web inbox identity and return those SIDs so the UI can open them now.
   */
  const recovered = [];
  let convPage = await twilioClient.conversations.v1
    .services(serviceSid)
    .conversations.page({ pageSize: 50 });
  for (;;) {
    for (const conv of convPage.instances) {
      const sid = conv.sid;
      if (!sid) continue;
      if (known.has(sid)) {
        recovered.push(sid);
        continue;
      }
      try {
        await ensureChatParticipantInConversation(sid);
        known.add(sid);
        recovered.push(sid);
      } catch (e) {
        console.warn('listConversationSidsForIdentity fallback', sid, e?.message);
      }
    }
    if (!convPage.nextPageUrl) break;
    convPage = await convPage.nextPage();
  }
  return [...new Set(recovered)];
}

/**
 * Collapse duplicate conversation rows that represent the same customer thread.
 * Prefer the newest conversation when multiple SIDs share a friendly name / customer number.
 */
function conversationThreadKey(friendlyName, sid) {
  const raw = String(friendlyName || '').trim();
  if (!raw) return `sid:${sid}`;
  const smsMatch = raw.match(/^SMS\s+(.+)$/i);
  const candidate = smsMatch ? smsMatch[1].trim() : raw;
  const canonical = canonicalCustomerE164(candidate);
  if (canonical) return `cust:${canonical}`;
  return `name:${raw.toLowerCase()}`;
}

async function collapseConversationSidsByThread(conversationSids) {
  if (!conversationSids.length) return [];
  const byKey = new Map();
  for (const sid of conversationSids) {
    try {
      const conv = await twilioClient.conversations.v1
        .services(serviceSid)
        .conversations(sid)
        .fetch();
      const key = conversationThreadKey(conv.friendlyName, sid);
      const updated = conv.dateUpdated?.getTime?.() ?? 0;
      const prev = byKey.get(key);
      if (!prev || updated >= prev.updated) {
        byKey.set(key, { sid, updated });
      }
    } catch (e) {
      const key = `sid:${sid}`;
      if (!byKey.has(key)) byKey.set(key, { sid, updated: 0 });
      console.warn('collapseConversationSidsByThread', sid, e?.message);
    }
  }
  return [...byKey.values()]
    .sort((a, b) => b.updated - a.updated)
    .map((x) => x.sid);
}

/**
 * GET /api/conversation-sids
 * Header: Authorization: Bearer <sessionJwt>
 */
app.get('/api/conversation-sids', requireSession, async (_req, res) => {
  try {
    const rawConversationSids = await listConversationSidsForIdentity();
    const conversationSids = await collapseConversationSidsByThread(rawConversationSids);
    return res.json({ conversationSids });
  } catch (err) {
    console.error('List conversations error:', err);
    return res.status(500).json({ error: 'Failed to list conversations.' });
  }
});

/**
 * GET /api/trello-relay/threads
 * In-memory threads parsed from Trello self-SMS relay (display-only; not in Twilio Conversations).
 */
app.get('/api/trello-relay/threads', requireSession, (_req, res) => {
  try {
    return res.json({ threads: listTrelloRelayThreads() });
  } catch (err) {
    console.error('Trello relay list error:', err);
    return res.status(500).json({ error: 'Failed to list relay threads.' });
  }
});

/**
 * GET /api/trello-relay/thread?customer=%2B614...
 */
app.get('/api/trello-relay/thread', requireSession, (req, res) => {
  const raw = req.query.customer;
  if (!raw || typeof raw !== 'string') {
    return res.status(400).json({ error: 'Missing customer (E.164).' });
  }
  const c = canonicalCustomerE164(decodeURIComponent(raw.trim()));
  if (!c) {
    return res.status(400).json({ error: 'Invalid customer phone.' });
  }
  try {
    return res.json(getTrelloRelayThread(c));
  } catch (err) {
    console.error('Trello relay thread error:', err);
    return res.status(500).json({ error: 'Failed to load relay thread.' });
  }
});

/**
 * Add the web inbox identity to every Conversation in this service that lacks it.
 * Use once after deploy or when old SMS-only threads never triggered onConversationAdded.
 */
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
  res.json({
    ok: true,
    service: 'pbsg-messenger-backend',
    programmableStatusCallbackMirror: programmableStatusMirrorEnabled(),
    nativePushConfigured: Boolean(firebaseMessaging),
    nativePushSubscriptions: nativePushTokens.size,
    nativePushLastAttemptAt,
    nativePushLastSuccessAt,
    nativePushLastError,
    nativePushLastResult,
  });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`PBSG Messenger API listening on http://localhost:${PORT}`);
});
