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
import {
  readAllContactLabels,
  removeContactLabel,
  upsertContactLabel,
} from './lib/contactLabels.js';
import { readSettings, updateSettings } from './lib/appSettings.js';

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

/**
 * Named staff accounts. All share APP_PASSWORD_HASH — the username only
 * identifies WHO is signed in (to personalise message templates with their
 * name). The inbox itself is shared across all accounts. Override with
 * APP_USERS="Name1,Name2,…".
 */
const appUsers = (process.env.APP_USERS || 'Mylene,Matt')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
function resolveAppUser(username) {
  const want = String(username || '').trim().toLowerCase();
  if (!want) return null;
  return appUsers.find((u) => u.toLowerCase() === want) || null;
}

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
if (!twilioAuthToken && !allowUnsignedWebhooks()) {
  console.warn(
    'WARNING: TWILIO_AUTH_TOKEN is not set — Twilio webhooks will be REJECTED (403) ' +
      'until it is configured. Set it to your Twilio Account Auth Token (Console → Account Dashboard) ' +
      'in Railway and your local .env. (Set ALLOW_UNSIGNED_WEBHOOKS=true for local dev only.)'
  );
}
const pushSubscriptions = new Map();
const nativePushTokens = new Set();
let nativePushLastAttemptAt = null;
let nativePushLastSuccessAt = null;
let nativePushLastError = null;
let nativePushLastResult = null;
let nativePushLastFailures = [];
let lastConversationsWebhook = null;
const recentConversationsWebhooks = [];
const seenConversationSids = new Set();
const newConversationNotifiedAt = new Map();
const NEW_CONVERSATION_COOLDOWN_MS = 45 * 1000;
// Caps so these long-lived structures stay bounded on the single instance.
const SEEN_CONVERSATION_CAP = 20000;
const NEW_CONVERSATION_NOTIFIED_CAP = 20000;
const PUSH_SUBSCRIPTION_CAP = 2000;

function recordConversationsWebhookSnapshot(snapshot) {
  recentConversationsWebhooks.unshift({
    at: new Date().toISOString(),
    event: snapshot?.event || null,
    conversationSid: snapshot?.conversationSid || null,
    messageSid: snapshot?.messageSid || null,
    author: snapshot?.author || null,
    status: snapshot?.status || null,
    error: snapshot?.error || null,
  });
  if (recentConversationsWebhooks.length > 12) {
    recentConversationsWebhooks.length = 12;
  }
}

/** Read-only: may a "new conversation" push be sent now (outside the cooldown)? */
function canNotifyNewConversation(conversationSid) {
  if (!conversationSid) return false;
  const lastAt = newConversationNotifiedAt.get(conversationSid) || 0;
  return Date.now() - lastAt >= NEW_CONVERSATION_COOLDOWN_MS;
}

/** Record that a "new conversation" push was actually sent (starts the cooldown). */
function markNewConversationNotified(conversationSid) {
  if (!conversationSid) return;
  newConversationNotifiedAt.set(conversationSid, Date.now());
  if (newConversationNotifiedAt.size > NEW_CONVERSATION_NOTIFIED_CAP) {
    const oldest = newConversationNotifiedAt.keys().next().value;
    newConversationNotifiedAt.delete(oldest);
  }
}

/** Status-callback → Conversations mirror is opt-in (default off) so misconfigured relay cannot resend SMS. */
function programmableStatusMirrorEnabled() {
  return ['true', '1', 'yes', 'on'].includes(
    String(process.env.TWILIO_PROGRAMMABLE_STATUS_MIRROR ?? 'false').toLowerCase()
  );
}

/**
 * Capacitor / Cordova WebViews load the UI from a non-real host (e.g. https://localhost).
 * If CORS_ORIGIN is a fixed list of web origins only, the Android APK gets "Failed to fetch"
 * on login. Allow these by default when an allowlist is set; set CORS_ALLOW_CAPACITOR=false to disable.
 */
function isPackagedMessengerOrigin(origin) {
  if (!origin || typeof origin !== 'string') return false;
  try {
    const u = new URL(origin);
    const h = u.hostname.toLowerCase();
    if (h !== 'localhost' && h !== '127.0.0.1') return false;
    const p = u.protocol.toLowerCase();
    return (
      p === 'https:' ||
      p === 'http:' ||
      p === 'capacitor:' ||
      p === 'ionic:'
    );
  } catch {
    return false;
  }
}

/** Browser Origin never has a trailing slash; strip so CORS matches Netlify exactly. */
function corsOriginOption() {
  const raw = process.env.CORS_ORIGIN;
  if (!raw?.trim()) return true;
  const list = raw
    .split(',')
    .map((s) => s.trim().replace(/\/+$/, ''))
    .filter(Boolean);
  const allowPackaged = !['false', '0', 'no', 'off'].includes(
    String(process.env.CORS_ALLOW_CAPACITOR ?? 'true').toLowerCase()
  );
  if (!allowPackaged) return list;

  return (origin, cb) => {
    if (!origin) {
      cb(null, true);
      return;
    }
    const normalized = origin.replace(/\/+$/, '');
    if (list.includes(normalized)) {
      cb(null, true);
      return;
    }
    if (isPackagedMessengerOrigin(origin)) {
      cb(null, true);
      return;
    }
    cb(null, false);
  };
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

/** Dev-only escape hatch: explicitly allow unsigned Twilio webhooks (local testing). */
function allowUnsignedWebhooks() {
  return ['true', '1', 'yes', 'on'].includes(
    String(process.env.ALLOW_UNSIGNED_WEBHOOKS ?? '').toLowerCase()
  );
}

function validateTwilioWebhookSignature(req) {
  if (!twilioAuthToken) {
    // Fail CLOSED: without the Auth Token we cannot verify Twilio's signature,
    // so an unsigned request from anyone could spam push / inject content.
    // ALLOW_UNSIGNED_WEBHOOKS is the only (dev-only) way to bypass this.
    if (allowUnsignedWebhooks()) {
      console.warn(
        'ALLOW_UNSIGNED_WEBHOOKS is set; skipping Twilio signature verification (dev only).'
      );
      return true;
    }
    console.error('TWILIO_AUTH_TOKEN not set; rejecting unsigned Twilio webhook.');
    return false;
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
  let firstError = null;
  const sends = [];
  for (const [key, sub] of pushSubscriptions.entries()) {
    sends.push(
      webpush.sendNotification(sub, JSON.stringify(payload)).catch((err) => {
        const code = Number(err?.statusCode || 0);
        if (code === 404 || code === 410) {
          deadKeys.push(key);
          return;
        }
        // Don't rethrow here: a rethrow rejects Promise.all and skips the
        // dead-subscription cleanup below, so 404/410 endpoints would be
        // retried forever. Remember one error and surface it after cleanup.
        if (!firstError) firstError = err;
      })
    );
  }
  await Promise.all(sends);
  for (const key of deadKeys) {
    pushSubscriptions.delete(key);
  }
  if (firstError) throw firstError;
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
      notification: {
        channelId: 'high_importance_channel',
        icon: 'ic_stat_pbsg',
        priority: 'high',
        defaultSound: true,
        visibility: 'public',
      },
    },
  };
  const result = await firebaseMessaging.sendEachForMulticast(message);
  nativePushLastResult = {
    successCount: result.successCount,
    failureCount: result.failureCount,
    tokenCount: tokens.length,
  };
  nativePushLastFailures = [];
  nativePushLastSuccessAt = new Date().toISOString();
  nativePushLastError = null;
  result.responses.forEach((r, idx) => {
    if (r.success) return;
    const code = r.error?.code || '';
    nativePushLastFailures.push({
      tokenSuffix: tokens[idx]?.slice(-12) || '',
      code: code || null,
      message: r.error?.message || null,
    });
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

/** E.164 list for web UI: treat last message from these as non-unread. */
function listOurSmsE164sForClient() {
  const out = new Set();
  const addDigits = (d) => {
    const x = String(d || '').replace(/\D/g, '');
    if (x) out.add(`+${x}`);
  };
  addDigits(twilioPhone);
  for (const x of ourSenderDigitSets) addDigits(x);
  return [...out];
}

/** Add to a Set with FIFO eviction so dedup memory degrades gracefully at the
 *  cap instead of being wiped wholesale (a full clear would re-admit — and so
 *  re-notify/re-mirror — every recently-seen SID at once). */
function addToCappedSet(set, key, cap) {
  set.add(key);
  if (set.size > cap) {
    const oldest = set.values().next().value;
    set.delete(oldest);
  }
}

/** Dedupe Programmable Messaging status callbacks (sent + delivered, retries). */
const mirroredProgrammableMessageSids = new Set();
const MIRROR_SID_CAP = 8000;
function rememberMirroredSid(sid) {
  addToCappedSet(mirroredProgrammableMessageSids, sid, MIRROR_SID_CAP);
}

/** Dedupe push sends per message SID (avoids double notify across webhook paths). */
const pushedMessageSids = new Set();
const PUSH_SID_CAP = 8000;
/** Read-only: has a push already been sent for this message SID? */
function wasPushedForMessageSid(sid) {
  const key = String(sid || '').trim();
  if (!key) return false;
  return pushedMessageSids.has(key);
}
/** Mark a message SID as pushed — call ONLY when a push is actually being sent. */
function markPushedForMessageSid(sid) {
  const key = String(sid || '').trim();
  if (!key) return;
  addToCappedSet(pushedMessageSids, key, PUSH_SID_CAP);
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
      friendlyName: customerE164,
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
    const now = new Date().toISOString();
    const event = req.body.EventType || req.body.eventType || '';
    const convSid = req.body.ConversationSid || req.body.conversationSid || '';
    const messageSid = req.body.MessageSid || req.body.messageSid || '';
    const author = req.body.Author || req.body.author || '';
    lastConversationsWebhook = {
      at: now,
      event,
      conversationSid: convSid || null,
      messageSid: messageSid || null,
      author: author || null,
      signatureValid: null,
      status: 'received',
    };
    if (!validateTwilioWebhookSignature(req)) {
      lastConversationsWebhook.signatureValid = false;
      lastConversationsWebhook.status = 'forbidden_signature';
      return res.status(403).send('Forbidden');
    }
    lastConversationsWebhook.signatureValid = true;
    const bodyText = req.body.Body || req.body.body || '';
    const shouldEnsure =
      convSid &&
      (event === 'onConversationAdded' || event === 'onMessageAdded');
    if (shouldEnsure) {
      try {
        await ensureChatParticipantInConversation(convSid);
      } catch (e) {
        // Do not block push delivery if participant-linking has a transient failure.
        console.error('Conversations webhook ensureChatParticipant:', e);
        lastConversationsWebhook.status = 'ensure_error';
        lastConversationsWebhook.error = e?.message || String(e);
      }
      // Display-only helper: if inbound message embeds [[PBSG_INTERNAL_DRAFT]], add a synthetic
      // pbsgOutbound row so the draft text appears as a right-aligned "sent" bubble in the app.
      if (event === 'onMessageAdded' && author !== 'system') {
        try {
          const draftBody = extractInternalDraftSegment(bodyText);
          if (draftBody) {
            await ensureInternalDraftMirrorMessage(convSid, messageSid, draftBody);
          }
        } catch (draftErr) {
          console.warn(
            'Conversations webhook draft mirror error:',
            draftErr?.message || draftErr
          );
        }
      }
      // Phone push notification for new inbound customer messages.
      // Skip system/web-app-authored messages to avoid notifying on our own sends.
      const hasPushTargets =
        (webPushEnabled() && pushSubscriptions.size > 0) ||
        (firebaseMessaging && nativePushTokens.size > 0);
      const isInboundMessageEvent =
        event === 'onMessageAdded' &&
        author !== 'system' &&
        author !== twilioChatIdentity;
      const isConversationAddedEvent = event === 'onConversationAdded';
      const isFirstSeenConversationMessage =
        event === 'onMessageAdded' && convSid && !seenConversationSids.has(convSid);
      const shouldSendNewConversationPush =
        convSid &&
        canNotifyNewConversation(convSid) &&
        (isConversationAddedEvent || isFirstSeenConversationMessage);
      const notAlreadyPushed = !wasPushedForMessageSid(messageSid);
      if (convSid) {
        addToCappedSet(seenConversationSids, convSid, SEEN_CONVERSATION_CAP);
      }
      const shouldSendInboundMessagePush =
        isInboundMessageEvent && !shouldSendNewConversationPush;
      if (
        hasPushTargets &&
        notAlreadyPushed &&
        (shouldSendNewConversationPush || shouldSendInboundMessagePush)
      ) {
        // Commit the dedup SID and new-conversation cooldown only now that we
        // are actually sending — a webhook that decides NOT to push must not
        // suppress a later Twilio retry or the Studio fallback for this message.
        markPushedForMessageSid(messageSid);
        if (shouldSendNewConversationPush) markNewConversationNotified(convSid);
        try {
          const preview = shouldSendNewConversationPush
            ? 'New conversation started'
            : pushPreviewText(bodyText) || 'New message received';
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
          lastConversationsWebhook.status = 'processed_push_attempted';
        } catch (pushErr) {
          // Never fail Twilio webhook for push transport issues.
          console.warn('Conversations webhook push notify error:', pushErr?.message || pushErr);
          lastConversationsWebhook.status = 'processed_push_error';
        }
      }
    }
    if (!shouldEnsure) {
      lastConversationsWebhook.status = 'ignored_event';
    } else if (lastConversationsWebhook.status === 'received') {
      lastConversationsWebhook.status = 'processed_no_push';
    }
    recordConversationsWebhookSnapshot(lastConversationsWebhook);
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
      // Ack 200 even on failure: a 500 makes Twilio retry the status callback,
      // and because the dedupe SID is only remembered after a fully successful
      // mirror, a retry can create a duplicate Conversations row. The mirror is
      // a display-only convenience, so dropping the retry is the safer trade.
      console.error('programmable-messaging mirror error:', e);
      return res.status(200).end();
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
    // Never 5xx a Twilio inbound-SMS webhook: a 500 makes Twilio retry the
    // delivery. Log and swallow any parse/append error and still ack 200.
    try {
      const parsed = parseTrelloRelaySmsBody(bodyText);
      if (parsed) {
        appendTrelloRelayMessages(
          parsed.customerE164,
          parsed.fromBody,
          parsed.replyBody
        );
      }
    } catch (e) {
      console.error('trello-relay parse error:', e?.message || e);
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
    // Pin HS256 (the algorithm used by jwt.sign in /api/login) so a token
    // cannot be presented under a different/weaker algorithm.
    const session = jwt.verify(token, sessionJwtSecret, { algorithms: ['HS256'] });
    req.sessionUserKey =
      typeof session?.sub === 'string' && session.sub.trim() ? session.sub.trim() : 'pbsg';
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
  if (pushSubscriptions.size > PUSH_SUBSCRIPTION_CAP) {
    // FIFO-evict the oldest subscription so this unauthenticated endpoint
    // cannot grow the Map without bound.
    const oldest = pushSubscriptions.keys().next().value;
    if (oldest !== key) pushSubscriptions.delete(oldest);
  }
  return res.json({ ok: true, subscribed: pushSubscriptions.size });
});

/**
 * POST /api/push/fcm/subscribe
 * Header: Authorization: Bearer <sessionJwt>
 * Body: { token: string }
 */
app.post('/api/push/fcm/subscribe', requireSession, (req, res) => {
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
app.post('/api/push/fcm/unsubscribe', requireSession, (req, res) => {
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
    lastFailures: nativePushLastFailures,
  });
});

/**
 * POST /api/push/fcm/test
 * Body: { title?: string, body?: string, url?: string }
 */
app.post('/api/push/fcm/test', requireSession, async (req, res) => {
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
      lastFailures: nativePushLastFailures,
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
 * Brute-force / DoS guard for the single-shared-password /api/login.
 * Counts FAILED attempts per client IP within a rolling window; a correct
 * password clears the counter, so legitimate staff are never locked out by
 * their own successful logins. Blocked requests return before bcrypt runs,
 * so this also caps the event-loop cost of password hashing under flood.
 */
const LOGIN_RL_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RL_MAX_FAILS = 30;
const LOGIN_RL_CAP = 5000;
const loginFailures = new Map(); // ip -> { count, resetAt }

function loginRateLimitRetryAfter(ip) {
  const now = Date.now();
  const rec = loginFailures.get(ip);
  if (!rec || now >= rec.resetAt) return 0;
  if (rec.count >= LOGIN_RL_MAX_FAILS) {
    return Math.max(1, Math.ceil((rec.resetAt - now) / 1000));
  }
  return 0;
}

function recordLoginFailure(ip) {
  const now = Date.now();
  const rec = loginFailures.get(ip);
  if (!rec || now >= rec.resetAt) {
    loginFailures.set(ip, { count: 1, resetAt: now + LOGIN_RL_WINDOW_MS });
  } else {
    rec.count += 1;
  }
  // Bound memory: prune expired entries, then hard-cap.
  if (loginFailures.size > LOGIN_RL_CAP) {
    for (const [k, v] of loginFailures) {
      if (now >= v.resetAt) loginFailures.delete(k);
    }
    if (loginFailures.size > LOGIN_RL_CAP) loginFailures.clear();
  }
}

/**
 * POST /api/login
 * Body: { password: string, username?: string }
 * username is optional (legacy clients omit it). When supplied it must be a
 * known staff name (appUsers); it is embedded in the JWT + returned so the UI
 * can personalise templates. Returns a signed session JWT.
 */
app.post('/api/login', async (req, res) => {
  const ip = req.ip || req.socket?.remoteAddress || 'unknown';
  const retryAfter = loginRateLimitRetryAfter(ip);
  if (retryAfter > 0) {
    res.set('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Too many sign-in attempts. Please try again later.' });
  }

  const password = req.body?.password;
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required.' });
  }
  const usernameRaw = typeof req.body?.username === 'string' ? req.body.username.trim() : '';

  try {
    const ok = await bcrypt.compare(password, appPasswordHash);
    if (!ok) {
      recordLoginFailure(ip);
      return res.status(401).json({ error: 'Invalid credentials.' });
    }
    // Password is correct; if a username was supplied it must be a known staff name.
    let displayName = '';
    if (usernameRaw) {
      displayName = resolveAppUser(usernameRaw);
      if (!displayName) {
        return res
          .status(401)
          .json({ error: `Unknown user. Choose one of: ${appUsers.join(', ')}.` });
      }
    }
    loginFailures.delete(ip);
    const sessionToken = jwt.sign(
      { v: 1, name: displayName || undefined },
      sessionJwtSecret,
      { expiresIn: sessionMaxAgeSec, subject: displayName ? displayName.toLowerCase() : 'pbsg' }
    );
    return res.json({
      token: sessionToken,
      expiresIn: sessionMaxAgeSec,
      name: displayName,
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
      ourSmsE164s: listOurSmsE164sForClient(),
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
 * Fast inbox list: read straight from participantConversations, which already
 * includes friendlyName + dateUpdated for every thread the inbox identity is in.
 * No full-conversation scan, no per-SID fetch, no writes on the hot path — this
 * is what the "Connecting to inbox…" screen waits on, so keep it cheap.
 * @returns {Array<{ sid: string, friendlyName: string|null, dateUpdated: number }>}
 */
async function listInboxConversations() {
  const rows = [];
  let pcPage = await twilioClient.conversations.v1
    .services(serviceSid)
    .participantConversations.page({
      identity: twilioChatIdentity,
      pageSize: 100,
    });
  for (;;) {
    for (const row of pcPage.instances) {
      if (!row.conversationSid) continue;
      rows.push({
        sid: row.conversationSid,
        friendlyName: row.conversationFriendlyName,
        dateUpdated: row.conversationDateUpdated?.getTime?.() ?? 0,
      });
    }
    if (!pcPage.nextPageUrl) break;
    pcPage = await pcPage.nextPage();
  }
  return rows;
}

/**
 * Recovery for service-created threads that never got the inbox identity added
 * (e.g. created before the post-event webhook existed). This is the slow
 * full-conversation scan + ensureChatParticipant; run it in the BACKGROUND on a
 * throttle so it never blocks GET /api/conversation-sids. Newly-joined threads
 * then appear on the next inbox load (participantConversations returns them).
 */
let recoveryInFlight = false;
let lastRecoveryAt = 0;
const RECOVERY_THROTTLE_MS = 5 * 60 * 1000;

function maybeRunBackgroundRecovery() {
  const now = Date.now();
  if (recoveryInFlight || now - lastRecoveryAt < RECOVERY_THROTTLE_MS) return;
  recoveryInFlight = true;
  lastRecoveryAt = now;
  (async () => {
    const known = new Set();
    let pcPage = await twilioClient.conversations.v1
      .services(serviceSid)
      .participantConversations.page({ identity: twilioChatIdentity, pageSize: 100 });
    for (;;) {
      for (const row of pcPage.instances) {
        if (row.conversationSid) known.add(row.conversationSid);
      }
      if (!pcPage.nextPageUrl) break;
      pcPage = await pcPage.nextPage();
    }
    let convPage = await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations.page({ pageSize: 50 });
    let joined = 0;
    for (;;) {
      for (const conv of convPage.instances) {
        const sid = conv.sid;
        if (!sid || known.has(sid)) continue;
        try {
          await ensureChatParticipantInConversation(sid);
          known.add(sid);
          joined++;
        } catch (e) {
          console.warn('background recovery join failed', sid, e?.message);
        }
      }
      if (!convPage.nextPageUrl) break;
      convPage = await convPage.nextPage();
    }
    if (joined) console.log(`background recovery joined ${joined} conversation(s).`);
  })()
    .catch((e) => console.warn('background recovery error:', e?.message || e))
    .finally(() => {
      recoveryInFlight = false;
    });
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

function collapseConversations(rows) {
  const byKey = new Map();
  for (const row of rows) {
    const key = conversationThreadKey(row.friendlyName, row.sid);
    const prev = byKey.get(key);
    if (!prev || row.dateUpdated >= prev.dateUpdated) {
      byKey.set(key, row);
    }
  }
  return [...byKey.values()]
    .sort((a, b) => b.dateUpdated - a.dateUpdated)
    .map((x) => x.sid);
}

/**
 * GET /api/conversation-sids
 * Header: Authorization: Bearer <sessionJwt>
 */
app.get('/api/conversation-sids', requireSession, async (_req, res) => {
  try {
    const rows = await listInboxConversations();
    const conversationSids = collapseConversations(rows);
    // Kick off recovery of any unjoined historical threads without blocking the
    // response; results appear on the next load.
    maybeRunBackgroundRecovery();
    return res.json({ conversationSids });
  } catch (err) {
    console.error('List conversations error:', err);
    return res.status(500).json({ error: 'Failed to list conversations.' });
  }
});

/**
 * GET /api/settings
 * Server-side UI settings. Templates are scoped to the authenticated user;
 * hideRecruitment remains shared across the team.
 */
app.get('/api/settings', requireSession, (req, res) => {
  try {
    return res.json({ settings: readSettings(req.sessionUserKey) });
  } catch (err) {
    console.error('Settings read error:', err);
    return res.status(500).json({ error: 'Failed to load settings.' });
  }
});

/**
 * PUT /api/settings
 * Body: { hideRecruitment?: boolean, templates?: Array, soundVolume?: number(0..1) }
 * Only keys present in the body are applied (partial update).
 */
app.put('/api/settings', requireSession, (req, res) => {
  try {
    // Only apply keys the client actually sent (so a templates-only update does
    // not reset hideRecruitment, and vice versa).
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const patch = {};
    if ('hideRecruitment' in body) patch.hideRecruitment = body.hideRecruitment;
    if ('templates' in body) patch.templates = body.templates;
    if ('soundVolume' in body) patch.soundVolume = body.soundVolume;
    const settings = updateSettings(patch, req.sessionUserKey);
    return res.json({ ok: true, settings });
  } catch (err) {
    console.error('Settings write error:', err);
    return res.status(500).json({ error: 'Failed to save settings.' });
  }
});

/**
 * GET /api/contact-labels
 * Display names + details per conversation SID (does not change Twilio friendlyName).
 */
app.get('/api/contact-labels', requireSession, (_req, res) => {
  try {
    return res.json({ labels: readAllContactLabels() });
  } catch (err) {
    console.error('Contact labels read error:', err);
    return res.status(500).json({ error: 'Failed to load contact labels.' });
  }
});

/**
 * PUT /api/contact-labels
 * Body: { conversationSid, name?, details? } — empty name and details removes the label row.
 */
app.put('/api/contact-labels', requireSession, (req, res) => {
  const conversationSid = req.body?.conversationSid;
  if (!conversationSid || typeof conversationSid !== 'string') {
    return res.status(400).json({ error: 'conversationSid is required.' });
  }
  try {
    const label = upsertContactLabel(conversationSid, {
      name: req.body?.name,
      details: req.body?.details,
    });
    return res.json({ ok: true, label });
  } catch (err) {
    console.error('Contact labels write error:', err);
    return res.status(500).json({ error: err?.message || 'Failed to save contact label.' });
  }
});

/**
 * DELETE /api/twilio-conversations/:sid
 * Removes the conversation from Twilio Conversations (and local label for that SID).
 */
app.delete('/api/twilio-conversations/:sid', requireSession, async (req, res) => {
  const sid = String(req.params.sid || '').trim();
  if (!sid) {
    return res.status(400).json({ error: 'Conversation SID is required.' });
  }
  try {
    await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(sid)
      .remove();
    removeContactLabel(sid);
    return res.json({ ok: true });
  } catch (err) {
    console.error('Delete Twilio conversation error:', err);
    const msg = err?.message || 'Failed to delete conversation.';
    return res.status(500).json({ error: msg });
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
  let decoded;
  try {
    decoded = decodeURIComponent(raw.trim());
  } catch {
    // Malformed percent-encoding (e.g. a lone "%") otherwise throws URIError
    // and surfaces as a 500 via the global handler.
    return res.status(400).json({ error: 'Invalid customer phone.' });
  }
  const c = canonicalCustomerE164(decoded);
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

/**
 * POST /api/messages
 * Send an outbound SMS to a customer (creating the conversation if needed) and
 * optionally tag the contact with a display name + details. Used by automation
 * (e.g. the recruiter pipeline) to text a candidate and label them "Recruitment".
 *
 * Body: { to: string, body: string, name?: string, details?: string }
 * Auth: requireSession (Bearer session JWT from POST /api/login).
 * Returns: { ok, conversationSid, to, created, label }
 *
 * The message is authored as the chat identity, exactly like the web app's
 * conversation.sendMessage(), so Twilio relays it to the SMS participant.
 */
app.post('/api/messages', requireSession, async (req, res) => {
  const phone = toE164Australian(req.body?.to);
  if (!phone.ok) {
    return res.status(400).json({ error: phone.error });
  }
  const body = typeof req.body?.body === 'string' ? req.body.body.trim() : '';
  if (!body) {
    return res.status(400).json({ error: 'Message body is required.' });
  }

  try {
    const { conversationSid: sid, created } =
      await findOrCreateConversationForCustomerAddress(phone.e164);

    await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(sid)
      .messages.create({ author: twilioChatIdentity, body });

    // Optional contact label (name + free-text details, e.g. details: "Recruitment").
    // Best-effort: a label failure must not fail an already-sent SMS.
    let label = null;
    const name = typeof req.body?.name === 'string' ? req.body.name : undefined;
    const details = typeof req.body?.details === 'string' ? req.body.details : undefined;
    if ((name && name.trim()) || (details && details.trim())) {
      try {
        label = upsertContactLabel(sid, { name, details });
      } catch (labelErr) {
        console.error('Send message: contact label write failed:', labelErr);
      }
    }

    return res.status(created ? 201 : 200).json({
      ok: true,
      conversationSid: sid,
      to: phone.e164,
      created,
      label,
    });
  } catch (err) {
    console.error('Send message error:', err);
    return res.status(500).json({ error: err?.message || 'Failed to send message.' });
  }
});

/**
 * Studio-triggered inbound push fallback.
 * Use this from Twilio Studio on inbound message path to guarantee first-message alerts
 * even when Conversations post-event webhooks are delayed/missing for conversation creation.
 *
 * Optional header auth:
 *  - Set STUDIO_PUSH_WEBHOOK_SECRET in backend env
 *  - Send matching header x-pbsg-studio-secret from Studio HTTP Request widget
 */
app.post('/api/push/studio-inbound', async (req, res) => {
  try {
    const expectedSecret = String(process.env.STUDIO_PUSH_WEBHOOK_SECRET || '').trim();
    if (!expectedSecret) {
      // Fail CLOSED: with no shared secret configured this endpoint could be
      // used by anyone to spam push to all staff. ALLOW_UNSIGNED_WEBHOOKS is
      // the only (dev-only) bypass.
      if (!allowUnsignedWebhooks()) {
        console.error('STUDIO_PUSH_WEBHOOK_SECRET not set; rejecting studio-inbound request.');
        return res.status(403).json({ error: 'Forbidden.' });
      }
    } else {
      const gotSecret = String(req.headers['x-pbsg-studio-secret'] || '').trim();
      if (!gotSecret || gotSecret !== expectedSecret) {
        return res.status(403).json({ error: 'Forbidden.' });
      }
    }
    const conversationSid = String(req.body?.conversationSid || req.body?.ConversationSid || '');
    const messageSid = String(
      req.body?.messageSid || req.body?.MessageSid || req.body?.SmsSid || req.body?.smsSid || ''
    );
    const author = String(req.body?.author || req.body?.Author || '');
    const bodyText = String(req.body?.body || req.body?.Body || '');
    if (wasPushedForMessageSid(messageSid)) {
      return res.json({ ok: true, deduped: true });
    }
    if (
      author &&
      (author === 'system' || author === twilioChatIdentity) &&
      !String(req.body?.force || '').trim()
    ) {
      return res.json({ ok: true, skipped: 'self_or_system_author' });
    }
    const hasPushTargets =
      (webPushEnabled() && pushSubscriptions.size > 0) ||
      (firebaseMessaging && nativePushTokens.size > 0);
    if (!hasPushTargets) {
      return res.json({ ok: true, skipped: 'no_subscribers' });
    }
    // Commit the dedup SID only now that we will actually send, so a skipped
    // call (self/system author, or no subscribers) does not suppress a later one.
    markPushedForMessageSid(messageSid);
    const preview = pushPreviewText(bodyText) || 'New conversation started';
    const notifyPayload = {
      title: 'New message',
      body: preview,
      url: '/',
      conversationSid: conversationSid || null,
      messageSid: messageSid || null,
    };
    let webPushSent = false;
    let nativePushSent = false;
    let webPushError = null;
    let nativePushError = null;
    if (webPushEnabled() && pushSubscriptions.size > 0) {
      try {
        await sendWebPushToAll(notifyPayload);
        webPushSent = true;
      } catch (e) {
        webPushError = e?.message || String(e);
        console.warn('Studio inbound web push error:', webPushError);
      }
    }
    if (firebaseMessaging && nativePushTokens.size > 0) {
      try {
        await sendNativePushToAll(notifyPayload);
        nativePushSent = true;
      } catch (e) {
        nativePushError = e?.message || String(e);
        console.warn('Studio inbound native push error:', nativePushError);
      }
    }
    return res.json({
      ok: true,
      sent: webPushSent || nativePushSent,
      webPushSent,
      nativePushSent,
      webPushError,
      nativePushError,
    });
  } catch (err) {
    console.error('Studio inbound push error:', err);
    return res.status(500).json({ error: 'Failed to send studio inbound push.', detail: err?.message || String(err) });
  }
});

/**
 * /api/health is public (Railway healthcheck), so strip the customer-identifying
 * `author` (inbound webhook author is the customer's phone number) from the webhook
 * snapshots. Keep signatureValid/event/status/SIDs for diagnostics.
 */
function publicWebhookSnapshot(w) {
  if (!w || typeof w !== 'object') return w;
  const { author, ...rest } = w;
  return { ...rest, hasAuthor: Boolean(author) };
}

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
    nativePushLastFailures,
    lastConversationsWebhook: publicWebhookSnapshot(lastConversationsWebhook),
    recentConversationsWebhooks: recentConversationsWebhooks.map(publicWebhookSnapshot),
  });
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

// Process-level safety net. A stray unhandled rejection would otherwise
// terminate the process on Node 20+ (default --unhandled-rejections=throw),
// dropping in-flight webhooks and all in-memory state on this single instance.
// Log and keep serving for a rejection; exit on an uncaughtException (the
// process is then in an undefined state) so Railway can restart cleanly.
process.on('unhandledRejection', (err) => {
  console.error('unhandledRejection:', err);
});
process.on('uncaughtException', (err) => {
  console.error('uncaughtException:', err);
  process.exit(1);
});

const server = app.listen(PORT, () => {
  console.log(`PBSG Messenger API listening on http://localhost:${PORT}`);
});
server.on('error', (err) => {
  console.error('Failed to start HTTP server on port', PORT, '-', err?.message || err);
  process.exit(1);
});
