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

/**
 * Use Twilio Message `direction` first (correct for Zapier / Messaging Service).
 * Falls back to From/To vs TWILIO_PHONE_NUMBER (+ TWILIO_SMS_FROM_ALIASES).
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
 */
async function findOrCreateConversationForCustomerAddress(customerAddress) {
  const rows = await listParticipantConversationRowsForAddress(customerAddress);
  const existing = pickConversationSidForCustomer(rows);
  if (existing) return existing;
  const parsed = toE164Australian(customerAddress);
  const e164 = parsed.ok ? parsed.e164 : customerAddress.trim();
  return createSmsConversationForCustomerE164(e164);
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

async function pageAllProgrammableMessages(listParams) {
  const out = [];
  let page = await twilioClient.messages.page({
    ...listParams,
    pageSize: 100,
  });
  for (let i = 0; i < SMS_LOG_MAX_PAGES_PER_DIRECTION; i++) {
    out.push(...page.instances);
    if (!page.nextPageUrl) break;
    page = await page.nextPage();
  }
  return out;
}

/**
 * Pull Twilio Programmable Messaging (SMS log) and append missing rows into Conversations
 * so the web app can show traffic that never entered the Conversation service.
 */
async function syncProgrammableSmsLogIntoConversations(daysBack) {
  const our = proxyNumberE164();
  const dateSentAfter = new Date(Date.now() - Math.min(Math.max(daysBack, 1), 90) * 86400000);
  /** Bulk sync of *outbound* log rows can cause Twilio to deliver those rows again on the SMS leg — off by default. */
  const allowOutboundMirror = ['true', '1', 'yes'].includes(
    String(process.env.SMS_LOG_SYNC_OUTBOUND_MIRROR || '').toLowerCase()
  );

  const [toUs, fromUs] = await Promise.all([
    pageAllProgrammableMessages({ to: our, dateSentAfter }),
    pageAllProgrammableMessages({ from: our, dateSentAfter }),
  ]);

  const bySid = new Map();
  for (const m of toUs) bySid.set(m.sid, m);
  for (const m of fromUs) bySid.set(m.sid, m);
  const merged = [...bySid.values()].sort(
    (a, b) => (a.dateSent?.getTime?.() ?? 0) - (b.dateSent?.getTime?.() ?? 0)
  );

  let imported = 0;
  let skipped = 0;
  let skippedOutboundPolicy = 0;
  const convTouched = new Set();

  for (const sm of merged) {
    const { kind, customer } = classifyProgrammableSms(sm);
    if (!customer || kind === 'unknown') {
      skipped++;
      continue;
    }

    let bodyText = sm.body != null ? String(sm.body) : '';
    if (!bodyText.trim() && (sm.numMedia ?? 0) > 0) bodyText = '[Media]';
    if (!bodyText.trim()) bodyText = ' ';

    try {
      const convSid = await findOrCreateConversationForCustomerAddress(customer);
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
    scanned: merged.length,
    conversationsTouched: convTouched.size,
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
 * Twilio Conversations so PBSG Messenger shows the same thread. Uses Author=system plus
 * JSON attributes so we do not trigger a second SMS to the customer.
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
    const direction = (req.body.Direction || '').toLowerCase();

    if (!messageSid || statusRaw !== 'sent') {
      return res.status(200).end();
    }
    if (direction && !direction.startsWith('outbound')) {
      return res.status(200).end();
    }

    const from = req.body.From;
    const to = req.body.To;
    if (!from || !to || !fromMatchesAnyOurSender(from)) {
      return res.status(200).end();
    }

    if (mirroredProgrammableMessageSids.has(messageSid)) {
      return res.status(200).end();
    }

    let bodyText = typeof req.body.Body === 'string' ? req.body.Body : '';
    if (!bodyText && req.body.NumMedia && Number(req.body.NumMedia) > 0) {
      bodyText = '[Media]';
    }

    try {
      if (!bodyText) {
        const m = await twilioClient.messages(messageSid).fetch();
        bodyText = (m.body && String(m.body)) || '';
      }
    } catch (e) {
      console.warn('programmable-messaging webhook: could not fetch message body', messageSid, e?.message);
    }

    try {
      const convSid = await findOrCreateConversationForCustomerAddress(to);
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
  return [...new Set(sids)];
}

/**
 * GET /api/conversation-sids
 * Header: Authorization: Bearer <sessionJwt>
 */
app.get('/api/conversation-sids', requireSession, async (_req, res) => {
  try {
    const conversationSids = await listConversationSidsForIdentity();
    return res.json({ conversationSids });
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
 * Reads Twilio Programmable Messaging (the SMS/MMS log in Console) and mirrors each
 * message into the matching Conversation so the inbox matches what you see under Logs.
 */
app.post('/api/sync-sms-log', requireSession, async (req, res) => {
  const raw = req.body?.daysBack;
  const daysBack =
    typeof raw === 'number' && Number.isFinite(raw)
      ? raw
      : typeof raw === 'string'
        ? Number.parseInt(raw, 10)
        : 30;
  try {
    const result = await syncProgrammableSmsLogIntoConversations(
      Number.isFinite(daysBack) ? daysBack : 30
    );
    return res.json(result);
  } catch (err) {
    console.error('Sync SMS log error:', err);
    return res.status(500).json({ error: err?.message || 'SMS log sync failed.' });
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
    const sid = await createSmsConversationForCustomerE164(phone.e164);
    const conv = await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(sid)
      .fetch();
    return res.status(201).json({
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
