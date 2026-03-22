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

function validateTwilioConversationsWebhook(req) {
  if (!twilioAuthToken) {
    console.warn(
      'TWILIO_AUTH_TOKEN not set; Conversations webhook signature verification is disabled.'
    );
    return true;
  }
  const sig = req.headers['x-twilio-signature'];
  if (!sig) return false;
  const url = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
  return twilio.validateRequest(twilioAuthToken, sig, url, req.body);
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
 * Enable event: onConversationAdded (and URL must be reachable publicly).
 *
 * Also ensure inbound SMS can reach Conversations (see Twilio "Inbound autocreation"
 * and avoid a conflicting "A message comes in" handler on the number when possible).
 */
app.post(
  '/api/webhooks/twilio/conversations',
  express.urlencoded({ extended: false }),
  async (req, res) => {
    if (!validateTwilioConversationsWebhook(req)) {
      return res.status(403).send('Forbidden');
    }
    const event = req.body.EventType || req.body.eventType;
    const convSid = req.body.ConversationSid || req.body.conversationSid;
    if (event === 'onConversationAdded' && convSid) {
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

app.post('/api/conversations', requireSession, async (req, res) => {
  const phone = toE164Australian(req.body?.to);
  if (!phone.ok) {
    return res.status(400).json({ error: phone.error });
  }

  const proxy = twilioPhone.trim().startsWith('+')
    ? twilioPhone.trim()
    : `+${twilioPhone.replace(/\D/g, '')}`;

  try {
    const conversation = await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations.create({
        friendlyName: `SMS ${phone.e164}`,
      });

    await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(conversation.sid)
      .participants.create({
        identity: twilioChatIdentity,
      });

    await twilioClient.conversations.v1
      .services(serviceSid)
      .conversations(conversation.sid)
      .participants.create({
        'messagingBinding.address': phone.e164,
        'messagingBinding.proxyAddress': proxy,
      });

    return res.status(201).json({
      conversationSid: conversation.sid,
      friendlyName: conversation.friendlyName,
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
