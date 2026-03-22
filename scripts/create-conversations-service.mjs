/**
 * Create a Twilio Conversations service (SID starts with IS) via the API.
 * Use this when the Console wizard blocks you or pages 404.
 *
 * Requires in backend/.env:
 *   TWILIO_ACCOUNT_SID, TWILIO_API_KEY, TWILIO_API_SECRET
 *
 * Usage (from backend folder):
 *   npm run create-conversations-service
 *
 * Then set TWILIO_CONVERSATIONS_SERVICE_SID in .env and Railway to the printed IS...
 */
import 'dotenv/config';
import twilio from 'twilio';

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const apiKey = process.env.TWILIO_API_KEY;
const apiSecret = process.env.TWILIO_API_SECRET;
const name =
  process.argv[2] || process.env.CONVERSATIONS_SERVICE_NAME || 'PBSG Messenger';

if (!accountSid || !apiKey || !apiSecret) {
  console.error(
    'Missing TWILIO_ACCOUNT_SID, TWILIO_API_KEY, or TWILIO_API_SECRET in backend/.env'
  );
  process.exit(1);
}

const client = twilio(apiKey, apiSecret, { accountSid });

try {
  const service = await client.conversations.v1.services.create({
    friendlyName: name,
  });
  console.log('\nCreated Conversations service:\n');
  console.log('  TWILIO_CONVERSATIONS_SERVICE_SID=' + service.sid);
  console.log('\nAdd that line to backend/.env and to Railway Variables.\n');
} catch (err) {
  console.error('\nTwilio API error:', err.message || err);
  if (err.code === 20003 || /Authenticate/i.test(String(err.message))) {
    console.error('\nCheck API Key SID (SK…) and secret match your account.\n');
  }
  if (err.code === 20404) {
    console.error(
      '\nConversations may not be enabled for this account. Open a Twilio support ticket or enable Conversations in Console.\n'
    );
  }
  process.exit(1);
}
