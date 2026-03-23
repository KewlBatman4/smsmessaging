/**
 * Delete every Conversation in TWILIO_CONVERSATIONS_SERVICE_SID (Twilio-side).
 * The web app has no separate local inbox — it always reads from Twilio — so this
 * is how you get an empty sidebar to retest "Sync inbox".
 *
 * SMS/MMS rows in Programmable Messaging logs are NOT deleted.
 *
 * From backend/ with .env loaded:
 *
 *   PowerShell:
 *     $env:WIPE_CONVERSATIONS_CONFIRM='DELETE_ALL_CONVERSATIONS_IN_THIS_SERVICE'; npm run wipe-conversations
 *
 *   cmd.exe:
 *     set WIPE_CONVERSATIONS_CONFIRM=DELETE_ALL_CONVERSATIONS_IN_THIS_SERVICE && npm run wipe-conversations
 */
import 'dotenv/config';
import twilio from 'twilio';

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const apiKey = process.env.TWILIO_API_KEY;
const apiSecret = process.env.TWILIO_API_SECRET;
const serviceSid = process.env.TWILIO_CONVERSATIONS_SERVICE_SID;
const confirm = process.env.WIPE_CONVERSATIONS_CONFIRM;

const REQUIRED = 'DELETE_ALL_CONVERSATIONS_IN_THIS_SERVICE';

if (!accountSid || !apiKey || !apiSecret || !serviceSid) {
  console.error(
    'Missing TWILIO_ACCOUNT_SID, TWILIO_API_KEY, TWILIO_API_SECRET, or TWILIO_CONVERSATIONS_SERVICE_SID in .env'
  );
  process.exit(1);
}

if (confirm !== REQUIRED) {
  console.error(`
Refusing to run: this deletes every conversation in service ${serviceSid}.

Set exactly (same spelling, case-sensitive):

  WIPE_CONVERSATIONS_CONFIRM=${REQUIRED}

Then run: npm run wipe-conversations
`);
  process.exit(1);
}

const client = twilio(apiKey, apiSecret, { accountSid });

let removed = 0;
let failed = 0;

try {
  let page = await client.conversations.v1.services(serviceSid).conversations.page({
    pageSize: 50,
  });
  for (;;) {
    for (const conv of page.instances) {
      try {
        await client.conversations.v1
          .services(serviceSid)
          .conversations(conv.sid)
          .remove();
        removed++;
        console.log('Removed', conv.sid, conv.friendlyName || '');
      } catch (e) {
        failed++;
        console.error('Failed', conv.sid, e.message || e);
      }
    }
    if (!page.nextPageUrl) break;
    page = await page.nextPage();
  }
} catch (e) {
  console.error('List/delete error:', e.message || e);
  process.exit(1);
}

console.log(`\nDone. Removed ${removed} conversation(s). Failed: ${failed}.`);
console.log('Reload the web app (or log out/in). Use Sync inbox to repopulate from the SMS log.\n');
