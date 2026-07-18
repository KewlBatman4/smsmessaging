/**
 * Missed-call → messenger thread logic (pure helpers; no Twilio calls).
 *
 * A missed call is recorded in the customer's conversation as an inbound-style
 * marker message ("📞 Missed call", authored by the customer's number), and the
 * AI-generated follow-up SMS may be sent AT MOST once per customer per rolling
 * 7-day window, anchored at the last successful send.
 *
 * State lives in the conversation's JSON attributes (NOT server memory, so the
 * guard survives Railway restarts/redeploys) under `pbsgMissedCall`:
 *   {
 *     lastCallSid: string|null,      // dedupes a re-fired Studio widget for the same call
 *     lastMissedCallAt: ISO string,  // when the last marker was recorded
 *     autoSmsLastSentAt: ISO string, // anchors the 7-day send guard
 *     autoSmsLastCallSid: string|null
 *   }
 */

export const MISSED_CALL_SMS_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1000;
export const MISSED_CALL_MARKER_BODY = '📞 Missed call';

/** Conversation attributes arrive as a JSON string (or object); junk → {}. */
export function parseConversationAttributes(raw) {
  if (!raw) return {};
  let value = raw;
  if (typeof raw === 'string') {
    try {
      value = JSON.parse(raw);
    } catch {
      return {};
    }
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return value;
}

function missedCallState(attrs) {
  const mc = attrs?.pbsgMissedCall;
  if (!mc || typeof mc !== 'object' || Array.isArray(mc)) return {};
  return mc;
}

/**
 * Decide what to do for an incoming missed-call event.
 * @param {string|object|null} attributesRaw current conversation attributes
 * @param {{ callSid?: string, now: number }} opts now = epoch ms
 * @returns {{ deduped: boolean, canSendSms: boolean, skipReason: string|null, nextAllowedAt: string|null }}
 */
export function evaluateMissedCall(attributesRaw, { callSid, now }) {
  const mc = missedCallState(parseConversationAttributes(attributesRaw));
  const sid = String(callSid || '').trim();
  if (sid && mc.lastCallSid === sid) {
    return { deduped: true, canSendSms: false, skipReason: 'duplicate_call', nextAllowedAt: null };
  }
  const lastSentMs = Date.parse(String(mc.autoSmsLastSentAt || ''));
  if (Number.isFinite(lastSentMs) && now - lastSentMs < MISSED_CALL_SMS_COOLDOWN_MS) {
    return {
      deduped: false,
      canSendSms: false,
      skipReason: 'cooldown',
      nextAllowedAt: new Date(lastSentMs + MISSED_CALL_SMS_COOLDOWN_MS).toISOString(),
    };
  }
  return { deduped: false, canSendSms: true, skipReason: null, nextAllowedAt: null };
}

/** New attributes object with the missed-call marker recorded; other keys preserved. */
export function withMissedCallMarker(attributesRaw, { callSid, now }) {
  const attrs = parseConversationAttributes(attributesRaw);
  return {
    ...attrs,
    pbsgMissedCall: {
      ...missedCallState(attrs),
      lastCallSid: String(callSid || '').trim() || null,
      lastMissedCallAt: new Date(now).toISOString(),
    },
  };
}

/**
 * New attributes object with the auto-SMS guard fields set (reservation) or
 * restored/cleared (rollback after a failed send). Pass null/undefined to clear.
 */
export function withAutoSmsFields(attributesRaw, { lastSentAt, lastCallSid }) {
  const attrs = parseConversationAttributes(attributesRaw);
  const mc = { ...missedCallState(attrs) };
  if (lastSentAt === null || lastSentAt === undefined) {
    delete mc.autoSmsLastSentAt;
  } else {
    mc.autoSmsLastSentAt = lastSentAt;
  }
  if (lastCallSid === null || lastCallSid === undefined) {
    delete mc.autoSmsLastCallSid;
  } else {
    mc.autoSmsLastCallSid = lastCallSid;
  }
  return { ...attrs, pbsgMissedCall: mc };
}
