/**
 * Normalise user input to E.164, with Australian mobile assumptions.
 * Accepts 04xx, 4xxxxxxxx, +61, 61..., spaces and dashes.
 */
export function toE164Australian(input) {
  if (!input || typeof input !== 'string') {
    return { ok: false, error: 'Phone number is required.' };
  }

  const trimmed = input.trim();
  const digitsOnly = trimmed.replace(/\D/g, '');

  if (!digitsOnly) {
    return { ok: false, error: 'Phone number is empty.' };
  }

  // Already country code 61
  if (digitsOnly.startsWith('61') && digitsOnly.length >= 11) {
    return { ok: true, e164: `+${digitsOnly}` };
  }

  // Australian mobile: 04xx → +614xx
  if (digitsOnly.startsWith('0') && digitsOnly.length >= 10) {
    return { ok: true, e164: `+61${digitsOnly.slice(1)}` };
  }

  // 4xxxxxxxx (9 digits starting with 4) — mobile without leading 0
  if (digitsOnly.startsWith('4') && digitsOnly.length === 9) {
    return { ok: true, e164: `+61${digitsOnly}` };
  }

  // Fallback: if user pasted full international without +
  if (digitsOnly.length >= 10) {
    return { ok: true, e164: `+${digitsOnly}` };
  }

  return {
    ok: false,
    error:
      'Could not parse phone number. Use Australian format (e.g. 0412 345 678) or E.164.',
  };
}
