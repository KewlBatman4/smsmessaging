/**
 * Normalise user input to E.164, with Australian mobile assumptions.
 * Accepts 04xx, 4xxxxxxxx, +61, 61..., AU international prefixes (0011/00),
 * spaces and dashes.
 */

/** ITU-T E.164 allows at most 15 digits; require a sane minimum too. */
function e164FromDigits(digits) {
  if (digits.length < 8 || digits.length > 15) {
    return {
      ok: false,
      error:
        'Could not parse phone number. Use Australian format (e.g. 0412 345 678) ' +
        'or full international (e.g. +1 415 555 1234).',
    };
  }
  return { ok: true, e164: `+${digits}` };
}

export function toE164Australian(input) {
  if (!input || typeof input !== 'string') {
    return { ok: false, error: 'Phone number is required.' };
  }

  const trimmed = input.trim();
  const digitsOnly = trimmed.replace(/\D/g, '');

  if (!digitsOnly) {
    return { ok: false, error: 'Phone number is empty.' };
  }

  // International dialling prefixes MUST be handled before the local 0-prefix
  // rule below, otherwise 0061.../0011... get mangled into a wrong country
  // code (e.g. 0061412345678 -> +61061412345678 -> SMS misdelivery).
  // 0011 = Australian IDD; 00 = ITU international prefix. Strip and prepend +.
  if (digitsOnly.startsWith('0011')) {
    return e164FromDigits(digitsOnly.slice(4));
  }
  if (digitsOnly.startsWith('00')) {
    return e164FromDigits(digitsOnly.slice(2));
  }

  // Already country code 61
  if (digitsOnly.startsWith('61') && digitsOnly.length >= 11) {
    return { ok: true, e164: `+${digitsOnly}` };
  }

  // Australian mobile/local: 04xx / 0x... → +61x...
  if (digitsOnly.startsWith('0') && digitsOnly.length >= 10) {
    return { ok: true, e164: `+61${digitsOnly.slice(1)}` };
  }

  // 4xxxxxxxx (9 digits starting with 4) — mobile without leading 0
  if (digitsOnly.startsWith('4') && digitsOnly.length === 9) {
    return { ok: true, e164: `+61${digitsOnly}` };
  }

  // Fallback: full international number pasted without + (best effort).
  // Bounded to a valid E.164 length so garbage is rejected rather than sent.
  if (digitsOnly.length >= 10) {
    return e164FromDigits(digitsOnly);
  }

  return {
    ok: false,
    error:
      'Could not parse phone number. Use Australian format (e.g. 0412 345 678) or E.164.',
  };
}
