/**
 * TOTP (RFC 6238) implementation for Cloudflare Workers using Web Crypto API.
 * No external dependencies — pure base32 + HMAC-SHA1.
 */

const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // ±1 period (30s each side) for clock drift

// ── Base32 ──────────────────────────────────────────────────────────────────

const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer) {
  const bytes = new Uint8Array(buffer);
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  let result = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    result += BASE32_CHARS[parseInt(chunk, 2)];
  }
  return result;
}

function base32Decode(str) {
  const cleaned = str.replace(/[=\s]/g, '').toUpperCase();
  let bits = '';
  for (const c of cleaned) {
    const idx = BASE32_CHARS.indexOf(c);
    if (idx === -1) throw new Error('Invalid base32 character');
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = new Uint8Array(Math.floor(bits.length / 8));
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }
  return bytes;
}

// ── HMAC-SHA1 TOTP Core ─────────────────────────────────────────────────────

async function hmacSha1(secret, counter) {
  const key = await crypto.subtle.importKey(
    'raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  const counterBuf = new ArrayBuffer(8);
  const view = new DataView(counterBuf);
  view.setUint32(4, counter); // 64-bit big-endian, high 32 bits are 0
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));
}

function dynamicTruncate(hmac) {
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  );
  return code % (10 ** TOTP_DIGITS);
}

async function generateCode(secret, counter) {
  const hmac = await hmacSha1(secret, counter);
  return dynamicTruncate(hmac).toString().padStart(TOTP_DIGITS, '0');
}

// ── Public API ──────────────────────────────────────────────────────────────

export function generateSecret() {
  const bytes = new Uint8Array(20); // 160-bit secret
  crypto.getRandomValues(bytes);
  return base32Encode(bytes);
}

export function generateTotpUri(secret, email, issuer = 'vaultdotenv') {
  const label = encodeURIComponent(`${issuer}:${email}`);
  const params = `secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD}`;
  return `otpauth://totp/${label}?${params}`;
}

export async function verifyTotp(secret, code) {
  const secretBytes = base32Decode(secret);
  const now = Math.floor(Date.now() / 1000);
  const currentCounter = Math.floor(now / TOTP_PERIOD);

  for (let i = -TOTP_WINDOW; i <= TOTP_WINDOW; i++) {
    const expected = await generateCode(secretBytes, currentCounter + i);
    if (expected === code) return true;
  }
  return false;
}
