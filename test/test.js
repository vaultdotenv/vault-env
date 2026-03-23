'use strict';

const { encrypt, decrypt, sign, verify, generateVaultKey, parseVaultKey, generateDeviceSecret, hashDeviceSecret } = require('../src/crypto');

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) { passed++; console.log(`  PASS: ${msg}`); }
  else { failed++; console.error(`  FAIL: ${msg}`); }
}

console.log('\n=== Vault Crypto Tests ===\n');

// Key generation
const key = generateVaultKey('testproject');
assert(key.startsWith('vk_testproject_'), 'Key starts with vk_projectId_');
assert(key.length > 30, 'Key is long enough');

// Key parsing
const parsed = parseVaultKey(key);
assert(parsed.projectId === 'testproject', 'Parsed project ID');
assert(parsed.secret.length === 64, 'Parsed secret is 64 hex chars');

// Encryption roundtrip (no device secret — backward compat)
const plaintext = JSON.stringify({ DB_HOST: 'localhost', DB_PASS: 'supersecret', API_KEY: 'sk_live_abc123' });
const encrypted = encrypt(plaintext, key);
assert(encrypted !== plaintext, 'Encrypted differs from plaintext');
const decrypted = decrypt(encrypted, key);
assert(decrypted === plaintext, 'Decrypt returns original');

// Wrong key fails
try {
  const wrongKey = generateVaultKey('other');
  decrypt(encrypted, wrongKey);
  assert(false, 'Wrong key should throw');
} catch {
  assert(true, 'Wrong key throws error');
}

// Signing roundtrip (no device secret)
const body = '{"project_id":"test","environment":"production"}';
const { signature } = sign(key, body);
assert(signature.startsWith('v='), 'Signature starts with v=');
assert(signature.includes(',d='), 'Signature contains ,d=');

const { valid } = verify(key, body, signature);
assert(valid === true, 'Valid signature verifies');

// Tampered body fails
const { valid: invalid } = verify(key, body + 'x', signature);
assert(invalid === false, 'Tampered body fails verification');

// Wrong key fails
const wrongKey2 = generateVaultKey('wrong');
const { valid: invalid2 } = verify(wrongKey2, body, signature);
assert(invalid2 === false, 'Wrong key fails verification');

// Multiple encrypt/decrypt cycles produce different ciphertext (random IV)
const enc1 = encrypt(plaintext, key);
const enc2 = encrypt(plaintext, key);
assert(enc1 !== enc2, 'Different encryptions produce different ciphertext');
assert(decrypt(enc1, key) === decrypt(enc2, key), 'Both decrypt to same plaintext');

// ── Device Secret Tests ──────────────────────────────────────────────────────

console.log('\n=== Device Secret Tests ===\n');

// Device secret generation
const deviceSecret = generateDeviceSecret();
assert(deviceSecret.length === 64, 'Device secret is 64 hex chars');
const deviceSecret2 = generateDeviceSecret();
assert(deviceSecret !== deviceSecret2, 'Device secrets are unique');

// Device secret hashing
const hash = hashDeviceSecret(deviceSecret);
assert(hash.length === 64, 'Device hash is 64 hex chars');
assert(hashDeviceSecret(deviceSecret) === hash, 'Same secret produces same hash');
assert(hashDeviceSecret(deviceSecret2) !== hash, 'Different secret produces different hash');

// ── Dual-Key Encryption Tests ────────────────────────────────────────────────

console.log('\n=== Dual-Key Encryption Tests ===\n');

// Encrypt with vault key + device secret
const dualEncrypted = encrypt(plaintext, key, deviceSecret);
assert(dualEncrypted !== plaintext, 'Dual-key encrypted differs from plaintext');

// Decrypt with same vault key + device secret
const dualDecrypted = decrypt(dualEncrypted, key, deviceSecret);
assert(dualDecrypted === plaintext, 'Dual-key decrypt returns original');

// Decrypt with vault key ONLY fails (no device secret)
try {
  decrypt(dualEncrypted, key);
  assert(false, 'Decrypt without device secret should throw');
} catch {
  assert(true, 'Decrypt without device secret throws');
}

// Decrypt with wrong device secret fails
try {
  decrypt(dualEncrypted, key, deviceSecret2);
  assert(false, 'Decrypt with wrong device secret should throw');
} catch {
  assert(true, 'Decrypt with wrong device secret throws');
}

// Decrypt with right device secret but wrong vault key fails
try {
  decrypt(dualEncrypted, wrongKey2, deviceSecret);
  assert(false, 'Decrypt with wrong vault key should throw');
} catch {
  assert(true, 'Decrypt with wrong vault key throws (even with right device secret)');
}

// ── Dual-Key Signing Tests ───────────────────────────────────────────────────

console.log('\n=== Dual-Key Signing Tests ===\n');

// Sign with vault key + device secret
const { signature: dualSig } = sign(key, body, deviceSecret);
assert(dualSig.startsWith('v='), 'Dual-key signature starts with v=');

// Verify with same keys
const { valid: dualValid } = verify(key, body, dualSig, 300_000, deviceSecret);
assert(dualValid === true, 'Dual-key signature verifies');

// Verify without device secret fails
const { valid: noDev } = verify(key, body, dualSig);
assert(noDev === false, 'Dual-key sig fails without device secret');

// Verify with wrong device secret fails
const { valid: wrongDev } = verify(key, body, dualSig, 300_000, deviceSecret2);
assert(wrongDev === false, 'Dual-key sig fails with wrong device secret');

// Single-key sig doesn't verify with device secret added
const { valid: mixedValid } = verify(key, body, signature, 300_000, deviceSecret);
assert(mixedValid === false, 'Single-key sig fails when device secret added to verify');

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
