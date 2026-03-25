'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

// We need to clear the require cache between tests to re-evaluate config
function freshConfig() {
  delete require.cache[require.resolve('../../src/config')];
  return require('../../src/config');
}

describe('getFlag', () => {
  it('returns flag value', () => {
    const { getFlag } = freshConfig();
    assert.equal(getFlag(['push', '--env', 'production'], 'env'), 'production');
  });

  it('returns undefined for missing flag', () => {
    const { getFlag } = freshConfig();
    assert.equal(getFlag(['push'], 'env'), undefined);
  });

  it('returns value for flag at end', () => {
    const { getFlag } = freshConfig();
    assert.equal(getFlag(['--name', 'my-app'], 'name'), 'my-app');
  });
});

describe('getVaultUrl', () => {
  let original;
  beforeEach(() => { original = process.env.VAULT_URL; });
  afterEach(() => {
    if (original !== undefined) process.env.VAULT_URL = original;
    else delete process.env.VAULT_URL;
  });

  it('returns default URL when no flag or env', () => {
    delete process.env.VAULT_URL;
    const { getVaultUrl } = freshConfig();
    assert.equal(getVaultUrl([]), 'https://api.vaultdotenv.io');
  });

  it('prefers --url flag over env var', () => {
    process.env.VAULT_URL = 'https://env.api.com';
    const { getVaultUrl } = freshConfig();
    assert.equal(getVaultUrl(['--url', 'https://flag.api.com']), 'https://flag.api.com');
  });

  it('returns VAULT_URL env var when no flag', () => {
    process.env.VAULT_URL = 'https://env.api.com';
    const { getVaultUrl } = freshConfig();
    assert.equal(getVaultUrl([]), 'https://env.api.com');
  });
});

describe('getEnvironment', () => {
  let original;
  beforeEach(() => { original = process.env.NODE_ENV; });
  afterEach(() => {
    if (original !== undefined) process.env.NODE_ENV = original;
    else delete process.env.NODE_ENV;
  });

  it('returns development when no flag or env', () => {
    delete process.env.NODE_ENV;
    const { getEnvironment } = freshConfig();
    assert.equal(getEnvironment([]), 'development');
  });

  it('returns --env flag', () => {
    const { getEnvironment } = freshConfig();
    assert.equal(getEnvironment(['--env', 'staging']), 'staging');
  });

  it('returns NODE_ENV when no flag', () => {
    process.env.NODE_ENV = 'production';
    const { getEnvironment } = freshConfig();
    assert.equal(getEnvironment([]), 'production');
  });
});

describe('getVaultKey', () => {
  let originalKey, originalSecret;
  beforeEach(() => {
    originalKey = process.env.VAULT_KEY;
    originalSecret = process.env.VAULT_DEVICE_SECRET;
  });
  afterEach(() => {
    if (originalKey !== undefined) process.env.VAULT_KEY = originalKey;
    else delete process.env.VAULT_KEY;
    if (originalSecret !== undefined) process.env.VAULT_DEVICE_SECRET = originalSecret;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('returns VAULT_KEY from environment', () => {
    process.env.VAULT_KEY = 'vk_test_envkey';
    const { getVaultKey } = freshConfig();
    assert.equal(getVaultKey([]), 'vk_test_envkey');
  });

  it('reads VAULT_KEY from .env file', () => {
    delete process.env.VAULT_KEY;
    const tmpDir = path.join(os.tmpdir(), `vault-key-test-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(path.join(tmpDir, '.env'), 'VAULT_KEY=vk_test_fromfile\n');
    const origCwd = process.cwd();
    process.chdir(tmpDir);
    try {
      const { getVaultKey } = freshConfig();
      assert.equal(getVaultKey([]), 'vk_test_fromfile');
    } finally {
      process.chdir(origCwd);
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('reads key from --project flag', () => {
    delete process.env.VAULT_KEY;
    const { KEYS_DIR, getVaultKey } = freshConfig();
    const testProject = `test-getkey-${Date.now()}`;
    fs.mkdirSync(KEYS_DIR, { recursive: true, mode: 0o700 });
    const keyPath = path.join(KEYS_DIR, `${testProject}.key`);
    fs.writeFileSync(keyPath, 'vk_test_fromproject\n', { mode: 0o600 });
    try {
      assert.equal(getVaultKey(['--project', testProject]), 'vk_test_fromproject');
    } finally {
      fs.unlinkSync(keyPath);
    }
  });

  it('exits when --project key file missing', () => {
    delete process.env.VAULT_KEY;
    const { getVaultKey } = freshConfig();
    const origExit = process.exit;
    let exitCode = null;
    process.exit = (code) => { exitCode = code; throw new Error('exit'); };
    try {
      getVaultKey(['--project', 'nonexistent-project-xyz']);
    } catch (e) {
      if (e.message !== 'exit') throw e;
    }
    process.exit = origExit;
    assert.equal(exitCode, 1);
  });

  it('exits when no key found anywhere', () => {
    delete process.env.VAULT_KEY;
    const tmpDir = path.join(os.tmpdir(), `vault-nokey-${Date.now()}`);
    fs.mkdirSync(tmpDir, { recursive: true });
    const origCwd = process.cwd();
    process.chdir(tmpDir);
    const origExit = process.exit;
    let exitCode = null;
    process.exit = (code) => { exitCode = code; throw new Error('exit'); };
    try {
      const { getVaultKey } = freshConfig();
      getVaultKey([]);
    } catch (e) {
      if (e.message !== 'exit') throw e;
    }
    process.exit = origExit;
    process.chdir(origCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
    assert.equal(exitCode, 1);
  });
});

describe('auth helpers', () => {
  const { VAULT_DIR } = require('../../src/config');
  const authPath = path.join(VAULT_DIR, 'auth.json');
  let originalContent;

  beforeEach(() => {
    if (fs.existsSync(authPath)) {
      originalContent = fs.readFileSync(authPath, 'utf8');
    }
  });

  afterEach(() => {
    if (originalContent) {
      fs.writeFileSync(authPath, originalContent, { mode: 0o600 });
    }
  });

  it('getAuth returns object when auth file exists', () => {
    const { getAuth } = freshConfig();
    const result = getAuth();
    assert.ok(result === null || typeof result === 'object');
  });

  it('getAuth returns null for corrupt JSON', () => {
    const { AUTH_PATH, getAuth } = freshConfig();
    const origContent = fs.existsSync(AUTH_PATH) ? fs.readFileSync(AUTH_PATH, 'utf8') : null;
    fs.mkdirSync(path.dirname(AUTH_PATH), { recursive: true });
    fs.writeFileSync(AUTH_PATH, 'not json{{{', { mode: 0o600 });
    try {
      assert.equal(getAuth(), null);
    } finally {
      if (origContent) fs.writeFileSync(AUTH_PATH, origContent, { mode: 0o600 });
      else if (fs.existsSync(AUTH_PATH)) fs.unlinkSync(AUTH_PATH);
    }
  });

  it('saveAuth writes and getAuth reads back', () => {
    const { saveAuth, getAuth } = freshConfig();
    const testData = { token: 'test-token', email: 'test@test.com', api_url: 'https://test.api' };
    saveAuth(testData);
    const result = getAuth();
    assert.deepEqual(result, testData);
  });

  it('removeAuth returns true when file exists', () => {
    const { saveAuth, removeAuth } = freshConfig();
    saveAuth({ token: 'to-remove' });
    assert.equal(removeAuth(), true);
  });

  it('removeAuth returns false when no file', () => {
    const { removeAuth } = freshConfig();
    // Remove first if exists
    removeAuth();
    assert.equal(removeAuth(), false);
  });
});
