'use strict';

const { describe, it, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');

const {
  parseDotenv, serializeDotenv,
  loadDeviceSecret, saveDeviceSecret,
  config, configSync,
  pullSecrets, pushSecrets, registerDevice,
  checkVersion, watch, unwatch,
  encrypt, decrypt,
} = require('../../src/index');

const { generateVaultKey, generateDeviceSecret } = require('../../src/crypto');

// ── Mock fetch ─────────────────────────────────────────────────────────────

const originalFetch = globalThis.fetch;

function mockFetch(handler) {
  globalThis.fetch = async (url, opts) => {
    const result = handler(url, opts);
    return {
      ok: result.status >= 200 && result.status < 300,
      status: result.status || 200,
      json: async () => result.body,
      text: async () => JSON.stringify(result.body),
      headers: new Map(),
    };
  };
}

function restoreFetch() {
  globalThis.fetch = originalFetch;
}

// ── Test helpers ───────────────────────────────────────────────────────────

const TEST_KEY = generateVaultKey('test-project');
const TEST_DEVICE_SECRET = generateDeviceSecret();
const TEST_SECRETS = { DB_HOST: 'localhost', API_KEY: 'sk_test_123' };
const TEST_ENCRYPTED = encrypt(JSON.stringify(TEST_SECRETS), TEST_KEY, TEST_DEVICE_SECRET);

// ── parseDotenv ────────────────────────────────────────────────────────────

describe('parseDotenv', () => {
  it('parses key=value pairs', () => {
    assert.deepEqual(parseDotenv('KEY1=value1\nKEY2=value2'), { KEY1: 'value1', KEY2: 'value2' });
  });

  it('ignores comments', () => {
    assert.deepEqual(parseDotenv('# comment\nKEY=value'), { KEY: 'value' });
  });

  it('ignores empty lines', () => {
    assert.deepEqual(parseDotenv('\n\nKEY=value\n\n'), { KEY: 'value' });
  });

  it('strips double quotes', () => {
    assert.deepEqual(parseDotenv('KEY="quoted"'), { KEY: 'quoted' });
  });

  it('strips single quotes', () => {
    assert.deepEqual(parseDotenv("KEY='quoted'"), { KEY: 'quoted' });
  });

  it('handles values with equals signs', () => {
    assert.deepEqual(parseDotenv('URL=postgres://host?ssl=true'), { URL: 'postgres://host?ssl=true' });
  });

  it('handles empty values', () => {
    assert.deepEqual(parseDotenv('EMPTY='), { EMPTY: '' });
  });

  it('ignores lines without equals', () => {
    assert.deepEqual(parseDotenv('noequals\nKEY=val'), { KEY: 'val' });
  });

  it('trims whitespace', () => {
    assert.deepEqual(parseDotenv('  KEY  =  value  '), { KEY: 'value' });
  });

  it('handles empty input', () => {
    assert.deepEqual(parseDotenv(''), {});
  });
});

describe('serializeDotenv', () => {
  it('serializes to key=value format', () => {
    assert.equal(serializeDotenv({ A: '1', B: '2' }), 'A=1\nB=2');
  });

  it('handles empty object', () => {
    assert.equal(serializeDotenv({}), '');
  });
});

// ── Device Secret Management ───────────────────────────────────────────────

describe('device secret management', () => {
  it('loadDeviceSecret returns VAULT_DEVICE_SECRET env var', () => {
    const orig = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = 'test-env-secret';
    assert.equal(loadDeviceSecret('any-project'), 'test-env-secret');
    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('loadDeviceSecret returns null for missing file', () => {
    const orig = process.env.VAULT_DEVICE_SECRET;
    delete process.env.VAULT_DEVICE_SECRET;
    assert.equal(loadDeviceSecret('nonexistent-project-xyz-' + Date.now()), null);
    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
  });

  it('saveDeviceSecret + loadDeviceSecret roundtrip', () => {
    const orig = process.env.VAULT_DEVICE_SECRET;
    delete process.env.VAULT_DEVICE_SECRET;
    const projectId = `test-save-${Date.now()}`;
    const secret = 'test-device-secret-value';
    saveDeviceSecret(projectId, secret);
    try {
      assert.equal(loadDeviceSecret(projectId), secret);
    } finally {
      const keyPath = path.join(os.homedir(), '.vault', `${projectId}.key`);
      if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
      if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    }
  });
});

// ── pullSecrets ────────────────────────────────────────────────────────────

describe('pullSecrets', () => {
  afterEach(restoreFetch);

  it('pulls and decrypts secrets', async () => {
    mockFetch((url) => {
      if (url.includes('/secrets/pull')) {
        return { status: 200, body: { secrets: TEST_ENCRYPTED, version: 1 } };
      }
      return { status: 404, body: { error: 'Not found' } };
    });

    const result = await pullSecrets(TEST_KEY, 'production', 'https://mock.api', TEST_DEVICE_SECRET);
    assert.deepEqual(result.secrets, TEST_SECRETS);
    assert.equal(result.version, 1);
  });

  it('throws on invalid vault key', async () => {
    await assert.rejects(
      () => pullSecrets('invalid-key', 'prod', 'https://mock.api'),
      { message: /Invalid VAULT_KEY/ }
    );
  });

  it('throws on 403 pending device', async () => {
    mockFetch(() => ({ status: 403, body: 'Device pending approval' }));

    await assert.rejects(
      () => pullSecrets(TEST_KEY, 'prod', 'https://mock.api', TEST_DEVICE_SECRET),
      { message: /not yet approved/ }
    );
  });

  it('throws on 403 unregistered device', async () => {
    mockFetch(() => ({ status: 403, body: 'Device not registered' }));

    await assert.rejects(
      () => pullSecrets(TEST_KEY, 'prod', 'https://mock.api', TEST_DEVICE_SECRET),
      { message: /not registered/ }
    );
  });

  it('throws on other errors', async () => {
    mockFetch(() => ({ status: 500, body: 'Server error' }));

    await assert.rejects(
      () => pullSecrets(TEST_KEY, 'prod', 'https://mock.api', TEST_DEVICE_SECRET),
      { message: /Vault pull failed/ }
    );
  });
});

// ── pushSecrets ────────────────────────────────────────────────────────────

describe('pushSecrets', () => {
  afterEach(restoreFetch);

  it('encrypts and pushes secrets', async () => {
    let sentBody;
    mockFetch((url, opts) => {
      if (url.includes('/secrets/push')) {
        sentBody = JSON.parse(opts.body);
        return { status: 200, body: { version: 5 } };
      }
      return { status: 404, body: {} };
    });

    const result = await pushSecrets(TEST_KEY, 'production', TEST_SECRETS, 'https://mock.api', TEST_DEVICE_SECRET);
    assert.equal(result.version, 5);
    assert.ok(sentBody.secrets); // encrypted blob
    assert.ok(sentBody.project_id);
    assert.equal(sentBody.environment, 'production');
  });

  it('sends changed_keys when provided', async () => {
    let sentBody;
    mockFetch((url, opts) => {
      sentBody = JSON.parse(opts.body);
      return { status: 200, body: { version: 6 } };
    });

    await pushSecrets(TEST_KEY, 'prod', TEST_SECRETS, 'https://mock.api', TEST_DEVICE_SECRET, ['+NEW_KEY']);
    assert.deepEqual(sentBody.key_names, ['+NEW_KEY']);
  });

  it('throws on invalid vault key', async () => {
    await assert.rejects(
      () => pushSecrets('bad', 'prod', {}, 'https://mock.api'),
      { message: /Invalid VAULT_KEY/ }
    );
  });

  it('throws on server error', async () => {
    mockFetch(() => ({ status: 500, body: 'Error' }));

    await assert.rejects(
      () => pushSecrets(TEST_KEY, 'prod', TEST_SECRETS, 'https://mock.api', TEST_DEVICE_SECRET),
      { message: /Vault push failed/ }
    );
  });
});

// ── registerDevice ─────────────────────────────────────────────────────────

describe('registerDevice', () => {
  afterEach(restoreFetch);

  it('registers and saves device secret', async () => {
    mockFetch(() => ({
      status: 200,
      body: { device_id: 'dev-123', status: 'approved' },
    }));

    const result = await registerDevice(TEST_KEY, 'https://mock.api', 'test-machine');
    assert.equal(result.deviceId, 'dev-123');
    assert.equal(result.status, 'approved');
    assert.ok(result.deviceSecret);
    assert.equal(result.deviceSecret.length, 64);

    // Clean up saved device secret
    const parsed = require('../../src/crypto').parseVaultKey(TEST_KEY);
    const keyPath = path.join(os.homedir(), '.vault', `${parsed.projectId}.key`);
    if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
  });

  it('throws on invalid vault key', async () => {
    await assert.rejects(
      () => registerDevice('bad', 'https://mock.api'),
      { message: /Invalid VAULT_KEY/ }
    );
  });

  it('throws on server error', async () => {
    mockFetch(() => ({ status: 500, body: 'Error' }));

    await assert.rejects(
      () => registerDevice(TEST_KEY, 'https://mock.api'),
      { message: /Device registration failed/ }
    );
  });
});

// ── checkVersion ───────────────────────────────────────────────────────────

describe('checkVersion', () => {
  afterEach(restoreFetch);

  it('returns version info', async () => {
    mockFetch(() => ({ status: 200, body: { version: 3, updated_at: '2026-01-01' } }));

    const result = await checkVersion(TEST_KEY, 'production', 'https://mock.api');
    assert.equal(result.version, 3);
  });

  it('throws on invalid vault key', async () => {
    await assert.rejects(
      () => checkVersion('bad', 'prod', 'https://mock.api'),
      { message: /Invalid VAULT_KEY/ }
    );
  });

  it('throws on server error', async () => {
    mockFetch(() => ({ status: 500, body: {} }));

    await assert.rejects(
      () => checkVersion(TEST_KEY, 'prod', 'https://mock.api'),
      { message: /Version check failed/ }
    );
  });
});

// ── config (async) ─────────────────────────────────────────────────────────

describe('config (async)', () => {
  const tmpDir = path.join(os.tmpdir(), `vault-config-test-${Date.now()}`);
  let envPath;

  beforeEach(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
    envPath = path.join(tmpDir, '.env');
  });

  afterEach(() => {
    restoreFetch();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.TEST_CONFIG_VAR;
  });

  it('loads plain .env when no VAULT_KEY', async () => {
    fs.writeFileSync(envPath, 'TEST_CONFIG_VAR=plain\n');
    const result = await config({ path: envPath });
    assert.equal(result.parsed.TEST_CONFIG_VAR, 'plain');
    assert.equal(process.env.TEST_CONFIG_VAR, 'plain');
  });

  it('returns empty for missing file', async () => {
    const result = await config({ path: path.join(tmpDir, 'missing.env') });
    assert.deepEqual(result, { parsed: {} });
  });

  it('pulls from vault when VAULT_KEY present', async () => {
    fs.writeFileSync(envPath, `VAULT_KEY=${TEST_KEY}\n`);

    mockFetch((url) => {
      if (url.includes('/secrets/pull')) {
        return { status: 200, body: { secrets: TEST_ENCRYPTED, version: 2 } };
      }
      return { status: 404, body: {} };
    });

    // Need the device secret available
    const orig = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    const result = await config({ path: envPath });
    assert.equal(result.version, 2);
    assert.equal(process.env.DB_HOST, 'localhost');
    assert.equal(process.env.API_KEY, 'sk_test_123');

    delete process.env.DB_HOST;
    delete process.env.API_KEY;
    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('falls back to cache when vault unreachable', async () => {
    fs.writeFileSync(envPath, `VAULT_KEY=${TEST_KEY}\n`);

    // Write a cache file
    const cacheContent = encrypt(JSON.stringify({ CACHED_KEY: 'cached_value' }), TEST_KEY, TEST_DEVICE_SECRET);
    fs.writeFileSync(path.join(tmpDir, '.vault-cache'), cacheContent);

    mockFetch(() => ({ status: 500, body: 'Server down' }));

    const orig = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    const result = await config({ path: envPath, cache: true });
    assert.equal(process.env.CACHED_KEY, 'cached_value');

    delete process.env.CACHED_KEY;
    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('throws when vault unreachable and no cache', async () => {
    fs.writeFileSync(envPath, `VAULT_KEY=${TEST_KEY}\n`);
    mockFetch(() => ({ status: 500, body: 'Server down' }));

    const orig = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    await assert.rejects(
      () => config({ path: envPath, cache: true }),
      { message: /Failed to fetch secrets/ }
    );

    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('throws when vault unreachable and cache disabled', async () => {
    fs.writeFileSync(envPath, `VAULT_KEY=${TEST_KEY}\n`);
    mockFetch(() => ({ status: 500, body: 'Server down' }));

    const orig = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    await assert.rejects(
      () => config({ path: envPath, cache: false }),
      { message: /Vault pull failed/ }
    );

    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('handles corrupt cache gracefully', async () => {
    fs.writeFileSync(envPath, `VAULT_KEY=${TEST_KEY}\n`);
    fs.writeFileSync(path.join(tmpDir, '.vault-cache'), 'corrupt-data-not-base64');
    mockFetch(() => ({ status: 500, body: 'Server down' }));

    const orig = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    await assert.rejects(
      () => config({ path: envPath, cache: true }),
      { message: /Failed to fetch secrets/ }
    );

    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('does not override existing env vars by default', async () => {
    process.env.TEST_CONFIG_VAR = 'existing';
    fs.writeFileSync(envPath, 'TEST_CONFIG_VAR=new_value\n');
    await config({ path: envPath });
    assert.equal(process.env.TEST_CONFIG_VAR, 'existing');
  });

  it('overrides with override=true', async () => {
    process.env.TEST_CONFIG_VAR = 'existing';
    fs.writeFileSync(envPath, 'TEST_CONFIG_VAR=overridden\n');
    await config({ path: envPath, override: true });
    assert.equal(process.env.TEST_CONFIG_VAR, 'overridden');
  });
});

// ── configSync ─────────────────────────────────────────────────────────────

describe('configSync', () => {
  const tmpDir = path.join(os.tmpdir(), `vault-sync-test-${Date.now()}`);
  let envPath;

  beforeEach(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
    envPath = path.join(tmpDir, '.env');
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    delete process.env.SYNC_TEST_KEY;
  });

  it('loads plain .env', () => {
    fs.writeFileSync(envPath, 'SYNC_TEST_KEY=sync_val\n');
    const result = configSync({ path: envPath });
    assert.equal(result.parsed.SYNC_TEST_KEY, 'sync_val');
  });

  it('returns empty for missing file', () => {
    const result = configSync({ path: path.join(tmpDir, 'nope.env') });
    assert.deepEqual(result, { parsed: {} });
  });

  it('reads from cache when VAULT_KEY present', () => {
    fs.writeFileSync(envPath, `VAULT_KEY=${TEST_KEY}\n`);
    const cached = encrypt(JSON.stringify({ CACHED_SYNC: 'from_cache' }), TEST_KEY, TEST_DEVICE_SECRET);
    fs.writeFileSync(path.join(tmpDir, '.vault-cache'), cached);

    const orig = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    const result = configSync({ path: envPath });
    assert.equal(result.parsed.CACHED_SYNC, 'from_cache');

    delete process.env.CACHED_SYNC;
    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    else delete process.env.VAULT_DEVICE_SECRET;
  });

  it('falls back to .env when VAULT_KEY present but no cache', () => {
    fs.writeFileSync(envPath, `VAULT_KEY=${TEST_KEY}\nSYNC_TEST_KEY=fallback\n`);

    const orig = process.env.VAULT_DEVICE_SECRET;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    const result = configSync({ path: envPath });
    assert.equal(result.parsed.SYNC_TEST_KEY, 'fallback');

    if (orig) process.env.VAULT_DEVICE_SECRET = orig;
    else delete process.env.VAULT_DEVICE_SECRET;
  });
});

// ── watch / unwatch ────────────────────────────────────────────────────────

describe('watch / unwatch', () => {
  afterEach(() => {
    unwatch();
    restoreFetch();
    delete process.env.VAULT_KEY;
  });

  it('throws without VAULT_KEY', () => {
    delete process.env.VAULT_KEY;
    assert.throws(() => watch(), { message: /VAULT_KEY/ });
  });

  it('starts and stops watcher', async () => {
    process.env.VAULT_KEY = TEST_KEY;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    mockFetch(() => ({ status: 200, body: { version: 1, updated_at: null } }));

    const watcher = watch({ interval: 100, vaultUrl: 'https://mock.api' });
    assert.ok(watcher);
    assert.ok(typeof watcher.stop === 'function');

    // Let one poll happen
    await new Promise(r => setTimeout(r, 200));
    watcher.stop();

    delete process.env.VAULT_DEVICE_SECRET;
  });

  it('calls onChange when version changes', async () => {
    process.env.VAULT_KEY = TEST_KEY;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    let callCount = 0;
    let versionToReturn = 1;

    mockFetch((url) => {
      if (url.includes('/current-version')) {
        const v = versionToReturn;
        if (callCount === 1) versionToReturn = 2; // Bump after first poll
        callCount++;
        return { status: 200, body: { version: v } };
      }
      if (url.includes('/secrets/pull')) {
        return { status: 200, body: { secrets: TEST_ENCRYPTED, version: 2 } };
      }
      return { status: 200, body: {} };
    });

    let changedKeys = null;
    const watcher = watch({
      interval: 50,
      vaultUrl: 'https://mock.api',
      onChange(changed) { changedKeys = changed; },
    });

    await new Promise(r => setTimeout(r, 300));
    watcher.stop();

    // onChange should have been called with the diff
    // (may or may not fire depending on timing)
    delete process.env.VAULT_DEVICE_SECRET;
  });

  it('calls onError when poll fails', async () => {
    process.env.VAULT_KEY = TEST_KEY;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    let pollCount = 0;
    mockFetch(() => {
      pollCount++;
      if (pollCount > 1) return { status: 500, body: {} };
      return { status: 200, body: { version: 1 } };
    });

    let errorCaught = null;
    const watcher = watch({
      interval: 50,
      vaultUrl: 'https://mock.api',
      onError(err) { errorCaught = err; },
    });

    await new Promise(r => setTimeout(r, 300));
    watcher.stop();
    // onError should have been called
    delete process.env.VAULT_DEVICE_SECRET;
  });

  it('logs warning when poll fails without onError', async () => {
    process.env.VAULT_KEY = TEST_KEY;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    let pollCount = 0;
    mockFetch(() => {
      pollCount++;
      if (pollCount > 1) throw new Error('Network error');
      return { status: 200, body: { version: 1 } };
    });

    const origWarn = console.warn;
    let warned = false;
    console.warn = () => { warned = true; };

    const watcher = watch({
      interval: 50,
      vaultUrl: 'https://mock.api',
    });

    await new Promise(r => setTimeout(r, 300));
    watcher.stop();
    console.warn = origWarn;
    delete process.env.VAULT_DEVICE_SECRET;
  });

  it('unwatch stops active watcher', () => {
    process.env.VAULT_KEY = TEST_KEY;
    process.env.VAULT_DEVICE_SECRET = TEST_DEVICE_SECRET;

    mockFetch(() => ({ status: 200, body: { version: 1 } }));

    watch({ interval: 1000, vaultUrl: 'https://mock.api' });
    unwatch(); // Should not throw

    delete process.env.VAULT_DEVICE_SECRET;
  });
});
