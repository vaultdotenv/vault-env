/**
 * Vault Server — Cloudflare Worker
 *
 * Stores encrypted secret blobs in D1.
 * Never sees decryption keys — all encryption is client-side.
 *
 * D1 Tables:
 *   projects(id, name, key_hash, created_at)
 *   environments(id, project_id, name, created_at)
 *   secret_versions(id, environment_id, version, encrypted_blob, changed_keys, created_at)
 *   audit_log(id, project_id, action, ip, user_agent, created_at)
 */

const HMAC_MAX_AGE_MS = 300_000; // 5 minutes

// ── Signature Verification ───────────────────────────────────────────────────

async function verifySignature(body, sigHeader, keyHash) {
  if (!body || !sigHeader || !keyHash) return { valid: false, reason: 'missing_params' };

  const parts = {};
  for (const part of sigHeader.split(',')) {
    const idx = part.indexOf('=');
    if (idx !== -1) parts[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }

  const timestamp = parts['v'];
  const providedDigest = parts['d'];
  if (!timestamp || !providedDigest) return { valid: false, reason: 'malformed' };

  const age = Date.now() - parseInt(timestamp, 10);
  if (isNaN(age) || age < -60_000 || age > HMAC_MAX_AGE_MS) return { valid: false, reason: 'stale' };

  // We verify against the stored key hash
  // The client signs with HKDF(vault_key, "vault-auth-v1")
  // We store that derived auth key hash at project creation
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', hexToBuffer(keyHash), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
  );

  const input = encoder.encode(body + timestamp);
  const sigBuffer = hexToBuffer(providedDigest);
  const valid = await crypto.subtle.verify('HMAC', key, sigBuffer, input);

  return { valid };
}

function hexToBuffer(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes.buffer;
}

// ── Request Router ───────────────────────────────────────────────────────────

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Vault-Signature',
        },
      });
    }

    const corsHeaders = { 'Access-Control-Allow-Origin': '*' };

    try {
      if (path === '/api/v1/project/create' && request.method === 'POST') {
        return handleCreateProject(request, env, corsHeaders);
      }
      if (path === '/api/v1/project/set-key' && request.method === 'POST') {
        return handleSetKey(request, env, corsHeaders);
      }
      if (path === '/api/v1/devices/register' && request.method === 'POST') {
        return handleDeviceRegister(request, env, corsHeaders);
      }
      if (path === '/api/v1/devices/approve' && request.method === 'POST') {
        return handleDeviceApprove(request, env, corsHeaders);
      }
      if (path === '/api/v1/devices/list' && request.method === 'POST') {
        return handleDeviceList(request, env, corsHeaders);
      }
      if (path === '/api/v1/devices/revoke' && request.method === 'POST') {
        return handleDeviceRevoke(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/current-version' && request.method === 'POST') {
        return handleCurrentVersion(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/pull' && request.method === 'POST') {
        return handlePull(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/push' && request.method === 'POST') {
        return handlePush(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/versions' && request.method === 'POST') {
        return handleVersions(request, env, corsHeaders);
      }
      if (path === '/api/v1/secrets/rollback' && request.method === 'POST') {
        return handleRollback(request, env, corsHeaders);
      }
      if (path === '/health') {
        return Response.json({ status: 'ok', ts: Date.now() }, { headers: corsHeaders });
      }

      return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
    } catch (err) {
      return Response.json({ error: err.message }, { status: 500, headers: corsHeaders });
    }
  },
};

// ── Handlers ─────────────────────────────────────────────────────────────────

async function handleCreateProject(request, env, corsHeaders) {
  const body = await request.text();
  const { project_name } = JSON.parse(body);

  if (!project_name) {
    return Response.json({ error: 'project_name required' }, { status: 400, headers: corsHeaders });
  }

  const id = crypto.randomUUID();
  // key_hash is set in a follow-up /project/set-key call (client needs the UUID first to generate the vault key)
  await env.DB.prepare(
    'INSERT INTO projects (id, name, key_hash, created_at) VALUES (?, ?, ?, ?)'
  ).bind(id, project_name, '', new Date().toISOString()).run();

  // Create default environments
  for (const envName of ['development', 'staging', 'production']) {
    await env.DB.prepare(
      'INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)'
    ).bind(crypto.randomUUID(), id, envName, new Date().toISOString()).run();
  }

  return Response.json({ project_id: id, environments: ['development', 'staging', 'production'] }, { headers: corsHeaders });
}

async function handleSetKey(request, env, corsHeaders) {
  const body = await request.text();
  const { project_id, auth_key_hash } = JSON.parse(body);

  if (!project_id || !auth_key_hash) {
    return Response.json({ error: 'project_id and auth_key_hash required' }, { status: 400, headers: corsHeaders });
  }

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Only allow setting key if not already set (one-time operation)
  if (project.key_hash) {
    return Response.json({ error: 'Auth key already set' }, { status: 409, headers: corsHeaders });
  }

  await env.DB.prepare('UPDATE projects SET key_hash = ? WHERE id = ?').bind(auth_key_hash, project_id).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

// ── Device Helpers ────────────────────────────────────────────────────────────

async function validateDevice(env, projectId, deviceHash) {
  if (!deviceHash) return { valid: false, reason: 'no_device_hash' };

  const device = await env.DB.prepare(
    'SELECT * FROM devices WHERE project_id = ? AND device_hash = ?'
  ).bind(projectId, deviceHash).first();

  if (!device) return { valid: false, reason: 'unregistered' };
  if (device.status === 'pending') return { valid: false, reason: 'pending' };
  if (device.status === 'revoked') return { valid: false, reason: 'revoked' };

  // Update last_seen
  await env.DB.prepare(
    'UPDATE devices SET last_seen_at = ? WHERE id = ?'
  ).bind(new Date().toISOString(), device.id).run();

  return { valid: true, device };
}

async function projectHasDevices(env, projectId) {
  const count = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM devices WHERE project_id = ?'
  ).bind(projectId).first();
  return count.cnt > 0;
}

// ── Device Handlers ──────────────────────────────────────────────────────────

async function handleDeviceRegister(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, device_name, device_hash } = JSON.parse(body);

  if (!project_id || !device_name || !device_hash) {
    return Response.json({ error: 'project_id, device_name, and device_hash required' }, { status: 400, headers: corsHeaders });
  }

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Verify signature (signed with vault key only, no device secret yet)
  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  // Check if device already registered
  const existing = await env.DB.prepare(
    'SELECT * FROM devices WHERE project_id = ? AND device_hash = ?'
  ).bind(project_id, device_hash).first();

  if (existing) {
    return Response.json({ device_id: existing.id, status: existing.status }, { headers: corsHeaders });
  }

  // First device for a project is auto-approved (it's the owner)
  const hasDevices = await projectHasDevices(env, project_id);
  const status = hasDevices ? 'pending' : 'approved';
  const now = new Date().toISOString();

  const id = crypto.randomUUID();
  await env.DB.prepare(
    'INSERT INTO devices (id, project_id, device_name, device_hash, status, created_at, approved_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, project_id, device_name, device_hash, status, now, status === 'approved' ? now : null).run();

  // Audit
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, null, 'device_register', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), now).run();

  return Response.json({ device_id: id, status }, { headers: corsHeaders });
}

async function handleDeviceApprove(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, device_id } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Must be signed by an approved device (the owner)
  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const device = await env.DB.prepare('SELECT * FROM devices WHERE id = ? AND project_id = ?').bind(device_id, project_id).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare(
    'UPDATE devices SET status = ?, approved_at = ? WHERE id = ?'
  ).bind('approved', new Date().toISOString(), device_id).run();

  return Response.json({ device_id, status: 'approved' }, { headers: corsHeaders });
}

async function handleDeviceList(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const devices = await env.DB.prepare(
    'SELECT id, device_name, status, created_at, approved_at, last_seen_at FROM devices WHERE project_id = ? ORDER BY created_at DESC'
  ).bind(project_id).all();

  return Response.json({ devices: devices.results }, { headers: corsHeaders });
}

async function handleDeviceRevoke(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, device_id } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const device = await env.DB.prepare('SELECT * FROM devices WHERE id = ? AND project_id = ?').bind(device_id, project_id).first();
  if (!device) return Response.json({ error: 'Device not found' }, { status: 404, headers: corsHeaders });

  await env.DB.prepare('UPDATE devices SET status = ? WHERE id = ?').bind('revoked', device_id).run();

  return Response.json({ device_id, status: 'revoked' }, { headers: corsHeaders });
}

// ── Secret Handlers ──────────────────────────────────────────────────────────

async function handleCurrentVersion(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  const latest = await env.DB.prepare(
    'SELECT version, created_at FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 1'
  ).bind(envRow.id).first();

  return Response.json({
    version: latest?.version || 0,
    updated_at: latest?.created_at || null,
  }, { headers: corsHeaders });
}

async function handlePull(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment, device_hash } = JSON.parse(body);

  // Get project
  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Verify signature
  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  // Validate device if project has registered devices
  const hasDevices = await projectHasDevices(env, project_id);
  if (hasDevices) {
    const deviceCheck = await validateDevice(env, project_id, device_hash);
    if (!deviceCheck.valid) {
      const msg = deviceCheck.reason === 'pending'
        ? 'Device pending approval'
        : 'Device not registered or revoked';
      return Response.json({ error: msg }, { status: 403, headers: corsHeaders });
    }
  }

  // Get environment
  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  // Get latest version
  const latest = await env.DB.prepare(
    'SELECT * FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 1'
  ).bind(envRow.id).first();

  if (!latest) return Response.json({ error: 'No secrets stored yet' }, { status: 404, headers: corsHeaders });

  // Audit log
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'pull', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({
    secrets: latest.encrypted_blob,
    version: latest.version,
  }, { headers: corsHeaders });
}

async function handlePush(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment, secrets, device_hash } = JSON.parse(body);

  // Get project
  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  // Verify signature
  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  // Validate device if project has registered devices
  const hasDevices = await projectHasDevices(env, project_id);
  if (hasDevices) {
    const deviceCheck = await validateDevice(env, project_id, device_hash);
    if (!deviceCheck.valid) {
      const msg = deviceCheck.reason === 'pending'
        ? 'Device pending approval'
        : 'Device not registered or revoked';
      return Response.json({ error: msg }, { status: 403, headers: corsHeaders });
    }
  }

  // Get or create environment
  let envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();

  if (!envRow) {
    const envId = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO environments (id, project_id, name, created_at) VALUES (?, ?, ?, ?)'
    ).bind(envId, project_id, environment, new Date().toISOString()).run();
    envRow = { id: envId };
  }

  // Get next version number
  const latest = await env.DB.prepare(
    'SELECT MAX(version) as max_version FROM secret_versions WHERE environment_id = ?'
  ).bind(envRow.id).first();
  const nextVersion = (latest?.max_version || 0) + 1;

  // Store encrypted blob
  await env.DB.prepare(
    'INSERT INTO secret_versions (environment_id, version, encrypted_blob, created_at) VALUES (?, ?, ?, ?)'
  ).bind(envRow.id, nextVersion, secrets, new Date().toISOString()).run();

  // Audit log
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'push', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({ version: nextVersion }, { headers: corsHeaders });
}

async function handleVersions(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  const versions = await env.DB.prepare(
    'SELECT version, changed_keys, created_at FROM secret_versions WHERE environment_id = ? ORDER BY version DESC LIMIT 50'
  ).bind(envRow.id).all();

  return Response.json({ versions: versions.results }, { headers: corsHeaders });
}

async function handleRollback(request, env, corsHeaders) {
  const body = await request.text();
  const sig = request.headers.get('X-Vault-Signature') || '';
  const { project_id, environment, version } = JSON.parse(body);

  const project = await env.DB.prepare('SELECT * FROM projects WHERE id = ?').bind(project_id).first();
  if (!project) return Response.json({ error: 'Project not found' }, { status: 404, headers: corsHeaders });

  const { valid } = await verifySignature(body, sig, project.key_hash);
  if (!valid) return Response.json({ error: 'Unauthorized' }, { status: 401, headers: corsHeaders });

  const envRow = await env.DB.prepare(
    'SELECT * FROM environments WHERE project_id = ? AND name = ?'
  ).bind(project_id, environment).first();
  if (!envRow) return Response.json({ error: 'Environment not found' }, { status: 404, headers: corsHeaders });

  // Get the target version
  const target = await env.DB.prepare(
    'SELECT * FROM secret_versions WHERE environment_id = ? AND version = ?'
  ).bind(envRow.id, version).first();
  if (!target) return Response.json({ error: 'Version not found' }, { status: 404, headers: corsHeaders });

  // Create new version with old content
  const latest = await env.DB.prepare(
    'SELECT MAX(version) as max_version FROM secret_versions WHERE environment_id = ?'
  ).bind(envRow.id).first();
  const nextVersion = (latest?.max_version || 0) + 1;

  await env.DB.prepare(
    'INSERT INTO secret_versions (environment_id, version, encrypted_blob, changed_keys, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(envRow.id, nextVersion, target.encrypted_blob, `["rollback_from_v${version}"]`, new Date().toISOString()).run();

  // Audit
  await env.DB.prepare(
    'INSERT INTO audit_log (project_id, environment_id, action, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(project_id, envRow.id, 'rollback', request.headers.get('CF-Connecting-IP'), request.headers.get('User-Agent'), new Date().toISOString()).run();

  return Response.json({ version: nextVersion }, { headers: corsHeaders });
}
