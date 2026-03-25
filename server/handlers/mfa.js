/**
 * MFA endpoints: setup, enable, verify, challenge, disable.
 *
 * Setup flow (3-step, same as tradecommand):
 *   1. POST /2fa/setup   → generates secret + URI, stores pending secret in session
 *   2. POST /2fa/enable  → verifies first code (does NOT commit)
 *   3. POST /2fa/verify  → verifies second code, commits to DB
 *
 * Login challenge:
 *   POST /2fa/challenge → verifies code, promotes partial session to full
 *
 * Disable:
 *   POST /2fa/disable → requires password, clears TOTP from user
 */

import { generateSecret, generateTotpUri, verifyTotp } from '../lib/totp.js';
import { verifyPassword } from '../lib/crypto.js';

export async function handleMfa(request, env, user, corsHeaders, path, method) {
  if (path === '/api/v1/dashboard/2fa/setup' && method === 'POST') {
    return mfaSetup(request, env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/2fa/enable' && method === 'POST') {
    return mfaEnable(request, env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/2fa/verify' && method === 'POST') {
    return mfaVerify(request, env, user, corsHeaders);
  }
  if (path === '/api/v1/dashboard/2fa/disable' && method === 'POST') {
    return mfaDisable(request, env, user, corsHeaders);
  }
  return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
}

// Called from login flow — no session auth, uses partial token
export async function mfaChallenge(request, env, corsHeaders) {
  const { code, token } = await request.json();

  if (!code || code.length !== 6 || !token) {
    return Response.json({ error: 'Code and token required' }, { status: 400, headers: corsHeaders });
  }

  const session = await env.DB.prepare(
    'SELECT s.*, u.id as uid, u.email, u.plan, u.is_superadmin, u.totp_secret, u.totp_enabled FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.id = ?'
  ).bind(token).first();

  if (!session) {
    return Response.json({ error: 'Invalid session' }, { status: 401, headers: corsHeaders });
  }

  const data = session.data ? JSON.parse(session.data) : {};
  if (!data.awaiting_2fa) {
    return Response.json({ error: 'No pending 2FA challenge' }, { status: 400, headers: corsHeaders });
  }

  if (!session.totp_enabled || !session.totp_secret) {
    return Response.json({ error: 'Account not configured for 2FA' }, { status: 400, headers: corsHeaders });
  }

  const valid = await verifyTotp(session.totp_secret, code);
  if (!valid) {
    return Response.json({ error: 'Invalid code. Please try again.' }, { status: 401, headers: corsHeaders });
  }

  // Promote to full session — clear awaiting_2fa
  await env.DB.prepare('UPDATE sessions SET data = ? WHERE id = ?').bind('{}', token).run();

  return Response.json({
    token,
    user: {
      id: session.uid,
      email: session.email,
      plan: session.plan || 'free',
      is_superadmin: !!session.is_superadmin,
      totp_enabled: true,
    },
  }, { headers: corsHeaders });
}

// ── Setup: generate secret + URI ────────────────────────────────────────────

async function mfaSetup(request, env, user, corsHeaders) {
  // Check if already enabled
  const dbUser = await env.DB.prepare('SELECT totp_enabled FROM users WHERE id = ?').bind(user.id).first();
  if (dbUser?.totp_enabled) {
    return Response.json({ error: '2FA is already enabled. Disable it first to reconfigure.' }, { status: 400, headers: corsHeaders });
  }

  const secret = generateSecret();
  const uri = generateTotpUri(secret, user.email);

  // Store pending secret in session
  const token = request.headers.get('Authorization')?.slice(7);
  if (token) {
    const sessionData = JSON.stringify({ pending_totp_secret: secret });
    await env.DB.prepare('UPDATE sessions SET data = ? WHERE id = ?').bind(sessionData, token).run();
  }

  return Response.json({ secret, uri }, { headers: corsHeaders });
}

// ── Enable: verify first code (does NOT commit) ────────────────────────────

async function mfaEnable(request, env, user, corsHeaders) {
  const { code } = await request.json();
  if (!code || code.length !== 6) {
    return Response.json({ error: '6-digit code required' }, { status: 400, headers: corsHeaders });
  }

  const token = request.headers.get('Authorization')?.slice(7);
  const session = await env.DB.prepare('SELECT data FROM sessions WHERE id = ?').bind(token).first();
  const data = session?.data ? JSON.parse(session.data) : {};
  const pendingSecret = data.pending_totp_secret;

  if (!pendingSecret) {
    return Response.json({ error: 'No pending 2FA setup. Start setup first.' }, { status: 400, headers: corsHeaders });
  }

  const valid = await verifyTotp(pendingSecret, code);
  if (!valid) {
    return Response.json({ error: 'Invalid code. Check your authenticator app and try again.' }, { status: 400, headers: corsHeaders });
  }

  // First code valid — keep pending secret for verify step
  return Response.json({ ok: true }, { headers: corsHeaders });
}

// ── Verify: verify second code and commit ───────────────────────────────────

async function mfaVerify(request, env, user, corsHeaders) {
  const { code } = await request.json();
  if (!code || code.length !== 6) {
    return Response.json({ error: '6-digit code required' }, { status: 400, headers: corsHeaders });
  }

  const token = request.headers.get('Authorization')?.slice(7);
  const session = await env.DB.prepare('SELECT data FROM sessions WHERE id = ?').bind(token).first();
  const data = session?.data ? JSON.parse(session.data) : {};
  const pendingSecret = data.pending_totp_secret;

  if (!pendingSecret) {
    return Response.json({ error: 'No pending 2FA setup. Start setup first.' }, { status: 400, headers: corsHeaders });
  }

  const valid = await verifyTotp(pendingSecret, code);
  if (!valid) {
    return Response.json({ error: 'Invalid code. Wait for a new code and try again.' }, { status: 400, headers: corsHeaders });
  }

  // Commit: enable TOTP on user
  await env.DB.prepare('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?').bind(pendingSecret, user.id).run();

  // Clear pending secret from session
  await env.DB.prepare('UPDATE sessions SET data = ? WHERE id = ?').bind('{}', token).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}

// ── Disable: requires password ──────────────────────────────────────────────

async function mfaDisable(request, env, user, corsHeaders) {
  const { password } = await request.json();
  if (!password) {
    return Response.json({ error: 'Password required' }, { status: 400, headers: corsHeaders });
  }

  const dbUser = await env.DB.prepare('SELECT password_hash FROM users WHERE id = ?').bind(user.id).first();
  if (!dbUser) {
    return Response.json({ error: 'User not found' }, { status: 404, headers: corsHeaders });
  }

  const passwordOk = await verifyPassword(password, dbUser.password_hash);
  if (!passwordOk) {
    return Response.json({ error: 'Incorrect password.' }, { status: 400, headers: corsHeaders });
  }

  await env.DB.prepare('UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?').bind(user.id).run();

  return Response.json({ ok: true }, { headers: corsHeaders });
}
