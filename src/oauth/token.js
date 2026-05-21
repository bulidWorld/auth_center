const express = require('express');
const db = require('../db/init');
const config = require('../config');
const { signAccessToken, signRefreshToken, signIdToken } = require('../utils/jwt');
const { hashToken, generateToken, generateCodeChallenge } = require('../utils/crypto');
const { clientAuthMiddleware } = require('../middleware/clientAuth');
const { tokenLimiter } = require('../middleware/rateLimiter');
const crypto = require('crypto');

const router = express.Router();

// POST /token - Exchange authorization code for tokens
router.post('/', tokenLimiter, clientAuthMiddleware, (req, res) => {
  const { grant_type, code, redirect_uri, code_verifier, refresh_token } = req.body;

  if (grant_type === 'authorization_code') {
    handleAuthorizationCode(req, res, code, redirect_uri, code_verifier);
  } else if (grant_type === 'refresh_token') {
    handleRefreshToken(req, res, refresh_token);
  } else {
    res.status(400).json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code and refresh_token are supported' });
  }
});

function handleAuthorizationCode(req, res, code, redirect_uri, code_verifier) {
  if (!code || !redirect_uri) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing code or redirect_uri' });
  }

  // Find and consume the auth code
  const authCode = db.prepare(
    'SELECT * FROM auth_codes WHERE code = ? AND is_consumed = 0'
  ).get(code);

  if (!authCode) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code not found or already consumed' });
  }

  // Check expiry
  if (new Date() > new Date(authCode.expires_at)) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code has expired' });
  }

  // Verify redirect_uri
  if (authCode.redirect_uri !== redirect_uri) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' });
  }

  // Verify PKCE
  if (!code_verifier) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier is required' });
  }
  const computedChallenge = generateCodeChallenge(code_verifier);
  if (computedChallenge !== authCode.code_challenge) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
  }

  // Mark code as consumed
  db.prepare(`UPDATE auth_codes SET is_consumed = 1, consumed_at = datetime('now') WHERE code = ?`).run(code);

  // Issue tokens
  const userData = JSON.parse(authCode.user_data);
  const tokens = generateTokens(req.client, userData, authCode.scope);
  res.json(tokens);
}

function handleRefreshToken(req, res, refreshToken) {
  if (!refreshToken) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'refresh_token is required' });
  }

  const tokenHash = hashToken(refreshToken);
  const record = db.prepare(
    'SELECT * FROM refresh_tokens WHERE token_hash = ? AND is_revoked = 0'
  ).get(tokenHash);

  if (!record) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or revoked refresh token' });
  }

  if (record.client_id !== req.client.client_id) {
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Client mismatch' });
  }

  if (new Date() > new Date(record.expires_at)) {
    // Revoke and reject
    db.prepare(`UPDATE refresh_tokens SET is_revoked = 1, revoked_at = datetime('now') WHERE token_hash = ?`).run(tokenHash);
    return res.status(400).json({ error: 'invalid_grant', error_description: 'Refresh token has expired' });
  }

  // Rotate: revoke old, issue new
  db.prepare(`UPDATE refresh_tokens SET is_revoked = 1, revoked_at = datetime('now') WHERE token_hash = ?`).run(tokenHash);

  const userData = JSON.parse(record.user_data);
  const tokens = generateTokens(req.client, userData, record.scope);
  res.json(tokens);
}

function generateTokens(client, userData, scope) {
  const jti = crypto.randomUUID();
  const accessToken = signAccessToken({
    sub: userData.dn,
    preferred_username: userData.username,
    scope: scope || 'openid profile api',
    client_id: client.client_id,
    jti,
  });

  const refreshToken = generateToken();
  const accessTokenExpiresAt = new Date(Date.now() + config.jwt.accessTokenTTL * 1000).toISOString();
  const refreshTokenExpiresAt = new Date(Date.now() + config.jwt.refreshTokenTTL * 1000).toISOString();

  // Store access token metadata
  db.prepare(
    'INSERT INTO access_tokens (jti, client_id, user_dn, user_data, scope, token_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(jti, client.client_id, userData.dn, JSON.stringify(userData), scope || 'openid profile api', hashToken(accessToken), accessTokenExpiresAt);

  // Store refresh token hash
  db.prepare(
    'INSERT INTO refresh_tokens (client_id, user_dn, user_data, token_hash, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(client.client_id, userData.dn, JSON.stringify(userData), hashToken(refreshToken), scope || 'openid profile api', refreshTokenExpiresAt);

  // ID token for OIDC
  const idToken = signIdToken({
    sub: userData.dn,
    preferred_username: userData.username,
    aud: client.client_id,
    iat: Math.floor(Date.now() / 1000),
    // Note: iss and exp are set by signIdToken options (issuer, expiresIn)
  });

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.jwt.accessTokenTTL,
    refresh_token: refreshToken,
    scope: scope || 'openid profile api',
    id_token: idToken,
  };
}

module.exports = router;
