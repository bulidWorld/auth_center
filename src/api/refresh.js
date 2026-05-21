const express = require('express');
const db = require('../db/init');
const config = require('../config');
const { signAccessToken } = require('../utils/jwt');
const { hashToken, generateToken } = require('../utils/crypto');
const { authMiddleware } = require('../middleware/auth');
const crypto = require('crypto');

const router = express.Router();

// POST /api/revoke - Revoke a token
router.post('/revoke', authMiddleware, (req, res) => {
  const tokenFromBody = req.body && req.body.token;
  const tokenToRevoke = tokenFromBody || req.token;

  if (!tokenToRevoke) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'token is required' });
  }

  const tokenHash = require('../utils/crypto').hashToken(tokenToRevoke);

  // Try to revoke from access_tokens
  const result = db.prepare(`UPDATE access_tokens SET is_revoked = 1, revoked_at = datetime('now') WHERE token_hash = ?`).run(tokenHash);
  if (result.changes > 0) {
    return res.json({ revoked: true });
  }

  // Try to revoke from refresh_tokens
  const result2 = db.prepare(`UPDATE refresh_tokens SET is_revoked = 1, revoked_at = datetime('now') WHERE token_hash = ?`).run(tokenHash);
  if (result2.changes > 0) {
    return res.json({ revoked: true });
  }

  // Token not found in store (may be self-validating JWT)
  res.json({ revoked: true });
});

// POST /api/refresh - Refresh access token
router.post('/refresh', (req, res) => {
  const { refresh_token, ttl } = req.body;

  if (!refresh_token) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'refresh_token is required' });
  }

  const tokenHash = hashToken(refresh_token);
  const record = db.prepare(
    'SELECT * FROM refresh_tokens WHERE token_hash = ? AND is_revoked = 0'
  ).get(tokenHash);

  if (!record) {
    return res.status(401).json({ error: 'invalid_grant', error_description: 'Invalid or revoked refresh token' });
  }

  if (new Date() > new Date(record.expires_at)) {
    db.prepare(`UPDATE refresh_tokens SET is_revoked = 1, revoked_at = datetime('now') WHERE token_hash = ?`).run(tokenHash);
    return res.status(401).json({ error: 'invalid_grant', error_description: 'Refresh token has expired' });
  }

  // Revoke old refresh token
  db.prepare(`UPDATE refresh_tokens SET is_revoked = 1, revoked_at = datetime('now') WHERE token_hash = ?`).run(tokenHash);

  // Issue new tokens
  const userData = JSON.parse(record.user_data);
  const jti = crypto.randomUUID();
  const accessTokenTTL = Math.min(ttl || config.jwt.accessTokenTTL, config.jwt.accessTokenTTL);

  const accessToken = signAccessToken({
    sub: userData.dn,
    preferred_username: userData.username,
    scope: record.scope || 'api',
    client_id: record.client_id,
    jti,
  });

  const newRefreshToken = generateToken();
  const accessTokenExpiresAt = new Date(Date.now() + accessTokenTTL * 1000).toISOString();
  const refreshTokenExpiresAt = new Date(Date.now() + config.jwt.refreshTokenTTL * 1000).toISOString();

  // Store new access token
  db.prepare(
    'INSERT INTO access_tokens (jti, client_id, user_dn, user_data, scope, token_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(jti, record.client_id, userData.dn, JSON.stringify(userData), record.scope || 'api', hashToken(accessToken), accessTokenExpiresAt);

  // Store new refresh token
  db.prepare(
    'INSERT INTO refresh_tokens (client_id, user_dn, user_data, token_hash, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(record.client_id, userData.dn, JSON.stringify(userData), hashToken(newRefreshToken), record.scope || 'api', refreshTokenExpiresAt);

  res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: accessTokenTTL,
    refresh_token: newRefreshToken,
    scope: record.scope || 'api',
  });
});

module.exports = router;
