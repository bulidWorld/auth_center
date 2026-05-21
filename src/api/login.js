const express = require('express');
const db = require('../db/init');
const config = require('../config');
const logger = require('../logger');
const { signAccessToken } = require('../utils/jwt');
const { hashToken, generateToken } = require('../utils/crypto');
const { authenticate } = require('../ldap/authenticator');
const { loginLimiter } = require('../middleware/rateLimiter');
const crypto = require('crypto');

const router = express.Router();

// POST /api/login - Direct credential authentication
router.post('/login', loginLimiter, async (req, res) => {
  const { username, password, ttl, client_id } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'username and password are required' });
  }

  try {
    logger.info('Login attempt', { username, client_id: client_id || 'api' });
    const user = await authenticate(username, password);
    const jti = crypto.randomUUID();
    const accessTokenTTL = Math.min(ttl || config.jwt.accessTokenTTL, config.jwt.accessTokenTTL);

    const accessToken = signAccessToken({
      sub: user.dn,
      preferred_username: user.username,
      scope: 'api',
      client_id: client_id || 'api',
      jti,
    });

    const refreshToken = generateToken();
    const accessTokenExpiresAt = new Date(Date.now() + accessTokenTTL * 1000).toISOString();
    const refreshTokenExpiresAt = new Date(Date.now() + config.jwt.refreshTokenTTL * 1000).toISOString();

    // Store tokens
    db.prepare(
      'INSERT INTO access_tokens (jti, client_id, user_dn, user_data, scope, token_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(jti, client_id || 'api', user.dn, JSON.stringify(user), 'api', hashToken(accessToken), accessTokenExpiresAt);

    db.prepare(
      'INSERT INTO refresh_tokens (client_id, user_dn, user_data, token_hash, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(client_id || 'api', user.dn, JSON.stringify(user), hashToken(refreshToken), 'api', refreshTokenExpiresAt);

    logger.info('Login success', { username, client_id: client_id || 'api' });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: accessTokenTTL,
      refresh_token: refreshToken,
      scope: 'api',
      user: {
        username: user.username,
        displayName: user.displayName,
        email: user.email,
        dn: user.dn,
      },
    });
  } catch (err) {
    logger.warn('Login failed', { username, error: err.message });
    res.status(401).json({ error: 'invalid_credentials', error_description: err.message || 'Authentication failed' });
  }
});

module.exports = router;
