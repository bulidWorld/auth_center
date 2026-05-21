const express = require('express');
const db = require('../db/init');
const config = require('../config');
const { verifyAccessToken } = require('../utils/jwt');
const { hashToken } = require('../utils/crypto');

const router = express.Router();

// GET /gateway/validate - nginx auth_request handler
// Returns 200 with user headers if authenticated, 401 otherwise
router.get('/validate', (req, res) => {
  // Try Bearer token first
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    try {
      const decoded = verifyAccessToken(token);
      const tokenHashVal = hashToken(token);
      const record = db.prepare(
        'SELECT * FROM access_tokens WHERE token_hash = ? AND is_revoked = 0'
      ).get(tokenHashVal);

      if (record) {
        const userData = JSON.parse(record.user_data);
        res.set('X-Auth-Username', userData.username || '');
        res.set('X-Auth-Sub', record.user_dn || '');
        res.set('X-Auth-Email', userData.email || '');
        return res.status(200).end();
      }
    } catch (err) {
      // Invalid token, try session
    }
  }

  // Try session cookie
  const sessionId = req.cookies && req.cookies[config.session.cookieName];
  if (sessionId) {
    const record = db.prepare(
      'SELECT * FROM sessions WHERE session_id = ? AND is_revoked = 0'
    ).get(sessionId);

    if (record) {
      const now = new Date();
      const expiresAt = new Date(record.expires_at);
      if (now <= expiresAt) {
        const userData = JSON.parse(record.user_data);
        res.set('X-Auth-Username', userData.username || '');
        res.set('X-Auth-Sub', record.user_dn || '');
        res.set('X-Auth-Email', userData.email || '');
        return res.status(200).end();
      }
    }
  }

  res.set('X-Auth-Error', 'unauthorized');
  res.status(401).end();
});

module.exports = router;
