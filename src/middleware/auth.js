const { verifyAccessToken } = require('../utils/jwt');
const db = require('../db/init');
const config = require('../config');

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'unauthorized', error_description: 'Missing or invalid authorization header' });
  }

  const token = header.slice(7);
  try {
    const decoded = verifyAccessToken(token);
    // Check revocation
    const tokenHash = require('../utils/crypto').hashToken(token);
    const record = db.prepare('SELECT * FROM access_tokens WHERE token_hash = ? AND is_revoked = 0').get(tokenHash);
    if (!record) {
      return res.status(401).json({ error: 'token_revoked', error_description: 'Token has been revoked' });
    }
    req.user = {
      ...decoded,
      user_data: JSON.parse(record.user_data),
      client_id: record.client_id,
    };
    req.token = token;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'token_expired', error_description: 'Access token has expired' });
    }
    return res.status(401).json({ error: 'invalid_token', error_description: err.message });
  }
}

function sessionMiddleware(req, res, next) {
  const sessionId = req.cookies && req.cookies[config.session.cookieName];
  if (!sessionId) {
    req.session = null;
    return next();
  }

  const record = db.prepare(
    'SELECT * FROM sessions WHERE session_id = ? AND is_revoked = 0'
  ).get(sessionId);

  if (!record) {
    res.clearCookie(config.session.cookieName);
    req.session = null;
    return next();
  }

  const now = new Date();
  const expiresAt = new Date(record.expires_at);
  if (now > expiresAt) {
    db.prepare(`UPDATE sessions SET is_revoked = 1, revoked_at = datetime('now') WHERE session_id = ?`).run(sessionId);
    res.clearCookie(config.session.cookieName);
    req.session = null;
    return next();
  }

  req.session = {
    session_id: record.session_id,
    user_dn: record.user_dn,
    user_data: JSON.parse(record.user_data),
  };
  next();
}

module.exports = { authMiddleware, sessionMiddleware };
