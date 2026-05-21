const express = require('express');
const config = require('../config');
const { signAccessToken, verifyAccessToken } = require('../utils/jwt');

const router = express.Router();

// API key auth middleware
function apiKeyMiddleware(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey || apiKey !== config.adminApiKey) {
    return res.status(401).json({ error: 'unauthorized', error_description: 'Invalid or missing API key' });
  }
  next();
}

router.use(apiKeyMiddleware);

// POST /api/internal/token/sign
router.post('/token/sign', (req, res) => {
  const { payload, ttl } = req.body;
  if (!payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'payload object is required' });
  }
  try {
    const token = signAccessToken(payload, ttl || undefined);
    res.json({ token });
  } catch (err) {
    console.error('Token sign error:', err);
    res.status(500).json({ error: 'sign_failed', error_description: err.message });
  }
});

// POST /api/internal/token/verify
router.post('/token/verify', (req, res) => {
  const { token } = req.body;
  if (!token) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'token is required' });
  }
  try {
    const decoded = verifyAccessToken(token);
    res.json({ valid: true, payload: decoded });
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ valid: false, error: 'token_expired' });
    }
    return res.status(401).json({ valid: false, error: 'invalid_token' });
  }
});

module.exports = router;
