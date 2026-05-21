const express = require('express');
const { authMiddleware } = require('../middleware/auth');

const router = express.Router();

// GET /api/verify - Verify token
router.get('/verify', authMiddleware, (req, res) => {
  const userData = req.user.user_data || {};
  res.json({
    valid: true,
    user: {
      username: userData.username || req.user.preferred_username,
      displayName: userData.displayName,
      email: userData.email,
      sub: req.user.sub,
    },
    expires_at: new Date(req.user.exp * 1000).toISOString(),
    scope: req.user.scope,
  });
});

module.exports = router;
