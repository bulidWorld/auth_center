const express = require('express');
const { getUser, searchUsers } = require('../ldap/authenticator');

const router = express.Router();

// GET /api/users — Search LDAP users
router.get('/users', async (req, res) => {
  const { q, limit } = req.query;
  try {
    const users = await searchUsers(q || '', parseInt(limit, 10) || 50);
    res.json({ total: users.length, users });
  } catch (err) {
    res.status(500).json({ error: 'ldap_error', error_description: err.message });
  }
});

// GET /api/users/:username — Get a specific LDAP user
router.get('/users/:username', async (req, res) => {
  try {
    const user = await getUser(req.params.username);
    res.json(user);
  } catch (err) {
    if (err.message === 'User not found') {
      return res.status(404).json({ error: 'not_found', error_description: err.message });
    }
    res.status(500).json({ error: 'ldap_error', error_description: err.message });
  }
});

module.exports = router;
