const express = require('express');
const bcrypt = require('bcrypt');
const db = require('../db/init');
const { generateClientSecret } = require('../utils/crypto');
const config = require('../config');

const router = express.Router();

// Simple admin auth - check API key
function adminAuth(req, res, next) {
  const apiKey = req.headers['x-admin-api-key'];
  if (!config.adminApiKey || apiKey !== config.adminApiKey) {
    return res.status(401).json({ error: 'unauthorized', error_description: 'Admin API key required' });
  }
  next();
}

// POST /admin/clients - Register a new client
router.post('/clients', adminAuth, (req, res) => {
  const { client_name, redirect_uris, grant_types, scope } = req.body;

  if (!client_name || !redirect_uris || !Array.isArray(redirect_uris)) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'client_name and redirect_uris (array) are required' });
  }

  const crypto = require('crypto');
  const clientId = crypto.randomUUID();
  const clientSecret = generateClientSecret();
  const secretHash = bcrypt.hashSync(clientSecret, 10);

  db.prepare(
    'INSERT INTO clients (client_id, client_secret, client_name, redirect_uris, grant_types, scope) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(
    clientId,
    secretHash,
    client_name,
    JSON.stringify(redirect_uris),
    JSON.stringify(grant_types || ['authorization_code']),
    scope || 'openid profile'
  );

  res.status(201).json({
    client_id: clientId,
    client_secret: clientSecret,
    client_name,
    redirect_uris,
    grant_types: grant_types || ['authorization_code'],
    scope: scope || 'openid profile',
    created_at: new Date().toISOString(),
  });
});

// GET /admin/clients - List all clients
router.get('/clients', adminAuth, (req, res) => {
  const clients = db.prepare('SELECT client_id, client_name, redirect_uris, grant_types, scope, created_at, is_active FROM clients').all();
  res.json(clients);
});

// PUT /admin/clients/:id - Update a client
router.put('/clients/:id', adminAuth, (req, res) => {
  const { client_name, redirect_uris, grant_types, scope, is_active } = req.body;
  
  // Build update query dynamically
  const updates = [];
  const values = [];
  
  if (client_name) {
    updates.push('client_name = ?');
    values.push(client_name);
  }
  if (redirect_uris && Array.isArray(redirect_uris)) {
    updates.push('redirect_uris = ?');
    values.push(JSON.stringify(redirect_uris));
  }
  if (grant_types && Array.isArray(grant_types)) {
    updates.push('grant_types = ?');
    values.push(JSON.stringify(grant_types));
  }
  if (scope) {
    updates.push('scope = ?');
    values.push(scope);
  }
  if (is_active !== undefined) {
    updates.push('is_active = ?');
    values.push(is_active ? 1 : 0);
  }
  
  if (updates.length === 0) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'No fields to update' });
  }
  
  values.push(req.params.id);
  
  const result = db.prepare(`UPDATE clients SET ${updates.join(', ')} WHERE client_id = ?`).run(...values);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'not_found', error_description: 'Client not found' });
  }
  
  res.json({ updated: true, client_id: req.params.id });
});

// DELETE /admin/clients/:id - Delete a client
router.delete('/clients/:id', adminAuth, (req, res) => {
  const result = db.prepare('DELETE FROM clients WHERE client_id = ?').run(req.params.id);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'not_found', error_description: 'Client not found' });
  }
  res.json({ deleted: true });
});

module.exports = router;
