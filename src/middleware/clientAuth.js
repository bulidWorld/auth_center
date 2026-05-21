const bcrypt = require('bcrypt');
const db = require('../db/init');

function clientAuthMiddleware(req, res, next) {
  const { client_id, client_secret } = req.body;

  if (!client_id || !client_secret) {
    // Try Basic Auth
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Basic ')) {
      const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
      const [id, secret] = decoded.split(':');
      req.body.client_id = id;
      req.body.client_secret = secret;
    } else {
      return res.status(400).json({ error: 'invalid_client', error_description: 'Missing client credentials' });
    }
  }

  const client = db.prepare('SELECT * FROM clients WHERE client_id = ? AND is_active = 1').get(req.body.client_id);
  if (!client) {
    return res.status(401).json({ error: 'invalid_client', error_description: 'Client not found or inactive' });
  }

  const valid = bcrypt.compareSync(req.body.client_secret, client.client_secret);
  if (!valid) {
    return res.status(401).json({ error: 'invalid_client', error_description: 'Invalid client secret' });
  }

  req.client = client;
  next();
}

module.exports = { clientAuthMiddleware };
