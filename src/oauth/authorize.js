const express = require('express');
const db = require('../db/init');
const config = require('../config');
const { generateToken, hashToken, generateCodeChallenge } = require('../utils/crypto');
const { authenticate } = require('../ldap/authenticator');
const { sessionMiddleware } = require('../middleware/auth');
const { loginLimiter } = require('../middleware/rateLimiter');
const winston = require('winston');

const router = express.Router();
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  transports: [new winston.transports.Console()],
});

// GET /authorize - OAuth 2.0 Authorization endpoint
router.get('/', sessionMiddleware, (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
  } = req.query;

  // Validate required params
  if (response_type !== 'code') {
    return res.status(400).json({ error: 'unsupported_response_type', error_description: 'Only authorization_code is supported' });
  }
  if (!client_id || !redirect_uri || !state) {
    return res.status(400).json({ error: 'invalid_request', error_description: 'Missing required parameters' });
  }
  if (!code_challenge || code_challenge_method !== 'S256') {
    return res.status(400).json({ error: 'invalid_request', error_description: 'PKCE S256 is required' });
  }

  // Validate client
  const client = db.prepare('SELECT * FROM clients WHERE client_id = ? AND is_active = 1').get(client_id);
  if (!client) {
    return res.status(400).json({ error: 'invalid_client', error_description: 'Client not found' });
  }

  const redirectUris = JSON.parse(client.redirect_uris);
  if (!redirectUris.includes(redirect_uri)) {
    return res.status(400).json({ error: 'invalid_redirect_uri', error_description: 'Redirect URI not registered' });
  }

  // If user has valid session, generate auth code and redirect immediately
  if (req.session) {
    const code = generateToken();
    const expiresAt = new Date(Date.now() + config.authCodeTTL * 1000).toISOString();

    db.prepare(
      'INSERT INTO auth_codes (code, client_id, redirect_uri, user_dn, user_data, code_challenge, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      code, client_id, redirect_uri,
      req.session.user_dn,
      JSON.stringify(req.session.user_data),
      code_challenge,
      scope || 'openid profile',
      expiresAt
    );

    const redirectUrl = `${redirect_uri}?code=${code}&state=${state}`;
    return res.redirect(redirectUrl);
  }

  // No session - show login form
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - Auth Center</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .login-container { background: white; padding: 2.5rem; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #1a1a2e; text-align: center; }
    .subtitle { text-align: center; color: #666; margin-bottom: 2rem; font-size: 0.9rem; }
    .form-group { margin-bottom: 1.25rem; }
    label { display: block; margin-bottom: 0.4rem; font-size: 0.875rem; color: #333; font-weight: 500; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.75rem 1rem; border: 1px solid #ddd; border-radius: 8px; font-size: 1rem; transition: border-color 0.2s; }
    input:focus { outline: none; border-color: #4361ee; box-shadow: 0 0 0 3px rgba(67,97,238,0.1); }
    .btn { width: 100%; padding: 0.75rem; background: #4361ee; color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 500; cursor: pointer; transition: background 0.2s; margin-top: 0.5rem; }
    .btn:hover { background: #3a56d4; }
    .error { background: #fee; color: #c00; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.875rem; display: none; }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>Auth Center</h1>
    <p class="subtitle">Sign in with your LDAP credentials</p>
    <div class="error" id="error"></div>
    <form method="POST" action="/authorize/login">
      <input type="hidden" name="client_id" value="${client_id}">
      <input type="hidden" name="redirect_uri" value="${redirect_uri}">
      <input type="hidden" name="state" value="${state}">
      <input type="hidden" name="code_challenge" value="${code_challenge}">
      <input type="hidden" name="scope" value="${scope || 'openid profile'}">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autocomplete="username" autofocus>
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn">Sign In</button>
    </form>
  </div>
</body>
</html>`);
});

// POST /oauth/login - Process login form submission
router.post('/login', loginLimiter, sessionMiddleware, async (req, res) => {
  const { username, password, client_id, redirect_uri, state, code_challenge, scope } = req.body;

  if (!username || !password) {
    return res.status(400).send(renderLoginError('Username and password are required', req.body));
  }

  try {
    const user = await authenticate(username, password);

    // Create session
    const sessionId = require('../utils/crypto').generateSessionId();
    const expiresAt = new Date(Date.now() + config.session.ttl * 1000).toISOString();

    db.prepare(
      'INSERT INTO sessions (session_id, user_dn, user_data, expires_at) VALUES (?, ?, ?, ?)'
    ).run(sessionId, user.dn, JSON.stringify(user), expiresAt);

    res.cookie(config.session.cookieName, sessionId, {
      httpOnly: true,
      secure: false, // Set true in production with HTTPS
      sameSite: 'lax',
      maxAge: config.session.ttl * 1000,
      path: '/',
    });

    // Generate auth code and redirect
    const code = generateToken();
    const codeExpiresAt = new Date(Date.now() + config.authCodeTTL * 1000).toISOString();

    db.prepare(
      'INSERT INTO auth_codes (code, client_id, redirect_uri, user_dn, user_data, code_challenge, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      code, client_id, redirect_uri, user.dn, JSON.stringify(user), code_challenge, scope || 'openid profile', codeExpiresAt
    );

    const redirectUrl = `${redirect_uri}?code=${code}&state=${state}`;
    res.redirect(redirectUrl);
  } catch (err) {
    res.status(401).send(renderLoginError('Invalid username or password', { client_id, redirect_uri, state, code_challenge, scope }));
  }
});

function renderLoginError(message, fields = {}) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - Auth Center</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .login-container { background: white; padding: 2.5rem; border-radius: 12px; box-shadow: 0 4px 24px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
    h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #1a1a2e; text-align: center; }
    .subtitle { text-align: center; color: #666; margin-bottom: 2rem; font-size: 0.9rem; }
    .form-group { margin-bottom: 1.25rem; }
    label { display: block; margin-bottom: 0.4rem; font-size: 0.875rem; color: #333; font-weight: 500; }
    input[type="text"], input[type="password"] { width: 100%; padding: 0.75rem 1rem; border: 1px solid #ddd; border-radius: 8px; font-size: 1rem; }
    input:focus { outline: none; border-color: #4361ee; box-shadow: 0 0 0 3px rgba(67,97,238,0.1); }
    .btn { width: 100%; padding: 0.75rem; background: #4361ee; color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 500; cursor: pointer; margin-top: 0.5rem; }
    .error { background: #fee; color: #c00; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; font-size: 0.875rem; }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>Auth Center</h1>
    <p class="subtitle">Sign in with your LDAP credentials</p>
    <div class="error">${message}</div>
    <form method="POST" action="/authorize/login">
      <input type="hidden" name="client_id" value="${fields.client_id || ''}">
      <input type="hidden" name="redirect_uri" value="${fields.redirect_uri || ''}">
      <input type="hidden" name="state" value="${fields.state || ''}">
      <input type="hidden" name="code_challenge" value="${fields.code_challenge || ''}">
      <input type="hidden" name="scope" value="${fields.scope || 'openid profile'}">
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" required autocomplete="username" autofocus>
      </div>
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn">Sign In</button>
    </form>
  </div>
</body>
</html>`;
}

module.exports = router;
