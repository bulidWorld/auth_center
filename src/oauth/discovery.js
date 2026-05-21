const express = require('express');
const { getJwks } = require('../utils/jwt');
const { authMiddleware } = require('../middleware/auth');
const config = require('../config');

const discoveryRouter = express.Router();

// GET /.well-known/openid-configuration
discoveryRouter.get('/openid-configuration', (req, res) => {
  const issuer = process.env.JWT_ISSUER || `http://localhost:${config.port}`;
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    userinfo_endpoint: `${issuer}/userinfo`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    code_challenge_methods_supported: ['S256'],
  });
});

// GET /.well-known/jwks.json
discoveryRouter.get('/jwks.json', (req, res) => {
  res.json(getJwks());
});

const userinfoRouter = express.Router();
userinfoRouter.get('/', authMiddleware, (req, res) => {
  const userData = req.user.user_data || {};
  res.json({
    sub: req.user.sub || userData.dn,
    preferred_username: req.user.preferred_username || userData.username,
    name: userData.displayName || userData.username,
    email: userData.email || null,
  });
});

module.exports = { discoveryRouter, userinfoRouter };
