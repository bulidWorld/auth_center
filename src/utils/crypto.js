const crypto = require('crypto');

function generateRandomBytes(length = 32) {
  return crypto.randomBytes(length);
}

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('base64url');
}

function generateCodeChallenge(verifier) {
  const hash = crypto.createHash('sha256').update(verifier).digest();
  return hash.toString('base64url');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateState() {
  return crypto.randomBytes(16).toString('hex');
}

function generateClientSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function generateJTI() {
  return crypto.randomUUID();
}

module.exports = {
  generateRandomBytes,
  generateSessionId,
  generateCodeVerifier,
  generateCodeChallenge,
  generateToken,
  hashToken,
  generateState,
  generateClientSecret,
  generateJTI,
};
