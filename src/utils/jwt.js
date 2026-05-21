const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const config = require('../config');

const privateKeyPath = path.join(config.jwt.keyDir, 'jwt-private.pem');
const publicKeyPath = path.join(config.jwt.keyDir, 'jwt-public.pem');

function ensureKeys() {
  if (!fs.existsSync(privateKeyPath) || !fs.existsSync(publicKeyPath)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    fs.mkdirSync(config.jwt.keyDir, { recursive: true });
    fs.writeFileSync(privateKeyPath, privateKey);
    fs.writeFileSync(publicKeyPath, publicKey);
  }
  return {
    privateKey: fs.readFileSync(privateKeyPath, 'utf8'),
    publicKey: fs.readFileSync(publicKeyPath, 'utf8'),
  };
}

const keys = ensureKeys();

function signAccessToken(payload) {
  return jwt.sign(payload, keys.privateKey, {
    algorithm: 'RS256',
    issuer: config.jwt.issuer,
    expiresIn: config.jwt.accessTokenTTL,
    keyid: 'key-001',
  });
}

function signRefreshToken(payload) {
  return jwt.sign(payload, keys.privateKey, {
    algorithm: 'RS256',
    issuer: config.jwt.issuer,
    expiresIn: config.jwt.refreshTokenTTL,
    keyid: 'key-001',
  });
}

function signIdToken(payload) {
  return jwt.sign(payload, keys.privateKey, {
    algorithm: 'RS256',
    issuer: config.jwt.issuer,
    expiresIn: config.jwt.accessTokenTTL,
    keyid: 'key-001',
  });
}

function verifyAccessToken(token) {
  return jwt.verify(token, keys.publicKey, {
    algorithms: ['RS256'],
    issuer: config.jwt.issuer,
  });
}

function getPublicKey() {
  return keys.publicKey;
}

function getJwks() {
  return {
    keys: [
      {
        kty: 'RSA',
        kid: 'key-001',
        use: 'sig',
        alg: 'RS256',
        n: extractN(keys.publicKey),
        e: extractE(keys.publicKey),
      },
    ],
  };
}

// Minimal RSA public key to JWK converter
function extractN(publicKeyPem) {
  const der = Buffer.from(
    publicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, ''),
    'base64'
  );

  // Parse ASN.1 to find the modulus
  // Skip the outer SEQUENCE, bit string wrapper, and RSA OID
  let offset = 0;

  // Outer SEQUENCE
  if (der[offset++] !== 0x30) throw new Error('Invalid PEM');
  skipLength(der, offset); offset = skipLengthOffset(der, offset);

  // SEQUENCE (AlgorithmIdentifier)
  if (der[offset++] !== 0x30) throw new Error('Invalid PEM');
  const algoLen = readLength(der, offset); offset = skipLengthOffset(der, offset);
  offset += algoLen;

  // BIT STRING
  if (der[offset++] !== 0x03) throw new Error('Invalid PEM');
  const bitStrLen = readLength(der, offset); offset = skipLengthOffset(der, offset);
  offset++; // skip unused bits byte

  // Inner SEQUENCE (modulus, exponent)
  if (der[offset++] !== 0x30) throw new Error('Invalid PEM');
  const innerLen = readLength(der, offset); offset = skipLengthOffset(der, offset);

  // Modulus INTEGER
  if (der[offset++] !== 0x02) throw new Error('Invalid PEM');
  const modLen = readLength(der, offset); offset = skipLengthOffset(der, offset);
  let nBuf = der.slice(offset, offset + modLen);
  // Remove leading zero byte if present (ASN.1 sign byte)
  if (nBuf[0] === 0x00) nBuf = nBuf.slice(1);
  offset += modLen;

  return nBuf.toString('base64url');
}

function extractE(publicKeyPem) {
  const der = Buffer.from(
    publicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----/, '')
      .replace(/-----END PUBLIC KEY-----/, '')
      .replace(/\s/g, ''),
    'base64'
  );

  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error('Invalid PEM');
  offset = skipLengthOffset(der, offset);
  if (der[offset++] !== 0x30) throw new Error('Invalid PEM');
  const algoLen = readLength(der, offset); offset = skipLengthOffset(der, offset);
  offset += algoLen;
  if (der[offset++] !== 0x03) throw new Error('Invalid PEM');
  const bitStrLen = readLength(der, offset); offset = skipLengthOffset(der, offset);
  offset++;
  if (der[offset++] !== 0x30) throw new Error('Invalid PEM');
  const innerLen = readLength(der, offset); offset = skipLengthOffset(der, offset);
  if (der[offset++] !== 0x02) throw new Error('Invalid PEM');
  const modLen = readLength(der, offset); offset = skipLengthOffset(der, offset);
  offset += modLen;

  // Exponent INTEGER
  if (der[offset++] !== 0x02) throw new Error('Invalid PEM');
  const expLen = readLength(der, offset); offset = skipLengthOffset(der, offset);
  let eBuf = der.slice(offset, offset + expLen);
  if (eBuf[0] === 0x00) eBuf = eBuf.slice(1);

  return eBuf.toString('base64url');
}

function readLength(buf, offset) {
  if (buf[offset] < 0x80) return buf[offset];
  const numBytes = buf[offset] & 0x7f;
  let len = 0;
  for (let i = 0; i < numBytes; i++) {
    len = (len << 8) | buf[offset + 1 + i];
  }
  return len;
}

function skipLength(buf, offset) {
  if (buf[offset] < 0x80) return 1;
  return (buf[offset] & 0x7f) + 1;
}

function skipLengthOffset(buf, offset) {
  if (buf[offset] < 0x80) return offset + 1;
  return offset + 1 + (buf[offset] & 0x7f);
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  signIdToken,
  verifyAccessToken,
  getPublicKey,
  getJwks,
};
