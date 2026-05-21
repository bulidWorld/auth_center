require('dotenv/config');
const path = require('path');

module.exports = {
  port: parseInt(process.env.PORT, 10) || 10531,

  ldap: {
    url: process.env.LDAP_URL || 'ldap://192.168.124.247:389',
    bindDN: process.env.LDAP_BIND_DN || 'cn=admin,dc=naze',
    bindPassword: process.env.LDAP_BIND_PASSWORD || 'Naze666666',
    baseDN: process.env.LDAP_BASE_DN || 'dc=naze',
    userSearchBase: process.env.LDAP_USER_SEARCH_BASE || 'dc=naze',
    userSearchFilter: process.env.LDAP_USER_SEARCH_FILTER || '(uid={{username}})',
  },

  jwt: {
    keyDir: path.resolve(__dirname, '..', process.env.JWT_KEY_DIR || 'data'),
    issuer: process.env.JWT_ISSUER || 'auth-center',
    accessTokenTTL: parseInt(process.env.JWT_ACCESS_TOKEN_TTL, 10) || 3600,
    refreshTokenTTL: parseInt(process.env.JWT_REFRESH_TOKEN_TTL, 10) || 604800,
  },

  session: {
    secret: process.env.SESSION_SECRET || 'change-me-in-production',
    cookieName: process.env.SESSION_COOKIE_NAME || 'ac_session',
    ttl: parseInt(process.env.SESSION_TTL, 10) || 86400,
  },

  authCodeTTL: parseInt(process.env.AUTH_CODE_TTL, 10) || 60,

  db: {
    path: path.resolve(__dirname, '..', process.env.DB_PATH || 'data/auth_center.db'),
  },

  corsOrigins: (process.env.CORS_ORIGINS || '').split(',').filter(Boolean),

  adminApiKey: process.env.ADMIN_API_KEY || '',
};
