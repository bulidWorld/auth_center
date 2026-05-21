const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const config = require('./config');
const { initDB } = require('./db/schema');

// Initialize database
initDB();

const app = express();

// Global middleware
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));
app.use(cors({
  origin: config.corsOrigins.length > 0 ? config.corsOrigins : true,
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// OAuth 2.0 / OIDC routes
app.use('/authorize', require('./oauth/authorize'));
app.use('/oauth/login', require('./oauth/authorize'));
app.use('/token', require('./oauth/token'));
app.use('/.well-known', require('./oauth/discovery').discoveryRouter);
app.use('/userinfo', require('./oauth/discovery').userinfoRouter);

// API Token routes (all under /api)
app.use('/api', require('./api/login'));
app.use('/api', require('./api/verify'));
app.use('/api', require('./api/refresh'));
app.use('/api', require('./api/users'));

// Gateway (nginx auth_request)
app.use('/gateway', require('./gateway/validate'));

// Internal service-to-service routes
app.use('/api/internal', require('./api/internal'));

// Admin routes
app.use('/admin', require('./admin/clients'));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handler
app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'internal_server_error', error_description: 'An unexpected error occurred' });
});

// Start server
const PORT = config.port;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Auth Center running on port ${PORT}`);
  console.log(`LDAP URL: ${config.ldap.url}`);
  console.log(`JWT Issuer: ${config.jwt.issuer}`);
});

module.exports = app;
