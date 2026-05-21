const db = require('./init');

const schema = `
CREATE TABLE IF NOT EXISTS clients (
    client_id       TEXT PRIMARY KEY,
    client_secret   TEXT NOT NULL,
    client_name     TEXT NOT NULL,
    redirect_uris   TEXT NOT NULL,
    grant_types     TEXT NOT NULL DEFAULT '["authorization_code"]',
    scope           TEXT DEFAULT 'openid profile',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS auth_codes (
    code            TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL REFERENCES clients(client_id),
    redirect_uri    TEXT NOT NULL,
    user_dn         TEXT NOT NULL,
    user_data       TEXT NOT NULL,
    code_challenge  TEXT NOT NULL,
    scope           TEXT DEFAULT 'openid profile',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL,
    consumed_at     TEXT,
    is_consumed     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS access_tokens (
    jti             TEXT PRIMARY KEY,
    client_id       TEXT,
    user_dn         TEXT NOT NULL,
    user_data       TEXT NOT NULL,
    scope           TEXT DEFAULT 'openid profile api',
    token_hash      TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL,
    revoked_at      TEXT,
    is_revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id       TEXT,
    user_dn         TEXT NOT NULL,
    user_data       TEXT NOT NULL,
    token_hash      TEXT NOT NULL UNIQUE,
    scope           TEXT DEFAULT 'openid profile api',
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL,
    revoked_at      TEXT,
    is_revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    user_dn         TEXT NOT NULL,
    user_data       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at      TEXT NOT NULL,
    last_seen_at    TEXT NOT NULL DEFAULT (datetime('now')),
    revoked_at      TEXT,
    is_revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON auth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_dn);
CREATE INDEX IF NOT EXISTS idx_access_tokens_hash ON access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_dn);
`;

function initDB() {
  db.exec(schema);
}

function cleanupExpired() {
  const now = new Date().toISOString();
  db.prepare('DELETE FROM auth_codes WHERE is_consumed = 1 AND expires_at < ?').run(now);
  db.prepare("DELETE FROM access_tokens WHERE is_revoked = 1 AND expires_at < datetime('now', '-7 days')").run();
  db.prepare("DELETE FROM refresh_tokens WHERE is_revoked = 1 AND expires_at < datetime('now', '-7 days')").run();
  db.prepare("DELETE FROM sessions WHERE is_revoked = 1 AND expires_at < datetime('now', '-1 day')").run();
}

// Run cleanup every 15 minutes
setInterval(cleanupExpired, 15 * 60 * 1000);

module.exports = { initDB, cleanupExpired };
