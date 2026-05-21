const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const config = require('../config');

const dbDir = path.dirname(config.db.path);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new Database(config.db.path);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

module.exports = db;
