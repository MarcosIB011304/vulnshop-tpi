// Capa de acceso a datos con SQLite (better-sqlite3). La base vive en un
// archivo dentro del contenedor y se recrea con datos de ejemplo al arrancar.
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const { MODE } = require('./config');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Cada modo usa su propia base, asi se pueden correr la version vulnerable y la
// segura al mismo tiempo sin pisarse (en Docker ademas son contenedores aparte).
const db = new Database(path.join(DATA_DIR, `vulnshop-${MODE}.db`));
db.pragma('journal_mode = WAL');

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      address TEXT
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      price INTEGER NOT NULL,
      emoji TEXT NOT NULL,
      description TEXT
    );
    CREATE TABLE IF NOT EXISTS reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      product_id INTEGER NOT NULL,
      author TEXT NOT NULL,
      rating INTEGER NOT NULL,
      body TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      total INTEGER NOT NULL,
      status TEXT NOT NULL,
      items TEXT NOT NULL
    );
  `);
}

module.exports = { db, init };
