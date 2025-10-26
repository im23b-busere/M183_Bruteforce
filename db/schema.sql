PRAGMA foreign_keys = ON;

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password_plain TEXT,
  password_hash TEXT,
  email TEXT,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);

-- Index to look up users by email quickly
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Authentication attempts log
CREATE TABLE IF NOT EXISTS auth_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT,
  ip TEXT,
  timestamp INTEGER NOT NULL DEFAULT (strftime('%s','now')),
  success INTEGER NOT NULL DEFAULT 0,
  method TEXT,
  note TEXT,
  
  FOREIGN KEY(username) REFERENCES users(username) ON DELETE SET NULL
);

-- Indices to speed up common queries on auth attempts
CREATE INDEX IF NOT EXISTS idx_auth_username ON auth_attempts(username);
CREATE INDEX IF NOT EXISTS idx_auth_ip ON auth_attempts(ip);
CREATE INDEX IF NOT EXISTS idx_auth_timestamp ON auth_attempts(timestamp);
CREATE INDEX IF NOT EXISTS idx_auth_username_timestamp ON auth_attempts(username, timestamp);
