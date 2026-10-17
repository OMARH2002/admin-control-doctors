PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS lecturer_accounts (
  lecturer_id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  department TEXT NOT NULL DEFAULT '',
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  must_change_password INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS lecturer_sessions (
  token_hash TEXT PRIMARY KEY,
  lecturer_id TEXT NOT NULL REFERENCES lecturer_accounts(lecturer_id) ON DELETE CASCADE,
  expires_at_ms INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_lecturer_sessions_lecturer ON lecturer_sessions(lecturer_id);
CREATE INDEX IF NOT EXISTS idx_lecturer_sessions_expiry ON lecturer_sessions(expires_at_ms);

CREATE TABLE IF NOT EXISTS lecturer_password_reset_requests (
  request_id TEXT PRIMARY KEY,
  lecturer_id TEXT NOT NULL REFERENCES lecturer_accounts(lecturer_id) ON DELETE CASCADE,
  requested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  status TEXT NOT NULL DEFAULT 'pending',
  resolved_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_lecturer_reset_requests_status ON lecturer_password_reset_requests(status, requested_at);
