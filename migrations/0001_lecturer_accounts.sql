CREATE TABLE IF NOT EXISTS lecturer_accounts (
  lecturer_id TEXT PRIMARY KEY,
  full_name TEXT NOT NULL,
  department TEXT NOT NULL DEFAULT '',
  password_salt TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS lecturer_sessions (
  token_hash TEXT PRIMARY KEY,
  lecturer_id TEXT NOT NULL REFERENCES lecturer_accounts(lecturer_id) ON DELETE CASCADE,
  expires_at_ms BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_lecturer_sessions_lecturer ON lecturer_sessions(lecturer_id);
CREATE INDEX IF NOT EXISTS idx_lecturer_sessions_expiry ON lecturer_sessions(expires_at_ms);