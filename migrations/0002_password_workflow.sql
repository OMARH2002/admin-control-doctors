ALTER TABLE lecturer_accounts ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT TRUE;
CREATE TABLE IF NOT EXISTS lecturer_password_reset_requests (
  request_id TEXT PRIMARY KEY,
  lecturer_id TEXT NOT NULL REFERENCES lecturer_accounts(lecturer_id) ON DELETE CASCADE,
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  status TEXT NOT NULL DEFAULT 'pending',
  resolved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_lecturer_reset_requests_status ON lecturer_password_reset_requests(status, requested_at DESC);