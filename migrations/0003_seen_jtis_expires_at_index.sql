ALTER TABLE seen_jtis
  ALTER COLUMN expires_at TYPE TIMESTAMPTZ
  USING expires_at::timestamptz;

CREATE INDEX IF NOT EXISTS seen_jtis_expires_at_idx
  ON seen_jtis (expires_at);
