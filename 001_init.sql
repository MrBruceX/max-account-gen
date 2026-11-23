CREATE TABLE IF NOT EXISTS admins (
  id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
  id BIGSERIAL PRIMARY KEY,
  token_hash CHAR(64) NOT NULL UNIQUE,
  csrf_token TEXT NOT NULL,
  user_type TEXT NOT NULL CHECK (user_type IN ('admin','customer')),
  admin_id BIGINT REFERENCES admins(id) ON DELETE CASCADE,
  license_id BIGINT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK ((user_type='admin' AND admin_id IS NOT NULL AND license_id IS NULL)
      OR (user_type='customer' AND license_id IS NOT NULL AND admin_id IS NULL))
);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS licenses (
  id BIGSERIAL PRIMARY KEY,
  token_hash CHAR(64) NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  tier TEXT NOT NULL CHECK (tier IN ('weekly','monthly','lifetime')),
  expires_at TIMESTAMPTZ NOT NULL,
  discord_id TEXT,
  rockstar_code_access BOOLEAN NOT NULL DEFAULT false,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE sessions
  ADD CONSTRAINT sessions_license_fk
  FOREIGN KEY (license_id) REFERENCES licenses(id) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS stock_items (
  id BIGSERIAL PRIMARY KEY,
  type TEXT NOT NULL CHECK (type IN ('discord','steam','rockstar','rockstar_code')),
  secret TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS stock_type_created_idx ON stock_items(type, created_at, id);

CREATE TABLE IF NOT EXISTS daily_usage (
  license_id BIGINT NOT NULL REFERENCES licenses(id) ON DELETE CASCADE,
  usage_date DATE NOT NULL,
  used INTEGER NOT NULL DEFAULT 0 CHECK (used >= 0),
  PRIMARY KEY (license_id, usage_date)
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS bug_reports (
  id BIGSERIAL PRIMARY KEY,
  discord_id TEXT NOT NULL CHECK (discord_id ~ '^[0-9]{15,20}$'),
  username TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT '',
  title TEXT NOT NULL,
  body TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  actor_type TEXT NOT NULL,
  actor_id BIGINT,
  action TEXT NOT NULL,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
