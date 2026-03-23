-- Vault D1 Schema

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS environments (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  name TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE(project_id, name)
);

CREATE TABLE IF NOT EXISTS secret_versions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  environment_id TEXT NOT NULL REFERENCES environments(id),
  version INTEGER NOT NULL,
  encrypted_blob TEXT NOT NULL,
  changed_keys TEXT,
  created_at TEXT NOT NULL,
  UNIQUE(environment_id, version)
);

CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  device_name TEXT NOT NULL,
  device_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TEXT NOT NULL,
  approved_at TEXT,
  last_seen_at TEXT,
  UNIQUE(project_id, device_hash)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id TEXT,
  environment_id TEXT,
  action TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_env_project ON environments(project_id);
CREATE INDEX IF NOT EXISTS idx_sv_env ON secret_versions(environment_id, version DESC);
CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_devices_project ON devices(project_id);
CREATE INDEX IF NOT EXISTS idx_devices_hash ON devices(project_id, device_hash);
