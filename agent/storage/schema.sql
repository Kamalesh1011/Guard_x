PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    type            TEXT NOT NULL,
    process_name    TEXT,
    pid             INTEGER,
    severity        TEXT NOT NULL CHECK(severity IN ('SAFE','LOW','MEDIUM','HIGH','CRITICAL')),
    summary         TEXT,
    reasons         TEXT,
    shap_values     TEXT,
    risk_factors    TEXT,
    mitre_ttps      TEXT,
    total_risk_score REAL DEFAULT 0,
    recommendation  TEXT,
    raw_event       TEXT,
    dismissed       INTEGER DEFAULT 0,
    whitelisted     INTEGER DEFAULT 0,
    created_at      DATETIME DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

CREATE TABLE IF NOT EXISTS whitelist (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    process_name    TEXT UNIQUE NOT NULL,
    added_at        DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS telemetry (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pillar          TEXT NOT NULL CHECK(pillar IN ('process','network','hardware','filesystem','idle')),
    snapshot        TEXT NOT NULL,
    created_at      DATETIME DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_telemetry_pillar ON telemetry(pillar);
CREATE INDEX IF NOT EXISTS idx_telemetry_created ON telemetry(created_at);

CREATE TABLE IF NOT EXISTS baseline (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    pillar          TEXT UNIQUE NOT NULL,
    model           BLOB,
    feature_names   TEXT,
    sample_count    INTEGER DEFAULT 0,
    fitted_at       DATETIME
);

CREATE TABLE IF NOT EXISTS settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL,
    updated_at      DATETIME DEFAULT (datetime('now'))
);
