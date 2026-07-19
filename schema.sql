-- SOC Analyst Dashboard schema
-- Drop existing objects so the schema can be re-applied cleanly.
DROP TABLE IF EXISTS analyst_actions CASCADE;
DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Analyst/admin accounts for dashboard login. Passwords are bcrypt-hashed and
-- never stored in plaintext. Accounts are created only via manage.py (no
-- self-registration).
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(64) UNIQUE NOT NULL,
    password_hash TEXT        NOT NULL,
    role          VARCHAR(16) NOT NULL DEFAULT 'analyst',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security alerts surfaced to the SOC queue.
--   category: brute_force | malware | phishing | port_scan | anomaly
--   severity: CRITICAL | HIGH | MEDIUM | LOW
--   status:   open | true_positive | false_positive | escalated
--   source:   detecting sensor/tool (EDR, Firewall/IDS, Email Gateway, ...)
--   workflow_run_id / run_metadata: optional provenance from an upstream
--     Orkes Conductor pipeline run (which run produced this alert + per-task
--     timings, JSON). Both NULL for manually-created or non-orchestrated alerts.
CREATE TABLE alerts (
    id              SERIAL PRIMARY KEY,
    title           TEXT        NOT NULL,
    category        TEXT        NOT NULL,
    severity        TEXT        NOT NULL
                    CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    source          TEXT,
    source_ip       TEXT,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    status          TEXT        NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'true_positive', 'false_positive', 'escalated')),
    assigned_to     TEXT,
    workflow_run_id TEXT,
    run_metadata    TEXT
);

-- Actions an analyst took to triage an alert.
--   action: classify_tp | classify_fp | escalate
CREATE TABLE analyst_actions (
    id                    SERIAL PRIMARY KEY,
    alert_id              INT         NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    analyst_name          TEXT        NOT NULL,
    action                TEXT        NOT NULL,
    acted_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    response_time_seconds INT
);

CREATE INDEX idx_alerts_status   ON alerts(status);
CREATE INDEX idx_alerts_severity ON alerts(severity);
CREATE INDEX idx_alerts_category ON alerts(category);
CREATE INDEX idx_alerts_source   ON alerts(source);
CREATE INDEX idx_alerts_assigned ON alerts(assigned_to);
CREATE INDEX idx_actions_alert   ON analyst_actions(alert_id);
CREATE INDEX idx_actions_analyst ON analyst_actions(analyst_name);

-- Audit log: every status change or analyst note is recorded here atomically
-- with the corresponding alert update (same transaction).
-- Roles: viewer (read-only) | analyst (triage) | admin (all + audit log view)
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    alert_id    INTEGER REFERENCES alerts(id) ON DELETE CASCADE,
    user_id     INTEGER REFERENCES users(id),
    username    VARCHAR(64) NOT NULL,
    action      VARCHAR(32) NOT NULL,   -- triage, escalate, reclassify, note_added
    from_status VARCHAR(32),
    to_status   VARCHAR(32),
    note        TEXT,                   -- encrypted when DB_ENCRYPTION_KEY is set
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_alert ON audit_log(alert_id);
CREATE INDEX IF NOT EXISTS idx_audit_user  ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_time  ON audit_log(created_at);
