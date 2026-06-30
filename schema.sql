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
CREATE TABLE alerts (
    id          SERIAL PRIMARY KEY,
    title       TEXT        NOT NULL,
    category    TEXT        NOT NULL,
    severity    TEXT        NOT NULL
                CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    source      TEXT,
    source_ip   TEXT,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    status      TEXT        NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'true_positive', 'false_positive', 'escalated')),
    assigned_to TEXT
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
