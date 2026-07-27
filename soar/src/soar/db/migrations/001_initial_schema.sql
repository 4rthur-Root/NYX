CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL,
    attacker_ip TEXT,
    target_host TEXT NOT NULL,
    target_ip TEXT NOT NULL,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    events_count INTEGER NOT NULL DEFAULT 0,
    timestamp INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS responses (
    response_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    skip_reason TEXT,
    error TEXT,
    alert_timestamp INTEGER NOT NULL,
    response_timestamp INTEGER NOT NULL,
    latency_ms INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    FOREIGN KEY (alert_id) REFERENCES alerts(alert_id)
);

CREATE TABLE IF NOT EXISTS enrichments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id TEXT NOT NULL,
    source TEXT NOT NULL,
    abuseipdb_score INTEGER,
    country_code TEXT,
    isp TEXT,
    fallback_used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (response_id) REFERENCES responses(response_id)
);

CREATE TABLE IF NOT EXISTS opnsense_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id TEXT NOT NULL,
    rule_id TEXT,
    blocked_ip TEXT,
    api_status_code INTEGER NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (response_id) REFERENCES responses(response_id)
);

CREATE INDEX IF NOT EXISTS idx_responses_alert_id ON responses(alert_id);
CREATE INDEX IF NOT EXISTS idx_responses_status ON responses(status);
CREATE INDEX IF NOT EXISTS idx_responses_created_at ON responses(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);

CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    alert_id TEXT,
    details_json TEXT,
    timestamp INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events(event_type);
