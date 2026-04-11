# tests/phase4/mock_alerts.py

ALERTS = {

    "brute_force_ssh": {
        "alert_id":           "alert-001",
        "rule_description":   "Multiple failed SSH authentication attempts",
        "rule_id":            "5710",
        "rule_level":         10,
        "src_ip":             "45.33.32.156",
        "dst_ip":             "192.168.56.20",
        "agent_name":         "linux-target",
        "timestamp":          "2025-04-10T02:13:47Z",
        "user":               "root",
        # ML predictions (Phase 3 output — mocked)
        "ml_anomaly_score":   0.91,
        "ml_severity":        "high",
        "ml_attack_category": "brute_force",
        "ml_confidence":      0.87,
    },

    "port_scan": {
        "alert_id":           "alert-002",
        "rule_description":   "Nmap port scan detected from external IP",
        "rule_id":            "40111",
        "rule_level":         6,
        "src_ip":             "192.168.56.10",
        "dst_ip":             "192.168.56.20",
        "agent_name":         "linux-target",
        "timestamp":          "2025-04-10T01:58:22Z",
        "user":               None,
        "ml_anomaly_score":   0.65,
        "ml_severity":        "medium",
        "ml_attack_category": "port_scan",
        "ml_confidence":      0.79,
    },

    "privilege_escalation": {
        "alert_id":           "alert-003",
        "rule_description":   "Suspicious sudo command execution by non-admin user",
        "rule_id":            "5402",
        "rule_level":         13,
        "src_ip":             "192.168.56.10",
        "dst_ip":             "192.168.56.20",
        "agent_name":         "linux-target",
        "timestamp":          "2025-04-10T03:05:11Z",
        "user":               "testuser",
        "ml_anomaly_score":   0.94,
        "ml_severity":        "critical",
        "ml_attack_category": "privilege_escalation",
        "ml_confidence":      0.91,
    },

    "web_attack": {
        "alert_id":           "alert-004",
        "rule_description":   "SQL injection attempt detected in HTTP request",
        "rule_id":            "31103",
        "rule_level":         9,
        "src_ip":             "203.0.113.42",
        "dst_ip":             "192.168.56.20",
        "agent_name":         "linux-target",
        "timestamp":          "2025-04-10T14:22:33Z",
        "user":               None,
        "ml_anomaly_score":   0.78,
        "ml_severity":        "high",
        "ml_attack_category": "web_attack",
        "ml_confidence":      0.83,
    },

    "normal_login": {
        "alert_id":           "alert-005",
        "rule_description":   "SSH authentication success",
        "rule_id":            "5715",
        "rule_level":         3,
        "src_ip":             "192.168.1.10",
        "dst_ip":             "192.168.56.20",
        "agent_name":         "linux-target",
        "timestamp":          "2025-04-10T08:00:00Z",
        "user":               "alice",
        "ml_anomaly_score":   0.12,
        "ml_severity":        "low",
        "ml_attack_category": "normal",
        "ml_confidence":      0.95,
    },
}

def get_alert(name: str) -> dict:
    """Get a mock alert by name."""
    if name not in ALERTS:
        raise ValueError(f"Unknown alert: {name}. "
                         f"Available: {list(ALERTS.keys())}")
    return ALERTS[name].copy()

def get_all_alerts() -> list:
    return list(ALERTS.values())