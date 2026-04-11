# tests/phase4/mock_elastic.py

CONTEXT_LOGS = {

    "45.33.32.156": [  # brute force IP
        {"timestamp": "2025-04-10T02:00:11Z", "event": "Failed SSH login",
         "src_ip": "45.33.32.156", "user": "root",   "rule_id": "5710"},
        {"timestamp": "2025-04-10T02:00:14Z", "event": "Failed SSH login",
         "src_ip": "45.33.32.156", "user": "admin",  "rule_id": "5710"},
        {"timestamp": "2025-04-10T02:00:17Z", "event": "Failed SSH login",
         "src_ip": "45.33.32.156", "user": "ubuntu", "rule_id": "5710"},
        {"timestamp": "2025-04-10T02:13:47Z", "event": "Failed SSH login",
         "src_ip": "45.33.32.156", "user": "root",   "rule_id": "5710",
         "count_last_10min": 47},
    ],

    "192.168.56.10": [  # internal attacker (Kali)
        {"timestamp": "2025-04-10T01:58:22Z", "event": "Nmap SYN scan",
         "src_ip": "192.168.56.10", "ports_scanned": 1024, "rule_id": "40111"},
        {"timestamp": "2025-04-10T03:04:58Z", "event": "SSH login success",
         "src_ip": "192.168.56.10", "user": "testuser", "rule_id": "5715"},
        {"timestamp": "2025-04-10T03:05:11Z", "event": "Sudo command: /bin/bash",
         "src_ip": "192.168.56.10", "user": "testuser", "rule_id": "5402"},
    ],

    "203.0.113.42": [  # web attacker
        {"timestamp": "2025-04-10T14:20:01Z",
         "event": "HTTP GET /?id=1 UNION SELECT",
         "src_ip": "203.0.113.42", "status": 500, "rule_id": "31103"},
        {"timestamp": "2025-04-10T14:21:15Z",
         "event": "HTTP GET /?id=1' OR '1'='1",
         "src_ip": "203.0.113.42", "status": 200, "rule_id": "31103"},
        {"timestamp": "2025-04-10T14:22:33Z",
         "event": "HTTP GET /?id=1; DROP TABLE users--",
         "src_ip": "203.0.113.42", "status": 200, "rule_id": "31103"},
    ],

    "192.168.1.10": [],  # normal user — no suspicious context
}

def get_context_logs(ip: str, minutes: int = 15) -> list:
    """Return mock context logs for a given IP."""
    return CONTEXT_LOGS.get(ip, [])
