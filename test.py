# test_full_pipeline.py
from agent.graph import soc_agent
import json

# Utilise exactement ton vrai log Windows Sysmon
windows_alert = {
    "alert_id":           "1775859573.5194324",
    "timestamp":          "2026-04-10T23:19:33.588+0100",
    "rule_id":            "92200",
    "rule_level":         6,
    "rule_description":   "Scripting file created under Windows Temp or User folder",
    "agent_id":           "001",
    "agent_name":         "windows_agent1",
    "src_ip":             "10.0.2.15",
    "user":               "mossaabReverse",
    "os_type":            "windows",
    "mitre_ids":          ["T1059", "T1105"],
    "ml_severity":        "medium",
    "ml_attack_category": "script_execution",
    "ml_anomaly_score":   0.72,
    "process_image":      "SDXHelper.exe",
    "target_file":        "excel-copilot-strings.js",
}

initial_state = {
    "alert":        windows_alert,
    "graph_facts":  {},
    "rag_passages": [],
    "wazuh_logs":   [],
    "messages":     [],
    "tool_calls":   [],
    "report":       None,
    "error":        None,
}

print("Running agent on Windows Sysmon log...")
result = soc_agent.invoke(initial_state)
print(json.dumps(result["report"], indent=2, ensure_ascii=False))

# Verify Neo4j was updated
from agent.graph_db import get_driver
with get_driver().session() as s:
    ip = s.run(
        "MATCH (ip:IP {address:'10.0.2.15'}) RETURN ip.risk_score, ip.attack_count"
    ).single()
    print(f"\nNeo4j after analysis: {dict(ip) if ip else 'IP not found'}")