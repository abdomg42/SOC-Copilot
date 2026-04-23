# test_full_pipeline.py
from agent.graph import soc_agent
import json
from datetime import datetime
from pathlib import Path

# windows_alert = {
#     "alert_id": "1775858038.781129",
#     "timestamp": "2026-04-10T22:53:58.123+0100",

#     "rule_id": "92213",
#     "rule_level": 15,
#     "rule_description": "Executable file dropped in folder commonly used by malware",

#     "agent_id": "001",
#     "agent_name": "windows_agent1",
#     "src_ip": "10.0.2.15",

#     "user": "mossaabReverse",
#     "os_type": "windows",

#     "host": "DESKTOP-80FLS88",

#     "mitre_ids": ["T1105"],
#     "mitre_tactic": "Command and Control",
#     "mitre_technique": "Ingress Tool Transfer",

#     "process_image": "cleanmgr.exe",
#     "process_id": "6436",

#     "target_file": "DismHost.exe",
#     "target_path": "C:\\Users\\MOSSAA~1\\AppData\\Local\\Temp\\A5615CAD-FA6C-4F21-9F37-000205B32E04\\DismHost.exe",

#     "file_creation_time": "2026-04-10 21:53:57.192",

#     "mail_alert": True,
#     "groups": ["sysmon", "sysmon_eid11_detections", "windows"]
# }
# Utilise exactement ton vrai log Windows Sysmon
alert = {
    "alert_id":           "1775858038.781129",
    "timestamp":          "2026-04-10T22:53:58.123+0100",
    "rule_id":            "92213",
    "rule_level":         15,
    "rule_description":   "Executable file dropped in folder commonly used by malware",
    "agent_id":           "001",
    "agent_name":         "windows_agent1",
    "src_ip":             "10.0.2.15",
    "user":               "mossaabReverse",
    "os_type":            "windows",
    "host":               "DESKTOP-80FLS88",
    "mitre_ids":          ["T1105"],
    "mitre_tactic":       "Command and Control",
    "mitre_technique":    "Ingress Tool Transfer",
    "ml_severity":        "critical",
    "ml_attack_category": "malware_dropper",
    "ml_anomaly_score":   0.96,
    "process_image":      "cleanmgr.exe",
    "process_id":         "6436",
    "target_file":        "DismHost.exe",
    "target_path":        "C:\\Users\\MOSSAA~1\\AppData\\Local\\Temp\\A5615CAD-FA6C-4F21-9F37-000205B32E04\\DismHost.exe",
    "file_creation_time": "2026-04-10 21:53:57.192",
    "mail_alert":         True,
    "groups":             ["sysmon", "sysmon_eid11_detections", "windows"],
}
  
initial_state = {
    "alert":        alert,
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


# def _pdf_escape(text: str) -> str:
#     return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


# def _build_report_lines(report: dict) -> list[str]:
#     lines = []
#     lines.append("SOC COPILOT INCIDENT REPORT")
#     lines.append("")
#     lines.append(f"Title: {report.get('title', 'N/A')}")
#     lines.append(f"Severity: {report.get('severity', 'N/A')}")
#     lines.append(f"MITRE Technique ID: {report.get('mitre_technique_id', 'N/A')}")
#     lines.append(f"MITRE Technique Name: {report.get('mitre_technique_name', 'N/A')}")
#     lines.append(f"MITRE Tactic: {report.get('mitre_tactic', 'N/A')}")
#     lines.append(f"Confidence: {report.get('confidence', 'N/A')}")
#     lines.append("")
#     lines.append("Explanation:")
#     lines.append(str(report.get("explanation", "N/A")))
#     lines.append("")

#     lines.append("Attack Sequence:")
#     for idx, step in enumerate(report.get("attack_sequence", []), start=1):
#         lines.append(f"{idx}. {step}")
#     lines.append("")

#     lines.append("IoCs:")
#     for ioc in report.get("iocs", []):
#         lines.append(
#             f"- {ioc.get('type', 'unknown')}: {ioc.get('value', 'N/A')}"
#             f" | context: {ioc.get('context', '')}"
#         )
#     lines.append("")

#     lines.append("Remediation Steps:")
#     for step in report.get("remediation_steps", []):
#         lines.append(
#             f"- [{step.get('priority', 'unknown')}] {step.get('action', '')}"
#         )

#     return lines


# def write_simple_pdf(lines: list[str], output_path: Path) -> None:
#     max_lines_per_page = 48
#     pages = [lines[i:i + max_lines_per_page] for i in range(0, len(lines), max_lines_per_page)]

#     objects = []

#     def add_object(content: str) -> int:
#         objects.append(content)
#         return len(objects)

#     font_id = add_object("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

#     page_ids = []
#     content_ids = []

#     for page_lines in pages:
#         y = 780
#         text_cmds = ["BT", "/F1 10 Tf", "50 780 Td", "14 TL"]
#         first = True
#         for line in page_lines:
#             clean = _pdf_escape(str(line))
#             if first:
#                 text_cmds.append(f"({clean}) Tj")
#                 first = False
#             else:
#                 text_cmds.append("T*")
#                 text_cmds.append(f"({clean}) Tj")
#             y -= 14
#             if y < 40:
#                 break
#         text_cmds.append("ET")
#         stream = "\n".join(text_cmds)
#         content_obj = add_object(
#             f"<< /Length {len(stream.encode('latin-1', errors='replace'))} >>\nstream\n{stream}\nendstream"
#         )
#         content_ids.append(content_obj)
#         page_id_placeholder = add_object("")
#         page_ids.append(page_id_placeholder)

#     kids = " ".join(f"{pid} 0 R" for pid in page_ids)
#     pages_id = add_object(f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>")

#     for i, page_id in enumerate(page_ids):
#         objects[page_id - 1] = (
#             "<< /Type /Page "
#             f"/Parent {pages_id} 0 R "
#             "/MediaBox [0 0 595 842] "
#             f"/Resources << /Font << /F1 {font_id} 0 R >> >> "
#             f"/Contents {content_ids[i]} 0 R >>"
#         )

#     catalog_id = add_object(f"<< /Type /Catalog /Pages {pages_id} 0 R >>")

#     pdf = ["%PDF-1.4\n"]
#     offsets = [0]
#     for idx, obj in enumerate(objects, start=1):
#         offsets.append(sum(len(part.encode("latin-1", errors="replace")) for part in pdf))
#         pdf.append(f"{idx} 0 obj\n{obj}\nendobj\n")

#     xref_start = sum(len(part.encode("latin-1", errors="replace")) for part in pdf)
#     pdf.append(f"xref\n0 {len(objects) + 1}\n")
#     pdf.append("0000000000 65535 f \n")
#     for off in offsets[1:]:
#         pdf.append(f"{off:010d} 00000 n \n")

#     pdf.append(
#         "trailer\n"
#         f"<< /Size {len(objects) + 1} /Root {catalog_id} 0 R >>\n"
#         f"startxref\n{xref_start}\n%%EOF\n"
#     )

#     output_path.write_bytes("".join(pdf).encode("latin-1", errors="replace"))


# report_dir = Path("report")
# report_dir.mkdir(parents=True, exist_ok=True)
# report_path = report_dir / f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

# write_simple_pdf(_build_report_lines(result["report"]), report_path)
# print(f"\nPDF report written to: {report_path.resolve()}")

# Verify Neo4j was updated
from agent.neo4j_ingest.connection import get_driver
with get_driver().session() as s:
    ip = s.run(
        "MATCH (ip:IP {address:'10.0.2.15'}) RETURN ip.risk_score, ip.attack_count"
    ).single()
    print(f"\nNeo4j after analysis: {dict(ip) if ip else 'IP not found'}")