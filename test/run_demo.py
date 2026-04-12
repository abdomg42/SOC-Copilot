# tests/phase4/run_demo.py
"""
Run this to see the agent in action on all 5 scenarios.
Usage: python -m tests.phase4.run_demo
    python -m tests.phase4.run_demo brute_force_ssh
"""
import sys, json, time
from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from mock_alerts import get_alert, ALERTS
from mock_elastic import get_context_logs

def print_report(report: dict):
    SEV_COLOR = {
        "critical": "\033[91m",  # red
        "high":     "\033[93m",  # yellow
        "medium":   "\033[94m",  # blue
        "low":      "\033[92m",  # green
    }
    RESET = "\033[0m"
    sev   = report.get("severity", "unknown")
    color = SEV_COLOR.get(sev, "")

    print(f"\n{'═'*60}")
    print(f"  {color}SEVERITY: {sev.upper()}{RESET}")
    print(f"  TITLE: {report.get('title', 'N/A')}")
    print(f"  MITRE: {report.get('mitre_technique_id')} — "
          f"{report.get('mitre_technique_name')}")
    print(f"  TACTIC: {report.get('mitre_tactic')}")
    print(f"  CONFIDENCE: {report.get('confidence', 'N/A')}")
    print(f"\n  EXPLANATION:\n  {report.get('explanation', 'N/A')}")
    print(f"\n  REMEDIATION STEPS:")
    for i, step in enumerate(report.get("remediation_steps", []), 1):
        if isinstance(step, dict):
            prio   = step.get("priority", "")
            action = step.get("action", step)
            print(f"    {i}. [{prio.upper()}] {action}")
        else:
            print(f"    {i}. {step}")
    iocs = report.get("iocs", [])
    if iocs:
        print(f"\n  IOCs: {json.dumps(iocs, indent=4)}")
    print(f"{'═'*60}\n")


def run_scenario(name: str):
    from agent.graph import soc_agent

    alert = get_alert(name)
    print(f"\n{'─'*60}")
    print(f"  SCENARIO: {name.upper().replace('_', ' ')}")
    print(f"  src_ip: {alert['src_ip']}  |  rule_level: {alert['rule_level']}")
    print(f"  description: {alert['rule_description']}")
    print(f"  ml_severity: {alert['ml_severity']}  |  "
          f"ml_score: {alert['ml_anomaly_score']}")
    print(f"{'─'*60}")
    print("  Running agent", end="", flush=True)

    start = time.time()
    state = {
        "alert": alert, "context_logs": [], "rag_results": [],
        "messages": [], "tool_calls": [], "report": None, "error": None,
    }
    result = soc_agent.invoke(state)
    elapsed = round(time.time() - start, 1)

    print(f" done in {elapsed}s")
    print_report(result.get("report") or {"error": "No report generated"})


def main():
    scenarios = sys.argv[1:] if len(sys.argv) > 1 else list(ALERTS.keys())

    # Apply mocks
    with patch("agent.nodes.get_retriever") as mock_ret, \
         patch("agent.tools.search_elastic_logs") as mock_es:

        mock_doc = MagicMock()
        mock_doc.page_content = (
            "T1110.001 Password Guessing — block IP, disable password auth, "
            "enable fail2ban. T1046 Network Scanning — restrict open ports. "
            "T1548 Privilege Escalation — audit sudoers, enable auditd."
        )
        mock_ret.return_value.invoke.return_value = [mock_doc]
        mock_es.invoke.side_effect = lambda a: get_context_logs(a.get("ip",""))

        print("\n" + "█"*60)
        print("  SOC COPILOT — Phase 4 Standalone Demo")
        print("█"*60)

        for scenario in scenarios:
            run_scenario(scenario)
            if len(scenarios) > 1:
                time.sleep(1)

        print("\nAll scenarios completed.")


if __name__ == "__main__":
    main()