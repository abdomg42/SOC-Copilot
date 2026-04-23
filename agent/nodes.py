import json
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from .state   import AgentState
from .tools   import get_tools, execute_tool
from .knowledge_base import get_retriever
from .graph_retriever import retrieve_all
from .prompts import SYSTEM_PROMPT, REPORT_FORMAT_PROMPT

LLM            = ChatOllama(model="mistral:7b", temperature=0)
LLM_WITH_TOOLS = LLM.bind_tools(get_tools())


# Node 1 : validate alert
def receive_alert(state: AgentState) -> AgentState:
    alert = state["alert"]
    # Ensure required fields
    for f in ["rule_description", "src_ip", "timestamp", "rule_level"]:
        if f not in alert:
            alert[f] = "unknown"
    # Infer severity from rule_level if ML not available
    if "ml_severity" not in alert:
        lvl = int(alert.get("rule_level", 0))
        alert["ml_severity"] = (
            "critical" if lvl >= 14 else
            "high"     if lvl >= 10 else
            "medium"   if lvl >= 6  else "low"
        )
    return {"alert": alert}


# Node 2 : enrich context — (Neo4j + ChromaDB + Wazuh)
def enrich_context(state: AgentState) -> AgentState:
    alert = state["alert"]

    graph_facts = {}
    rag_passages = []
    try:
        ctx = retrieve_all(alert)

        ip_context = ctx.get("ip_context", {})
        d3fend_raw = ctx.get("d3fend", [])
        mitre_ctx = ctx.get("mitre_ctx", {})
        rag_docs = ctx.get("rag_docs", [])

        # Normalize D3FEND fields to match the existing reason() formatter.
        d3fend = [
            {
                "name": d.get("defense", "unknown"),
                "tactic": d.get("attack_technique", "unknown"),
                "definition": d.get("definition", ""),
            }
            for d in d3fend_raw
        ]

        graph_facts = {
            "ip_known": bool(ip_context.get("known", False)),
            "risk_score": float(ip_context.get("risk_score", 0.0) or 0.0),
            "attack_count": ip_context.get("attack_count", 0),
            "past_techniques": ip_context.get("techniques", []),
            "kill_chain": ip_context.get("kill_chain", []),
            "d3fend": d3fend,
            "engage": [],
            "mitre_ctx": mitre_ctx,
        }

        rag_passages = [
            {"text": d.get("text", ""), "source": d.get("source", "-")}
            for d in rag_docs
        ]
    except Exception as e:
        print(f"[Retriever] enrich_context warning: {e}")

    # Wazuh recent context logs from same IP 
    wazuh_logs = []
    # try:
    #     from agent.tools import _get_token
    #     import requests
    #     headers = {"Authorization": f"Bearer {_get_token()}"}
    #     r = requests.get(
    #         f"https://{os.getenv('WAZUH_HOST','192.168.56.30')}:{os.getenv('WAZUH_PORT','55000')}/alerts",
    #         headers=headers,
    #         params={"limit": 20, "sort": "-timestamp",
    #                 "q": f"data.srcip={ip}"},
    #         verify=False, timeout=15
    #     )
    #     if r.status_code == 200:
    #         items = r.json().get("data", {}).get("affected_items", [])
    #         wazuh_logs = [
    #             {
    #                 "timestamp":   a.get("timestamp"),
    #                 "description": a.get("rule", {}).get("description", ""),
    #                 "level":       a.get("rule", {}).get("level"),
    #             }
    #             for a in items[:10]
    #         ]
    # except Exception as e:
    #     print(f"[Wazuh] enrich_context warning: {e}")

    return {
        "graph_facts":  graph_facts,
        "rag_passages": rag_passages,
        "wazuh_logs":   wazuh_logs,
    }


# ── Node 3 : RAG lookup (additional targeted search) ────────────────────────
def rag_lookup(state: AgentState) -> AgentState:
    """
    Additional targeted RAG search specifically for the runbook
    and D3FEND content related to this alert's category.
    """
    alert    = state["alert"]
    category = alert.get("ml_attack_category", "")
    if not category:
        return {}  # nothing to add

    try:
        retriever = get_retriever()
        # Search specifically for runbook
        runbook_docs = retriever.invoke(f"{category} runbook response procedure")[:2]
        extra = [
            {"text": d.page_content, "source": d.metadata.get("source", "-")}
            for d in runbook_docs
        ]
        # Merge with existing passages
        existing = state.get("rag_passages", [])
        return {"rag_passages": existing + extra}
    except Exception:
        return {}


# ── Node 4 : reason — build unified prompt + LLM call
def reason(state: AgentState) -> AgentState:
    alert     = state["alert"]
    graph     = state.get("graph_facts",  {})
    rag       = state.get("rag_passages", [])
    wazuh_log = state.get("wazuh_logs",   [])
    messages  = state.get("messages",     [])

    if not messages:

        # Format graph facts section
        if graph.get("ip_known"):
            techs  = ", ".join(t["tid"] for t in graph.get("past_techniques", []))
            chain  = graph.get("kill_chain", [])
            ip_section = (
                f"KNOWN ATTACKER — risk={graph['risk_score']:.2f}, "
                f"attacks={graph['attack_count']}, past techniques: {techs}"
            )
            if chain:
                steps = " → ".join(c.get("desc","-")[:30] for c in chain)
                ip_section += f"\n  KILL CHAIN DETECTED: {steps}"
        else:
            ip_section = "First time this IP is seen in our environment."

        # Format MITRE context
        mc = graph.get("mitre_ctx", {})
        mitre_section = ""
        if mc.get("name"):
            mitre_section = (
                f"Technique: {mc['name']} — "
                f"tactics: {', '.join(mc.get('tactics', []))}\n"
                f"Platforms: {', '.join(mc.get('platforms', []))}\n"
                f"{mc.get('desc','')[:200]}"
            )
            if mc.get("parent_tid"):
                mitre_section += f"\nParent: {mc['parent_tid']}"

        # Format D3FEND defenses
        d3fend_section = ""
        if graph.get("d3fend"):
            lines = [f"  - {d['name']} [{d['tactic']}]"
                     for d in graph["d3fend"]]
            d3fend_section = "D3FEND defenses available:\n" + "\n".join(lines)

        # Format Engage activities
        engage_section = ""
        if graph.get("engage"):
            lines = [f"  - {e['name']} [{e['approach']}]: {e.get('why','')[:80]}"
                     for e in graph["engage"]]
            engage_section = "Engage counter-activities:\n" + "\n".join(lines)

        # Format RAG passages grouped by source
        rag_by_source = {}
        for p in rag:
            src = p.get("source", "unknown").upper()
            rag_by_source.setdefault(src, []).append(p["text"][:250])

        rag_section = ""
        for src, texts in rag_by_source.items():
            rag_section += f"[{src}]\n"
            for t in texts[:2]:
                rag_section += f"  {t}\n"

        human_content = f"""
=== SECURITY ALERT ===
Description : {alert.get('rule_description')}
Source IP   : {alert.get('src_ip')}
Target host : {alert.get('agent_name', 'unknown')}
Timestamp   : {alert.get('timestamp')}
Rule level  : {alert.get('rule_level')}
MITRE IDs   : {alert.get('mitre_ids', [])}
OS type     : {alert.get('os_type', 'unknown')}
ML severity : {alert.get('ml_severity', 'unknown')}
ML category : {alert.get('ml_attack_category', 'unknown')}

=== IP HISTORY (Neo4j attack graph) ===
{ip_section}

=== MITRE TECHNIQUE (Neo4j knowledge graph) ===
{mitre_section or 'Not found in graph'}

=== WAZUH CONTEXT LOGS (last 15 min from same IP) ===
{json.dumps(wazuh_log, indent=2) if wazuh_log else 'No recent logs from this IP'}

=== KNOWLEDGE BASE — RAG (ChromaDB) ===
{rag_section or 'No relevant passages found'}

=== D3FEND + ENGAGE CONTEXT ===
{d3fend_section}
{engage_section}

Analyze this incident. Use tools if you need more information.
You have access to:
  - query_wazuh_logs(ip, minutes)     → recent alerts from Wazuh
  - get_ip_risk_from_graph(ip)        → full IP history from Neo4j
  - get_user_events(username)         → user activity from Wazuh
"""
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=human_content),
        ]

    response = LLM_WITH_TOOLS.invoke(messages)
    messages.append(response)
    return {"messages": messages, "tool_calls": response.tool_calls}


# ── Node 5 : call_tool ───────────────────────────────────────────────────────
def call_tool(state: AgentState) -> AgentState:
    messages   = list(state["messages"])
    tool_calls = state.get("tool_calls", [])

    for tc in tool_calls:
        result = execute_tool(tc["name"], tc["args"])
        messages.append(ToolMessage(
            content=str(result),
            tool_call_id=tc["id"]
        ))
    return {"messages": messages, "tool_calls": []}


# ── Node 6 : generate_report — JSON + ingest into Neo4j + PDF export ────────
def generate_report(state: AgentState) -> AgentState:
    import re
    from pathlib import Path
    from datetime import datetime
    messages = list(state["messages"])
    
    alert = state.get("alert", {})
    logs = state.get("wazuh_logs", [])
    graph = state.get("graph_facts", {})

    # ─────────────────────────────
    # 2. Build unified input context
    # ─────────────────────────────

    input_payload = {
        "alert": alert,
        "related_logs": logs,
        "graph_facts": graph
    }

    input_str = json.dumps(input_payload, indent=2)

    # ─────────────────────────────
    # 3. Inject into prompt
    # ─────────────────────────────

    full_prompt = f"""
{REPORT_FORMAT_PROMPT}

--------------------
INPUT DATA (DO NOT IGNORE):
{input_str}
--------------------
"""
    messages = list(state["messages"])
    messages.append(HumanMessage(content=full_prompt))

    response = LLM.invoke(messages)
    raw = response.content

    # Parse JSON — handle markdown code blocks
    match = re.search(r'\{[\s\S]*\}', raw)
    try:
        report = json.loads(match.group()) if match else {"raw": raw}
    except json.JSONDecodeError:
        report = {"raw": raw, "parse_error": True}

    # Ingest alert + report into Neo4j (grows the attack graph)
    try:
        from agent.neo4j_ingest.runtime_alerts import ingest_alert
        ingest_alert(state["alert"], report)
    except Exception as e:
        print(f"[Neo4j] ingest_alert warning: {e}")

    # Generate professional PDF report
    try:
        from agent.report_generator import generate_incident_report
        report_dir = Path(__file__).parent.parent / "report"
        report_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = report_dir / f"incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generate_incident_report(report, pdf_path)
        print(f"[PDF] Report generated: {pdf_path.resolve()}")
        report["pdf_path"] = str(pdf_path)
    except Exception as e:
        print(f"[PDF] Generation warning: {e}")

    state["report"] = report
    return state