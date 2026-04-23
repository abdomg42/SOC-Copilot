import json
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from .state   import AgentState
from .tools   import get_tools, execute_tool
from .prompts import SYSTEM_PROMPT, REPORT_FORMAT_PROMPT

LLM            = ChatOllama(model="mistral:7b", temperature=0)
LLM_WITH_TOOLS = LLM.bind_tools(get_tools())


# ── Node 1 : validate alert ──────────────────────────────────────────────────
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


# ── Node 2 : enrich context — Neo4j + ChromaDB + Wazuh ──────────────────────
def enrich_context(state: AgentState) -> AgentState:
    alert     = state["alert"]
    ip        = alert.get("src_ip", "")
    desc      = alert.get("rule_description", "")
    mitre_ids = alert.get("mitre_ids", [])

    # ── A. Neo4j : IP history + D3FEND defenses + Engage activities ──────────
    graph_facts = {}
    try:
        from agent.neo4j_ingest.connection import get_driver
        with get_driver().session() as s:

            # IP risk profile
            ip_summary = s.run("""
                MATCH (ip:IP {address: $ip})
                RETURN ip.risk_score   AS risk,
                       ip.attack_count AS count,
                       ip.first_seen   AS first
            """, ip=ip).single()

            past_techniques = s.run("""
                MATCH (ip:IP {address: $ip})-[:TRIGGERED]->(:Alert)
                      -[:USES]->(t:MitreTechnique)
                RETURN DISTINCT t.tid AS tid, t.name AS name
            """, ip=ip).data()

            kill_chain = s.run("""
                MATCH path=(ip:IP {address: $ip})-[:TRIGGERED]
                      ->(a1:Alert)-[:FOLLOWED_BY*1..4]->(a2:Alert)
                RETURN [n IN nodes(path) WHERE n:Alert |
                        {desc:n.description, sev:n.severity}] AS chain
                ORDER BY length(path) DESC LIMIT 1
            """, ip=ip).single()

            # D3FEND defenses for detected MITRE techniques
            d3fend = []
            if mitre_ids:
                d3fend = s.run("""
                    UNWIND $ids AS tid
                    MATCH (d:D3FEND)-[:DEFENDS_AGAINST]
                          ->(t:MitreTechnique {tid: tid})
                    RETURN DISTINCT d.name AS name,
                                   d.tactic AS tactic,
                                   d.definition AS definition
                    LIMIT 6
                """, ids=mitre_ids).data()

            # Engage counter-activities
            engage = []
            if mitre_ids:
                engage = s.run("""
                    UNWIND $ids AS tid
                    MATCH (e:EngageActivity)-[r:COUNTERS]
                          ->(t:MitreTechnique {tid: tid})
                    RETURN DISTINCT e.name AS name,
                                   e.approach AS approach,
                                   r.why AS why
                    LIMIT 4
                """, ids=mitre_ids).data()

            # MITRE technique details from graph
            mitre_ctx = {}
            if mitre_ids:
                rec = s.run("""
                    MATCH (t:MitreTechnique {tid: $tid})
                    OPTIONAL MATCH (t)-[:BELONGS_TO]->(tac:MitreTactic)
                    OPTIONAL MATCH (t)-[:SUB_TECHNIQUE_OF]->(parent)
                    RETURN t.name AS name, t.desc AS desc,
                           t.platforms AS platforms,
                           collect(DISTINCT tac.name) AS tactics,
                           parent.tid AS parent_tid
                    LIMIT 1
                """, tid=mitre_ids[0]).single()
                if rec:
                    mitre_ctx = dict(rec)

        graph_facts = {
            "ip_known":        bool(ip_summary and ip_summary["count"] > 0),
            "risk_score":      float(ip_summary["risk"] or 0) if ip_summary else 0.0,
            "attack_count":    ip_summary["count"] if ip_summary else 0,
            "past_techniques": past_techniques,
            "kill_chain":      kill_chain["chain"] if kill_chain else [],
            "d3fend":          d3fend,
            "engage":          engage,
            "mitre_ctx":       mitre_ctx,
        }
    except Exception as e:
        print(f"[Neo4j] enrich_context warning: {e}")

    # ── B. ChromaDB : semantic passages ──────────────────────────────────────
    rag_passages = []
    try:
        from langchain_community.vectorstores import Chroma
        from langchain_community.embeddings import HuggingFaceEmbeddings

        emb = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={"device": "cpu"}
        )
        vs  = Chroma(
            persist_directory="../data/chroma_db",
            collection_name="soc_knowledge",
            embedding_function=emb
        )
        query = f"{desc} {' '.join(mitre_ids)} {alert.get('ml_attack_category','')}"
        docs  = vs.similarity_search(query, k=4)
        rag_passages = [
            {"text": d.page_content, "source": d.metadata.get("source", "?")}
            for d in docs
        ]
    except Exception as e:
        print(f"[ChromaDB] enrich_context warning: {e}")

    # ── C. Wazuh : recent context logs from same IP ───────────────────────────
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
        from langchain_community.vectorstores import Chroma
        from langchain_community.embeddings import HuggingFaceEmbeddings
        emb = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
            model_kwargs={"device": "cpu"}
        )
        vs   = Chroma(
            persist_directory="../data/chroma_db",
            collection_name="soc_knowledge",
            embedding_function=emb
        )
        # Search specifically for runbook
        runbook_docs = vs.similarity_search(
            f"{category} runbook response procedure", k=2
        )
        extra = [
            {"text": d.page_content, "source": d.metadata.get("source", "?")}
            for d in runbook_docs
        ]
        # Merge with existing passages
        existing = state.get("rag_passages", [])
        return {"rag_passages": existing + extra}
    except Exception:
        return {}


# ── Node 4 : reason — build unified prompt + LLM call ───────────────────────
def reason(state: AgentState) -> AgentState:
    import os
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
                steps = " → ".join(c.get("desc","?")[:30] for c in chain)
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