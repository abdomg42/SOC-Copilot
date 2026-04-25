import json
from langchain_core.tools import tool
from input.wazuh_client import create_client


def _search_alerts(query: dict, limit: int = 50) -> list[dict]:
    client = create_client()
    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": query,
    }
    response = client.search(index="wazuh-alerts-*", body=body)
    return response.get("hits", {}).get("hits", [])


# ── Tool 1 : query recent alerts from Wazuh by source IP ────────────────────
@tool
def query_wazuh_logs(ip: str, minutes: int = 15) -> str:
    """
    Query Wazuh API directly to get recent security alerts from a specific
    source IP address. Use this when you need context about what this IP
    has been doing recently (scans, login attempts, file activity).

    Args:
        ip:      source IP address to search (e.g. '192.168.56.10')
        minutes: how far back to look (default 15, max 60)

    Returns:
        JSON string with list of recent alerts from that IP.
    """
    try:
        items = _search_alerts({
            "bool": {
                "should": [
                    {"term": {"src_ip": ip}},
                    {"term": {"agent.ip": ip}},
                    {"term": {"data.srcip": ip}},
                    {"term": {"data.win.eventdata.sourceIp": ip}},
                    {"match": {"full_log": ip}},
                ],
                "minimum_should_match": 1,
            }
        })

        # Normalize to useful fields only
        results = []
        for item in items:
            alert = item.get("_source", {})
            rule = alert.get("rule", {})
            results.append({
                "timestamp":   alert.get("timestamp") or alert.get("@timestamp"),
                "rule_id":     str(rule.get("id", "")),
                "rule_level":  rule.get("level"),
                "description": rule.get("description", ""),
                "agent":       alert.get("agent", {}).get("name"),
                "mitre":       rule.get("mitre", {}).get("id", []),
            })

        return json.dumps({
            "ip":     ip,
            "count":  len(results),
            "alerts": results[:20],  # cap at 20 for prompt size
        }, ensure_ascii=False)

    except Exception as e:
        # Graceful fallback — agent continues without this context
        return json.dumps({"ip": ip, "error": str(e), "alerts": []})


# ── Tool 2 : get IP risk context from Neo4j knowledge graph ─────────────────
@tool
def get_ip_risk_from_graph(ip: str) -> str:
    """
    Query the Neo4j attack graph to get the full history and risk profile
    of an IP address. Returns attack count, risk score, past MITRE techniques
    used, hosts targeted, and whether a kill chain is detected.

    Use this to understand if this IP is a known attacker and what it
    has done before in your environment.

    Args:
        ip: source IP address to look up

    Returns:
        JSON string with IP risk profile from the attack graph.
    """
    try:
        from agent.neo4j_ingest.connection import get_driver

        with get_driver().session() as s:
            # Basic risk profile
            summary = s.run("""
                MATCH (ip:IP {address: $ip})
                RETURN ip.risk_score   AS risk_score,
                       ip.attack_count AS attack_count,
                       ip.first_seen   AS first_seen,
                       ip.last_seen    AS last_seen
            """, ip=ip).single()

            if not summary or summary["attack_count"] == 0:
                return json.dumps({
                    "ip": ip, "known": False,
                    "message": "First time this IP is seen in our environment"
                })

            # Past MITRE techniques
            techniques = s.run("""
                MATCH (ip:IP {address: $ip})-[:TRIGGERED]->(:Alert)
                      -[:USES]->(t:MitreTechnique)
                RETURN DISTINCT t.tid AS tid, t.name AS name
            """, ip=ip).data()

            # Hosts targeted
            hosts = s.run("""
                MATCH (ip:IP {address: $ip})-[r:ATTACKED]->(h:Host)
                RETURN h.name AS host, r.count AS times
            """, ip=ip).data()

            # Kill chain detection
            chain = s.run("""
                MATCH path=(ip:IP {address: $ip})-[:TRIGGERED]
                      ->(a1:Alert)-[:FOLLOWED_BY*1..4]->(a2:Alert)
                RETURN [n IN nodes(path) WHERE n:Alert |
                        {desc: n.description, sev: n.severity}] AS chain
                ORDER BY length(path) DESC LIMIT 1
            """, ip=ip).single()

            # D3FEND defenses available for past techniques
            tids = [t["tid"] for t in techniques]
            defenses = []
            if tids:
                defenses = s.run("""
                    UNWIND $tids AS tid
                    MATCH (d:D3FEND)-[:DEFENDS_AGAINST]
                          ->(t:MitreTechnique {tid: tid})
                    RETURN DISTINCT d.name AS defense, d.tactic AS tactic
                    LIMIT 5
                """, tids=tids).data()

        return json.dumps({
            "ip":           ip,
            "known":        True,
            "risk_score":   round(float(summary["risk_score"] or 0), 3),
            "attack_count": summary["attack_count"],
            "first_seen":   summary["first_seen"],
            "last_seen":    summary["last_seen"],
            "techniques_used":  techniques,
            "hosts_targeted":   hosts,
            "kill_chain":       chain["chain"] if chain else [],
            "d3fend_defenses":  defenses,
        }, ensure_ascii=False)

    except Exception as e:
        return json.dumps({"ip": ip, "error": str(e), "known": False})


# ── Tool 3 : get user event history from Wazuh ──────────────────────────────
@tool
def get_user_events(username: str) -> str:
    """
    Query Wazuh to get recent security events involving a specific user
    account. Use this when the alert involves a username (SSH login attempt,
    sudo execution, file access) and you need to understand if this user
    account is behaving normally or suspiciously.

    Args:
        username: the user account name to look up (e.g. 'root', 'testuser')

    Returns:
        JSON string with recent events involving this user.
    """
    try:
        items = _search_alerts({
            "bool": {
                "should": [
                    {"term": {"data.dstuser": username}},
                    {"term": {"data.srcuser": username}},
                    {"term": {"data.win.eventdata.user": username}},
                    {"term": {"data.win.eventdata.targetUserName": username}},
                    {"term": {"data.win.eventdata.subjectUserName": username}},
                    {"match": {"full_log": username}},
                ],
                "minimum_should_match": 1,
            }
        })

        all_items = [item.get("_source", {}) for item in items]

        # Count event types
        failed_logins = sum(
            1 for a in all_items
            if "fail" in a.get("rule", {}).get("description", "").lower()
        )
        sudo_events = sum(
            1 for a in all_items
            if "sudo" in a.get("rule", {}).get("description", "").lower()
        )
        high_severity = sum(
            1 for a in all_items
            if a.get("rule", {}).get("level", 0) >= 10
        )

        recent = []
        for a in all_items[:10]:
            rule = a.get("rule", {})
            recent.append({
                "timestamp":   a.get("timestamp") or a.get("@timestamp"),
                "description": rule.get("description", ""),
                "level":       rule.get("level"),
                "agent":       a.get("agent", {}).get("name"),
            })

        return json.dumps({
            "username":       username,
            "total_events":   len(all_items),
            "failed_logins":  failed_logins,
            "sudo_events":    sudo_events,
            "high_severity":  high_severity,
            "account_exists": len(all_items) > 0,
            "recent_events":  recent,
        }, ensure_ascii=False)

    except Exception as e:
        return json.dumps({
            "username": username,
            "error":    str(e),
            "total_events": 0
        })


def get_tools() -> list:
    return [query_wazuh_logs, get_ip_risk_from_graph, get_user_events]

def execute_tool(name: str, args: dict) -> str:
    tools_map = {t.name: t for t in get_tools()}
    if name in tools_map:
        return str(tools_map[name].invoke(args))
    return f"Unknown tool: {name}"