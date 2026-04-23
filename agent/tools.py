import os, requests, json, time
from functools import lru_cache
from langchain_core.tools import tool
from dotenv import load_dotenv
load_dotenv()

WAZUH_HOST = os.getenv("WAZUH_HOST", "192.168.56.30")
WAZUH_PORT = os.getenv("WAZUH_PORT", "55000")
WAZUH_USER = os.getenv("WAZUH_USER", "admin")
WAZUH_PASS = os.getenv("WAZUH_PASSWORD", "")
BASE_URL   = f"https://{WAZUH_HOST}:{WAZUH_PORT}"

# ── JWT token cache (expires after 14 min, Wazuh gives 15) ──────────────────
_token_cache = {"token": None, "expires_at": 0}

def _get_token() -> str:
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"]:
        return _token_cache["token"]
    r = requests.post(
        f"{BASE_URL}/security/user/authenticate",
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=False, timeout=10
    )
    r.raise_for_status()
    token = r.json()["data"]["token"]
    _token_cache["token"]      = token
    _token_cache["expires_at"] = now + 840  # 14 min
    return token

def _wazuh_get(endpoint: str, params: dict = None) -> dict:
    headers = {"Authorization": f"Bearer {_get_token()}"}
    r = requests.get(
        f"{BASE_URL}{endpoint}",
        headers=headers, params=params,
        verify=False, timeout=20
    )
    if r.status_code == 200:
        return r.json().get("data", {})
    return {}


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
        # Wazuh query syntax: field:value
        data = _wazuh_get("/alerts", params={
            "limit":  50,
            "sort":   "-timestamp",
            "q":      f"data.srcip={ip}",
            "pretty": False,
        })
        items = data.get("affected_items", [])

        # Normalize to useful fields only
        results = []
        for alert in items:
            rule    = alert.get("rule", {})
            results.append({
                "timestamp":   alert.get("timestamp"),
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
        from agent.graph_db import get_driver

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
        # Query by destination user (auth logs)
        data = _wazuh_get("/alerts", params={
            "limit": 30,
            "sort":  "-timestamp",
            "q":     f"data.dstuser={username}",
        })
        items_dst = data.get("affected_items", [])

        # Also query by source user
        data2 = _wazuh_get("/alerts", params={
            "limit": 30,
            "sort":  "-timestamp",
            "q":     f"data.srcuser={username}",
        })
        items_src = data2.get("affected_items", [])

        all_items = items_dst + items_src

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
                "timestamp":   a.get("timestamp"),
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