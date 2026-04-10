# agent/tools.py
from langchain_core.tools import tool
from typing import List
import requests, os
from dotenv import load_dotenv
load_dotenv()

@tool
def search_elastic_logs(ip: str, minutes: int = 15) -> List[dict]:
    """Search Elasticsearch for all events related to an IP
    in the last N minutes. Use this to get attack context."""
    try:
        from elasticsearch import Elasticsearch
        es = Elasticsearch(
            f"https://{os.getenv('ELASTIC_HOST', '192.168.56.30')}:9200",
            basic_auth=(os.getenv('ELASTIC_USER','admin'),
                        os.getenv('ELASTIC_PASSWORD','admin')),
            verify_certs=False
        )
        result = es.search(index='soc-alerts', query={'bool': {'must': [
            {'term': {'src_ip': ip}},
            {'range': {'timestamp': {'gte': f'now-{minutes}m'}}}
        ]}}, size=20, sort=[{'timestamp': 'desc'}])
        return [h['_source'] for h in result['hits']['hits']]
    except Exception:
        # MOCK fallback if Elasticsearch not available yet
        return [
            {'event': f'Failed SSH login from {ip}', 'count': 47},
            {'event': f'Port scan from {ip}', 'ports': [22, 80, 443]},
        ]

@tool
def check_ip_reputation(ip: str) -> dict:
    """Check the reputation and geolocation of an IP address.
    Returns abuse score, country, and known attacker status."""
    try:
        # Free API, no key needed
        r = requests.get(f'https://ipapi.co/{ip}/json/', timeout=5)
        geo = r.json()
        return {
            'ip': ip,
            'country': geo.get('country_name', 'Unknown'),
            'city': geo.get('city', 'Unknown'),
            'org': geo.get('org', 'Unknown'),
            'is_datacenter': 'hosting' in geo.get('org','').lower(),
        }
    except Exception:
        return {'ip': ip, 'error': 'lookup failed', 'country': 'Unknown'}

@tool
def get_user_login_history(username: str) -> dict:
    """Get the login history and failed attempts for a user.
    Use this when the alert involves a specific user account."""
    # MOCK — replace with real Elasticsearch query on your auth logs
    return {
        'username': username,
        'failed_today': 52,
        'last_success': '2025-03-19T08:00:00',
        'usual_ip': '192.168.1.10',
        'account_exists': True,
    }
def get_tools() -> list:
    return [search_elastic_logs, check_ip_reputation, get_user_login_history]

def execute_tool(name: str, args: dict) -> str:
    tools_map = {t.name: t for t in get_tools()}
    if name in tools_map:
        return str(tools_map[name].invoke(args))
    return f'Unknown tool: {name}'
