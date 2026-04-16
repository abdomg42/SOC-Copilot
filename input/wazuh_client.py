import argparse
import json
import os
import sys
from datetime import datetime, timedelta

import requests
from dotenv import load_dotenv

load_dotenv()

WAZUH_HOST = os.getenv("WAZUH_HOST", "")
WAZUH_PORT = os.getenv("WAZUH_PORT", "")
WAZUH_USERNAME = os.getenv("WAZUH_USERNAME", "")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
BASE_URL = f"https://{WAZUH_HOST}:{WAZUH_PORT}/api"



def get_token(timeout: int = 10, verify_ssl: bool = False) -> str:
    
    response = requests.post(
        f"{BASE_URL}/security/user/authenticate",
        auth=(WAZUH_USERNAME, WAZUH_PASSWORD),
        verify=verify_ssl,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()["data"]["token"]


def get_recent_alerts(token: str, minutes: int = 15, limit: int = 20, verify_ssl: bool = False):
    headers = {"Authorization": f"Bearer {token}"}
    since = (datetime.utcnow() - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    params = {
        "q": f'alert.timestamp:>="{since}"',
        "sort": "timestamp:desc",
        "limit": limit,
    }
    response = requests.get(
        f"{BASE_URL}/alerts",
        headers=headers,
        params=params,
        verify=verify_ssl,
        timeout=20,
    )
    response.raise_for_status()
    return response.json().get("data", {}).get("alerts", [])


def get_alerts_by_ip(
    token: str,
    ip: str,
    minutes: int = 15,
    limit: int = 100,
    verify_ssl: bool = False,
):
    headers = {"Authorization": f"Bearer {token}"}
    since = (datetime.utcnow() - timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S")
    params = {
        "limit": limit,
        "sort": "timestamp:desc",
        "q": f"alert.srcip:{ip} AND alert.timestamp:>='{since}'",
    }
    response = requests.get(
        f"{BASE_URL}/alerts",
        headers=headers,
        params=params,
        verify=verify_ssl,
        timeout=20,
    )
    response.raise_for_status()
    return response.json().get("data", {}).get("alerts", [])


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch alerts from Wazuh API")
    parser.add_argument(
        "--mode",
        choices=["recent", "by-ip"],
        default="recent",
        help="Fetch recent alerts or alerts filtered by source IP",
    )
    parser.add_argument("--ip", help="Source IP address (required when --mode by-ip)")
    parser.add_argument("--minutes", type=int, default=15, help="Lookback window in minutes")
    parser.add_argument("--limit", type=int, default=20, help="Maximum number of alerts to fetch")
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Enable SSL certificate verification (disabled by default)",
    )
    args = parser.parse_args()

    if args.mode == "by-ip" and not args.ip:
        parser.error("--ip is required when --mode by-ip")

    try:
        token = get_token(verify_ssl=args.verify_ssl)
        if args.mode == "recent":
            alerts = get_recent_alerts(
                token,
                minutes=args.minutes,
                limit=args.limit,
                verify_ssl=args.verify_ssl,
            )
        else:
            alerts = get_alerts_by_ip(
                token,
                args.ip,
                minutes=args.minutes,
                limit=args.limit,
                verify_ssl=args.verify_ssl,
            )

        print(json.dumps(alerts, indent=2))
        return 0
    except requests.RequestException as exc:
        print(f"Wazuh API request failed: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
