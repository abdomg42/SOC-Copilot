import argparse
import json
from datetime import datetime, timedelta

from opensearchpy import OpenSearch


def create_client():
    return OpenSearch(
        hosts=[{'host': '100.97.198.85', 'port': 9200}],
        http_auth=('admin', 'ea?JTvU2PfxVFTsZ?.hy2..t?Q3FWItz'),
        use_ssl=True,
        verify_certs=False,
        ssl_show_warn=False
    )


def get_recent_logs(client, minutes=15, limit=100):
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat() + "Z"

    query = {
        "_source": ["@timestamp", "src_ip", "dst_ip", "protocol"],
        "size": limit,
        "query": {
            "range": {
                "@timestamp": {
                    "gte": since,
                    "lte": "now"
                }
            }
        }
    }

    response = client.search(index="wazuh-alerts-*", body=query)
    return response["hits"]["hits"]


def get_logs_by_ip(client, ip, minutes=15, limit=100):
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat() + "Z"

    query = {
        "_source": ["@timestamp", "src_ip", "dst_ip", "protocol"],
        "size": limit,
        "query": {
            "bool": {
                "must": [
                    {"match": {"src_ip": ip}},
                    {
                        "range": {
                            "@timestamp": {
                                "gte": since,
                                "lte": "now"
                            }
                        }
                    }
                ]
            }
        }
    }

    response = client.search(index="logstash_rot--*", body=query)
    return response["hits"]["hits"]


def main():
    parser = argparse.ArgumentParser(description="Fetch logs from OpenSearch")

    parser.add_argument(
        "--mode",
        choices=["recent", "by-ip"],
        default="recent",
        help="Fetch recent logs or filter by source IP"
    )

    parser.add_argument("--ip", help="Source IP (required for by-ip mode)")
    parser.add_argument("--minutes", type=int, default=15)
    parser.add_argument("--limit", type=int, default=100)

    args = parser.parse_args()

    if args.mode == "by-ip" and not args.ip:
        parser.error("--ip is required when using --mode by-ip")

    client = create_client()

    if args.mode == "recent":
        logs = get_recent_logs(client, args.minutes, args.limit)
    else:
        logs = get_logs_by_ip(client, args.ip, args.minutes, args.limit)

    print(json.dumps(logs, indent=2))


if __name__ == "__main__":
    main()