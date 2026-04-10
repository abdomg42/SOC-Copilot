from agent.graph import soc_agent

test_alert = {
    'rule_description': 'Multiple failed SSH logins',
'src_ip': '192.168.56.10',
    'timestamp': '2025-03-22T10:00:00',
    'rule_level': 10,
    'ml_severity': 'high',
    'ml_attack_category': 'brute_force',
    'ml_anomaly_score': 0.91,
}

initial_state = {
    'alert': test_alert,
    'context_logs': [],
    'rag_results': [],
    'messages': [],
    'tool_calls': [],
    'report': None,
    'error': None,
}

print('Running SOC agent...')
result = soc_agent.invoke(initial_state)
print('\n=== REPORT ===')
import json
print(json.dumps(result['report'], indent=2, ensure_ascii=False))
