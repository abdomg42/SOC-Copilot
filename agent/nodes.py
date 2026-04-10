import json, re
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage
from .state import AgentState
from .tools import get_tools, execute_tool
from .prompts import SYSTEM_PROMPT, REPORT_FORMAT_PROMPT
from .knowledge_base import get_retriever

# LLM via Ollama — change model name if needed
LLM = ChatOllama(model='mistral', temperature=0)
LLM_WITH_TOOLS = LLM.bind_tools(get_tools())

# ── Node 1 : validate and normalize the incoming alert ──────────────
def receive_alert(state: AgentState) -> AgentState:
    alert = state['alert']
    # Ensure required fields exist
    for field in ['rule_description','src_ip','timestamp','rule_level']:
        if field not in alert:
            alert[field] = 'unknown'
    # Map ML output if present
    if 'ml_severity' not in alert:
        level = alert.get('rule_level', 0)
        if isinstance(level, int):
            if level >= 14:   alert['ml_severity'] = 'critical'
            elif level >= 10: alert['ml_severity'] = 'high'
            elif level >= 6:  alert['ml_severity'] = 'medium'
            else:             alert['ml_severity'] = 'low'
    return {'alert': alert}

# ── Node 2 : fetch context logs from Elasticsearch ──────────────────
def enrich_context(state: AgentState) -> AgentState:
    alert = state['alert']
    ip    = alert.get('src_ip', 'unknown')
    # Try real Elasticsearch, fall back to mock
    try:
        from ingestion.elastic_client import get_client, search_related
        es   = get_client()
        logs = search_related(es, ip, minutes=15)
    except Exception:
        logs = [  # MOCK — works even without Phase 1 complete
            {'event': f'SSH failed login from {ip}', 'count': 47, 'minutes_ago': 2},
            {'event': f'Port scan from {ip}', 'ports_scanned': 254, 'minutes_ago': 15},
        ]
    return {'context_logs': logs}

# ── Node 3 : semantic search in the knowledge base (RAG) ────────────
def rag_lookup(state: AgentState) -> AgentState:
    alert = state['alert']
    # Build a rich query combining alert description + category
    query = (' '.join(filter(None, [
        alert.get('rule_description', ''),
        alert.get('ml_attack_category', ''),
        alert.get('src_ip', ''),
    ])))
    retriever = get_retriever()
    docs      = retriever.invoke(query)
    passages  = [d.page_content for d in docs]
    return {'rag_results': passages}

# ── Node 4 : LLM reasoning + optional tool calls ────────────────────
def reason(state: AgentState) -> AgentState:
    alert    = state['alert']
    ctx_logs = state.get('context_logs', [])
    rag      = state.get('rag_results', [])
    messages = state.get('messages', [])

    if not messages:
        # First call — build the full initial prompt
        human_content = f"""
SECURITY ALERT:
================
Description : {alert.get('rule_description')}
Source IP   : {alert.get('src_ip')}
Timestamp   : {alert.get('timestamp')}
Rule Level  : {alert.get('rule_level')}
ML Severity : {alert.get('ml_severity', 'unknown')}
ML Category : {alert.get('ml_attack_category', 'unknown')}
ML Score    : {alert.get('ml_anomaly_score', 'N/A')}

CONTEXT LOGS (last 15 min from same IP):
{json.dumps(ctx_logs, indent=2)}

RELEVANT KNOWLEDGE BASE PASSAGES:
{chr(10).join(f'[{i+1}] {p}' for i, p in enumerate(rag))}

Analyze this incident. You may call tools if you need more information.
"""
        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=human_content),
        ]

    response = LLM_WITH_TOOLS.invoke(messages)
    messages.append(response)
    return {'messages': messages, 'tool_calls': response.tool_calls}

# ── Node 5 : execute tool calls requested by the LLM ────────────────
def call_tool(state: AgentState) -> AgentState:
    messages   = state['messages']
    tool_calls = state['tool_calls']
    new_msgs   = list(messages)
    for tc in tool_calls:
        result = execute_tool(tc['name'], tc['args'])
        new_msgs.append(ToolMessage(
            content=str(result),
            tool_call_id=tc['id']
        ))
    return {'messages': new_msgs, 'tool_calls': []}

# ── Node 6 : generate final structured report ────────────────────────
def generate_report(state: AgentState) -> AgentState:
    from langchain_core.messages import HumanMessage
    messages = list(state['messages'])
    messages.append(HumanMessage(content=REPORT_FORMAT_PROMPT))
    response = LLM.invoke(messages)  # No tools here — just JSON output
    raw = response.content
    # Extract JSON from response (handle markdown code blocks)
    match = re.search(r'\{[\s\S]*\}', raw)
    try:
        report = json.loads(match.group()) if match else {'raw_output': raw}
    except json.JSONDecodeError:
        report = {'raw_output': raw, 'parse_error': True}
    return {'report': report}
