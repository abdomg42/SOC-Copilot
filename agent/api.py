# agent/api.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import time
from langchain_ollama import ChatOllama
from langchain_core.messages import SystemMessage, HumanMessage
from agent.graph import soc_agent
from agent.knowledge_base import warm_up_retriever
from agent.prompts import CHAT_SYSTEM_PROMPT
from agent.graph_retriever import semantic_search, get_ip_context, get_mitre_context
import re


CHAT_LLM = ChatOllama(
    model='mistral:7b',
    temperature=0.2,
    num_predict=1000,
    num_ctx=4096,
    keep_alive='30m',
)


def _is_small_talk(question: str) -> bool:
    text = question.strip().lower()
    if not text:
        return True

    greetings = {
        'hi', 'hey', 'heyy', 'hello', 'hiya', 'yo', 'sup', 'good morning',
        'good afternoon', 'good evening', 'thanks', 'thank you', 'bye', 'ok',
        'okay'
    }
    if text in greetings:
        return True

    compact = text.replace('!', '').replace('?', '').replace('.', '')
    if compact in greetings:
        return True

    return len(text.split()) <= 2 and not any(
        keyword in text for keyword in (
            'alert', 'incident', 'attack', 'malware', 'ioc', 'mitre', 'wazuh',
            'log', 'contain', 'remed', 'phish', 'lateral', 'brute', 'ransom',
            'engagement', 'engage'
        )
    )

app = FastAPI(
    title='SOC Copilot Agent API',
    description='AI-powered security incident analysis',
    version='1.0.0'
)

app.add_middleware(CORSMiddleware,
    allow_origins=['*'], allow_methods=['*'], allow_headers=['*']
)


@app.on_event('startup')
def preload_models() -> None:
    warm_up_retriever()
    # Warm the chat model once so first user message is not cold-started.
    try:
        CHAT_LLM.invoke([
            SystemMessage(content='You are a SOC assistant.'),
            HumanMessage(content='Reply with: ready'),
        ])
    except Exception as e:
        print(f'[startup] chat warmup warning: {e}')

class AlertInput(BaseModel):
    rule_description:    str
    src_ip:              str
    timestamp:           str
    rule_level:          int
    ml_severity:         Optional[str] = None
    ml_attack_category:  Optional[str] = None
    ml_anomaly_score:    Optional[float] = None
    agent_name:          Optional[str] = None
    extra:               dict = Field(default_factory=dict)

class ChatInput(BaseModel):
    question:  str
    history:   List[dict] = Field(default_factory=list)

@app.get('/health')
def health():
    return {'status': 'ok', 'agent': 'SOC Copilot v1.0'}

@app.post('/analyze')
async def analyze_alert(alert: AlertInput):
    start = time.time()
    initial_state = {
        'alert':        alert.model_dump(),
        'graph_facts':  {},
        'rag_passages': [],
        'wazuh_logs':   [],
        'messages':     [],
        'tool_calls':   [],
        'report':       None,
        'error':        None,
    }
    try:
        final_state = soc_agent.invoke(initial_state)
        duration    = round(time.time() - start, 2)
        report      = final_state.get('report')
        if not report:
            raise HTTPException(status_code=500, detail='Agent produced no report')
        return {
            'report':     report,
            'duration_s': duration,
            'alert_id':   alert.extra.get('alert_id', 'unknown'),
        }
    except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

@app.post('/chat')
async def chat(data: ChatInput):
    """Free-form chat with the SOC agent for ad-hoc analysis."""
    start = time.time()

    if _is_small_talk(data.question):
        return {
            'answer': "Hey! What would you like to look into?",
            'latency_s': round(time.time() - start, 2),
        }

    messages = [SystemMessage(content=CHAT_SYSTEM_PROMPT)]
    # Retrieve RAG passages relevant to the question
    try:
        rag_docs = semantic_search(data.question)
    except Exception:
        rag_docs = []

    extra_context_parts = []
    if rag_docs:
        lines = []
        for d in rag_docs[:4]:
            src = d.get('source', '-')
            txt = d.get('text', '')[:400].replace('\n', ' ')
            lines.append(f'[{src}] {txt}')
        extra_context_parts.append('KNOWLEDGE_BASE (Chroma):\n' + '\n'.join(lines))

    # Detect IP addresses in the question and fetch Neo4j context
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", data.question)
    if ip_match:
        ip = ip_match.group(0)
        try:
            ip_ctx = get_ip_context(ip)
            extra_context_parts.append('IP_CONTEXT (Neo4j):\n' + str(ip_ctx))
        except Exception:
            pass

    # Detect MITRE technique IDs (e.g. T1059) and fetch MITRE context
    mitre_match = re.search(r"\bT\d{4}\b", data.question.upper())
    if mitre_match:
        tid = mitre_match.group(0)
        try:
            mitre_ctx = get_mitre_context(tid)
            extra_context_parts.append('MITRE_CONTEXT (Neo4j):\n' + str(mitre_ctx))
        except Exception:
            pass

    if extra_context_parts:
        messages.append(SystemMessage(
            content='Retrieved context (for understanding only, DO NOT answer directly):\n' + '\n\n'.join(extra_context_parts)
        ))
    # Keep a short rolling context to reduce prompt size and response time.
#   for m in data.history[-4:]:
#       role = m.get('role', '')
#       content = m.get('content', '')
#       if role == 'user':
#           messages.append(HumanMessage(content=content))
    if data.history:
        context_text = "\n".join(
            [f"{m['role']}: {m['content']}" for m in data.history[-4:]]
        )

        messages.append(SystemMessage(
            content=f"Conversation context (for understanding only, DO NOT answer it):\n{context_text}"
        ))
    messages.append(HumanMessage(content=data.question))
    response = CHAT_LLM.invoke(messages)
    print(round(time.time() - start, 2))
    return {'answer': response.content, 'latency_s': round(time.time() - start, 2)}

@app.get('/alerts')
async def get_alerts(hours: int = 24, severity: str = 'Toutes'):
    """Fetch recent alerts from OpenSearch/Wazuh for the dashboard."""
    try:
        from input.wazuh_client import create_client, get_recent_logs

        client = create_client()
        logs = get_recent_logs(client, minutes=max(1, hours * 60), limit=100)
        alerts = [entry.get('_source', {}) for entry in logs]

        if severity != 'Toutes':
            alerts = [a for a in alerts if str(a.get('ml_severity', '')).lower() == severity.lower()]

        return {'alerts': alerts}
    except Exception as e:
        return {'alerts': [], 'error': f'OpenSearch/Wazuh not available: {e}'}
