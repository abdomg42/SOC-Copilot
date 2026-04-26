# agent/api.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import time
from agent.graph import soc_agent
from agent.knowledge_base import warm_up_retriever

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
    from langchain_ollama import ChatOllama
    from langchain_core.messages import SystemMessage, HumanMessage
    from agent.prompts import SYSTEM_PROMPT
    llm = ChatOllama(model='mistral:7b', temperature=0.3)
    messages = [SystemMessage(content=SYSTEM_PROMPT)]
    for m in data.history[-6:]:  # keep last 6 turns
        if m['role'] == 'user':
            messages.append(HumanMessage(content=m['content']))
    messages.append(HumanMessage(content=data.question))
    response = llm.invoke(messages)
    return {'answer': response.content}

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
