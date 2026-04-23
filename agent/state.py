# agent/state.py
from typing import TypedDict, List, Optional, Any

class AgentState(TypedDict):
    alert:        dict           # normalized Wazuh alert
    graph_facts:  dict           # Neo4j results (ip history, d3fend, engage)
    rag_passages: List[dict]     # ChromaDB passages [{text, source}]
    wazuh_logs:   List[dict]     # recent Wazuh logs from same IP
    messages:     List[Any]      # LangChain message history
    tool_calls:   Optional[List] # pending tool calls
    report:       Optional[dict] # final JSON report
    error:        Optional[str]