from typing import TypedDict, List, Optional, Any

class AgentState(TypedDict):
    # Input
    alert: dict          # raw Wazuh alert (enriched by ML)

    # Enrichment
    context_logs: List[dict]    # related Elasticsearch logs
    rag_results: List[str]     # relevant passages from vector store

    # LLM conversation
    messages: List[Any]     # LangChain message history
    tool_calls: Optional[List]# pending tool calls from LLM

    # Final output
    report: Optional[dict]# structured JSON report
    error: Optional[str] # error message if something failed
