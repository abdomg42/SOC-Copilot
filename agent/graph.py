# agent/graph.py
from langgraph.graph import StateGraph, END
from .state import AgentState
from .nodes import (
    receive_alert, enrich_context, rag_lookup,
    reason, call_tool, generate_report
)

def should_call_tool(state: AgentState) -> str:
    tc = state.get("tool_calls", [])
    return "call_tool" if tc and len(tc) > 0 else "generate_report"

def build_graph():
    g = StateGraph(AgentState)

    g.add_node("receive_alert",   receive_alert)
    g.add_node("enrich_context",  enrich_context)
    # g.add_node("rag_lookup",      rag_lookup)
    g.add_node("reason",          reason)
    g.add_node("call_tool",       call_tool)
    g.add_node("generate_report", generate_report)

    g.set_entry_point("receive_alert")
    g.add_edge("receive_alert",  "enrich_context")
    g.add_edge("enrich_context", "reason") #rag_lookup
    # g.add_edge("rag_lookup",     "reason")
    g.add_conditional_edges(
        "reason", should_call_tool,
        {"call_tool": "call_tool", "generate_report": "generate_report"}
    )
    g.add_edge("call_tool",       "reason")  # loop back after tool
    g.add_edge("generate_report", END)

    return g.compile()

soc_agent = build_graph()