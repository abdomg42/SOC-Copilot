from langgraph.graph import StateGraph, END
from .state import AgentState
from .nodes import (
    receive_alert, enrich_context, rag_lookup,
    reason, call_tool, generate_report
)

def should_call_tool(state: AgentState) -> str:
    """Conditional edge: did the LLM request a tool call?"""
    tool_calls = state.get('tool_calls', [])
    if tool_calls and len(tool_calls) > 0:
        return 'call_tool'
    return 'generate_report'

def build_graph() -> StateGraph:
    g = StateGraph(AgentState)

    # Register all nodes
    g.add_node('receive_alert',   receive_alert)
    g.add_node('enrich_context',  enrich_context)
    g.add_node('rag_lookup',      rag_lookup)
    g.add_node('reason',          reason)
    g.add_node('call_tool',       call_tool)
    g.add_node('generate_report', generate_report)

    # Linear pipeline until reasoning
    g.set_entry_point('receive_alert')
    g.add_edge('receive_alert',  'enrich_context')
    g.add_edge('enrich_context', 'rag_lookup')
    g.add_edge('rag_lookup',     'reason')

    # Conditional: after reasoning, either call tool or generate report
    g.add_conditional_edges(
        'reason',
        should_call_tool,
        {'call_tool': 'call_tool', 'generate_report': 'generate_report'}
    )

    # After tool call, go back to reason (allows multiple tool calls)
    g.add_edge('call_tool', 'reason')

    # Final node
    g.add_edge('generate_report', END)

    return g.compile()

# Global instance — import this in api.py
soc_agent = build_graph()
