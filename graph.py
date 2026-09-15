"""LangGraph wiring for the Bug Hunter pipeline."""
from __future__ import annotations
from langgraph.graph import StateGraph, START, END
from state import BugHunterState
from agents.recon_agent import recon_node
from agents.vuln_agent import vuln_node
from agents.exploit_agent import exploit_node
from agents.report_agent import report_node


def build_graph():
    """Compile the 4-agent state machine."""
    graph = StateGraph(BugHunterState)
    graph.add_node("recon", recon_node)
    graph.add_node("vuln", vuln_node)
    graph.add_node("exploit", exploit_node)
    graph.add_node("report", report_node)

    graph.add_edge(START, "recon")
    graph.add_edge("recon", "vuln")
    graph.add_edge("vuln", "exploit")
    graph.add_edge("exploit", "report")
    graph.add_edge("report", END)

    return graph.compile()


BUG_HUNTER_GRAPH = build_graph()
