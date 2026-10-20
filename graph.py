"""StateGraph inşası ve kenarların (edges) bağlanması."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from nodes import (
    ai_extractor_agent,
    ai_reverser_agent,
    ai_supervisor_agent,
    db_writer_node,
    deep_inspection_node,
    entry_node,
    static_feature_node,
    unpack_dotnet_node,
    unpack_native_node,
    unpack_python_node,
)
from state import AgentState

# route_flag -> hedef düğüm
ROUTES: dict[str, str] = {
    "fast_track": "ai_supervisor_agent",
    "python": "unpack_python_node",
    "dotnet": "unpack_dotnet_node",
    "native": "unpack_native_node",
}


def route_after_entry(state: AgentState) -> str:
    """entry_node sonrası koşullu yönlendirme. Bilinmeyen/boş bayrakta 'native' varsayılır."""
    return state.route_flag if state.route_flag in ROUTES else "native"


def build_graph() -> CompiledStateGraph:
    graph = StateGraph(AgentState)

    # Düğümler
    graph.add_node("entry_node", entry_node)
    graph.add_node("unpack_python_node", unpack_python_node)
    graph.add_node("unpack_dotnet_node", unpack_dotnet_node)
    graph.add_node("unpack_native_node", unpack_native_node)
    graph.add_node("static_feature_node", static_feature_node)
    graph.add_node("deep_inspection_node", deep_inspection_node)
    graph.add_node("ai_extractor_agent", ai_extractor_agent)
    graph.add_node("ai_reverser_agent", ai_reverser_agent)
    graph.add_node("ai_supervisor_agent", ai_supervisor_agent)
    graph.add_node("db_writer_node", db_writer_node)

    # Kenarlar
    graph.add_edge(START, "entry_node")
    graph.add_conditional_edges("entry_node", route_after_entry, ROUTES)

    for unpack in ("unpack_python_node", "unpack_dotnet_node", "unpack_native_node"):
        graph.add_edge(unpack, "static_feature_node")

    graph.add_edge("static_feature_node", "deep_inspection_node")
    graph.add_edge("deep_inspection_node", "ai_extractor_agent")
    graph.add_edge("ai_extractor_agent", "ai_reverser_agent")
    graph.add_edge("ai_reverser_agent", "ai_supervisor_agent")
    # fast_track da ai_supervisor_agent'a gittiği için aynı yoldan db_writer_node'a ulaşır
    graph.add_edge("ai_supervisor_agent", "db_writer_node")
    graph.add_edge("db_writer_node", END)

    return graph.compile()
