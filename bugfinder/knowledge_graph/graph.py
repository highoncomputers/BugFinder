from __future__ import annotations

from typing import Any

import networkx as nx


class KnowledgeGraph:
    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()

    def add_node(self, node_id: str, node_type: str, **attrs: Any) -> None:
        attrs["type"] = node_type
        self.graph.add_node(node_id, **attrs)

    def add_edge(self, source: str, target: str, relationship: str, **attrs: Any) -> None:
        attrs["relationship"] = relationship
        self.graph.add_edge(source, target, **attrs)

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        if node_id in self.graph:
            return dict(self.graph.nodes[node_id])
        return None

    def get_neighbors(self, node_id: str) -> list[tuple[str, dict[str, Any]]]:
        if node_id not in self.graph:
            return []
        result = []
        for neighbor in self.graph.successors(node_id):
            data = self.graph.get_edge_data(node_id, neighbor)
            edge_info = dict(data[0]) if data else {}
            result.append((neighbor, edge_info))
        return result

    def get_nodes_by_type(self, node_type: str) -> list[tuple[str, dict[str, Any]]]:
        return [(n, dict(d)) for n, d in self.graph.nodes(data=True) if d.get("type") == node_type]

    def find_paths(self, source: str, target: str, max_depth: int = 10) -> list[list[str]]:
        try:
            paths = nx.all_simple_paths(self.graph, source, target, cutoff=max_depth)
            return list(paths)
        except nx.NodeNotFound:
            return []

    def get_finding_chain(self, finding_id: str) -> list[dict[str, Any]]:
        chain = []
        for neighbor, edge_info in self.get_neighbors(finding_id):
            node_data = self.get_node(neighbor)
            chain.append({"node": neighbor, "data": node_data, "edge": edge_info})
        return chain

    def merge(self, other: KnowledgeGraph) -> None:
        self.graph = nx.compose(self.graph, other.graph)

    def clear(self) -> None:
        self.graph.clear()

    @property
    def node_count(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self.graph.number_of_edges()

    def to_dict(self) -> dict:
        return {
            "nodes": [{"id": n, **dict(d)} for n, d in self.graph.nodes(data=True)],
            "edges": [{"source": u, "target": v, **dict(d)} for u, v, d in self.graph.edges(data=True)],
        }
