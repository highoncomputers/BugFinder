from __future__ import annotations

from bugfinder.knowledge_graph.graph import KnowledgeGraph
from bugfinder.knowledge_graph.schema import EdgeType, NodeType


class TestKnowledgeGraph:
    def test_add_and_get_node(self) -> None:
        kg = KnowledgeGraph()
        kg.add_node("example.com", NodeType.DOMAIN, name="Example")
        node = kg.get_node("example.com")
        assert node is not None
        assert node["type"] == NodeType.DOMAIN
        assert node["name"] == "Example"

    def test_add_edge(self) -> None:
        kg = KnowledgeGraph()
        kg.add_node("example.com", NodeType.DOMAIN)
        kg.add_node("192.168.1.1", NodeType.IP_ADDRESS)
        kg.add_edge("example.com", "192.168.1.1", EdgeType.RESOLVES_TO)
        neighbors = kg.get_neighbors("example.com")
        assert len(neighbors) == 1
        assert neighbors[0][0] == "192.168.1.1"
        assert neighbors[0][1]["relationship"] == EdgeType.RESOLVES_TO

    def test_get_nodes_by_type(self) -> None:
        kg = KnowledgeGraph()
        kg.add_node("a.com", NodeType.DOMAIN)
        kg.add_node("b.com", NodeType.DOMAIN)
        kg.add_node("1.1.1.1", NodeType.IP_ADDRESS)
        domains = kg.get_nodes_by_type(NodeType.DOMAIN)
        ips = kg.get_nodes_by_type(NodeType.IP_ADDRESS)
        assert len(domains) == 2
        assert len(ips) == 1

    def test_find_paths(self) -> None:
        kg = KnowledgeGraph()
        kg.add_node("a", NodeType.DOMAIN)
        kg.add_node("b", NodeType.IP_ADDRESS)
        kg.add_node("c", NodeType.FINDING)
        kg.add_edge("a", "b", EdgeType.RESOLVES_TO)
        kg.add_edge("b", "c", EdgeType.HAS_FINDING)
        paths = kg.find_paths("a", "c")
        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_merge(self) -> None:
        kg1 = KnowledgeGraph()
        kg1.add_node("a", NodeType.DOMAIN)
        kg2 = KnowledgeGraph()
        kg2.add_node("b", NodeType.DOMAIN)
        kg1.merge(kg2)
        assert kg1.node_count == 2

    def test_to_dict(self) -> None:
        kg = KnowledgeGraph()
        kg.add_node("test", NodeType.DOMAIN)
        data = kg.to_dict()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 1
        assert data["nodes"][0]["id"] == "test"
