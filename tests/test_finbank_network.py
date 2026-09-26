"""Unit tests for the FinBank network topology module."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from src.finbank_network import (
    EXPECTED_EDGES,
    EXPECTED_NODE_IDS,
    REQUIRED_EDGE_FIELDS,
    REQUIRED_NODE_FIELDS,
    build_finbank_graph,
    get_finbank_edge_count,
    get_finbank_node_count,
    load_finbank_network,
    validate_finbank_network,
)
from src.finbank_env import load_finbank_systems


class TestFinBankExpectedNodesExist(unittest.TestCase):
    """All expected FinBank systems must be present as nodes."""

    @classmethod
    def setUpClass(cls):
        cls.network = validate_finbank_network()
        cls.node_ids = {str(node["id"]) for node in cls.network["nodes"]}

    def test_all_expected_nodes_exist(self):
        self.assertSetEqual(set(EXPECTED_NODE_IDS), self.node_ids)

    def test_node_count(self):
        self.assertEqual(get_finbank_node_count(), len(EXPECTED_NODE_IDS))

    def test_nodes_have_required_fields(self):
        for node in self.network["nodes"]:
            missing = REQUIRED_NODE_FIELDS - set(node.keys())
            self.assertFalse(missing, f"Node {node.get('id')} missing fields: {sorted(missing)}")


class TestFinBankExpectedDirectedEdgesExist(unittest.TestCase):
    """All expected directed edges must be present in the FinBank topology."""

    @classmethod
    def setUpClass(cls):
        cls.network = validate_finbank_network()
        edges = [(str(e["source"]), str(e["target"])) for e in cls.network["edges"]]
        cls.edge_set = set(edges)

    def test_expected_edges_exist(self):
        missing = [edge for edge in EXPECTED_EDGES if edge not in self.edge_set]
        self.assertFalse(missing, f"Missing expected edges: {missing}")

    def test_edge_count_matches_expected(self):
        self.assertEqual(get_finbank_edge_count(), len(EXPECTED_EDGES))

    def test_edges_have_required_fields(self):
        for edge in self.network["edges"]:
            missing = REQUIRED_EDGE_FIELDS - set(edge.keys())
            self.assertFalse(missing, f"Edge {edge.get('source')} -> {edge.get('target')} missing fields: {sorted(missing)}")


class TestFinBankNoDuplicateEdges(unittest.TestCase):
    """No duplicate directed edges may exist."""

    @classmethod
    def setUpClass(cls):
        cls.network = validate_finbank_network()
        edges = [(str(e["source"]), str(e["target"])) for e in cls.network["edges"]]
        cls.edge_tuples = edges

    def test_no_duplicate_directed_edges(self):
        self.assertEqual(len(self.edge_tuples), len(set(self.edge_tuples)))

    def test_duplicate_edge_in_json_raises(self):
        bad_network = {
            "nodes": [
                {"id": "A", "name": "A", "type": "Server", "criticality": 1, "internet_exposed": False},
                {"id": "B", "name": "B", "type": "Server", "criticality": 1, "internet_exposed": False},
            ],
            "edges": [
                {"source": "A", "target": "B", "base_cost": 2},
                {"source": "A", "target": "B", "base_cost": 2},
            ],
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as f:
            json.dump(bad_network, f)
            tmp_path = f.name
        try:
            with self.assertRaises(ValueError):
                validate_finbank_network(tmp_path)
        finally:
            Path(tmp_path).unlink()


class TestFinBankGraphCompatibility(unittest.TestCase):
    """FinBank graph output must be compatible with TraceWard A* contract."""

    def test_build_graph_returns_expected_keys(self):
        graph = build_finbank_graph()
        for key in ("nodes", "edges", "adjacency", "risk_map"):
            self.assertIn(key, graph)

    def test_adjacency_contains_all_nodes(self):
        graph = build_finbank_graph()
        node_ids = {str(node["id"]) for node in graph["nodes"]}
        self.assertSetEqual(set(graph["adjacency"].keys()), node_ids)

    def test_graph_does_not_mutate_network_file(self):
        network_path = Path("data/finbank/network.json")
        original = network_path.read_text(encoding="utf-8")
        build_finbank_graph()
        current = network_path.read_text(encoding="utf-8")
        self.assertEqual(original, current)

    def test_load_from_json_file(self):
        data = load_finbank_network()
        self.assertIn("nodes", data)
        self.assertIn("edges", data)


if __name__ == "__main__":
    unittest.main()
