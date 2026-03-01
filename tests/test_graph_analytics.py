"""
Tests for the v3 Advanced Graph Analytics backend (ailee_core/backends/osint_semantic_backend.py).
"""

import pytest
import networkx as nx

from ailee_core.backends.osint_semantic_backend import (
    build_entity_graph,
    compute_graph_risk_metrics,
    OSINTSemanticBackend,
)


class TestBuildEntityGraph:
    def test_empty_input_returns_empty_graph(self):
        graph = build_entity_graph({})
        assert isinstance(graph, nx.DiGraph)
        assert graph.number_of_nodes() == 0
        assert graph.number_of_edges() == 0

    def test_vendor_and_jurisdiction_nodes_created(self):
        data = {
            "vendors": [{"id": "v-1", "name": "BadCorp", "jurisdiction": "OffshoreHaven"}]
        }
        graph = build_entity_graph(data)
        assert "v-1" in graph.nodes
        assert "j-OffshoreHaven" in graph.nodes
        assert graph.has_edge("v-1", "j-OffshoreHaven")

    def test_hosting_provider_linked_to_vendor(self):
        data = {
            "vendors": [{"id": "v-1", "name": "BadCorp"}],
            "hosting_providers": [{"id": "h-1", "name": "BulletproofISP"}],
        }
        graph = build_entity_graph(data)
        assert graph.has_edge("v-1", "h-1")

    def test_domain_nodes_created(self):
        data = {
            "vendors": [{"id": "v-1", "name": "BadCorp"}],
            "domains": [{"domain": "c2.bad.xyz", "registered_by": "v-1"}],
        }
        graph = build_entity_graph(data)
        assert "d-c2.bad.xyz" in graph.nodes
        assert graph.has_edge("v-1", "d-c2.bad.xyz")

    def test_node_types_set_correctly(self):
        data = {
            "vendors": [{"id": "v-1", "name": "BadCorp", "jurisdiction": "X"}],
            "hosting_providers": [{"id": "h-1", "name": "ISP"}],
        }
        graph = build_entity_graph(data)
        assert graph.nodes["v-1"]["type"] == "Vendor"
        assert graph.nodes["j-X"]["type"] == "Jurisdiction"
        assert graph.nodes["h-1"]["type"] == "Infrastructure"


class TestComputeGraphMetrics:
    def test_empty_graph_returns_zeros(self):
        graph = nx.DiGraph()
        metrics = compute_graph_risk_metrics(graph)
        assert metrics["node_count"] == 0
        assert metrics["edge_count"] == 0
        assert metrics["max_centrality"] == 0.0

    def test_metrics_computed_for_non_empty_graph(self):
        data = {
            "vendors": [
                {"id": "v-1", "name": "Corp1", "jurisdiction": "LandX"},
                {"id": "v-2", "name": "Corp2", "jurisdiction": "LandX"},
            ],
            "hosting_providers": [{"id": "h-1", "name": "ISP"}],
        }
        graph = build_entity_graph(data)
        metrics = compute_graph_risk_metrics(graph)
        assert metrics["node_count"] > 0
        assert metrics["edge_count"] > 0
        assert 0.0 <= metrics["max_centrality"] <= 1.0
        assert "top_nodes_by_centrality" in metrics
        assert metrics["num_components"] >= 1


class TestOSINTSemanticBackend:
    def test_mercenary_ecosystem_classification(self):
        data = {
            "vendors": [
                {"id": "v-1", "name": "Corp", "jurisdiction": "suspicious_jurisdiction"},
                {"id": "v-2", "name": "Shell", "jurisdiction": "suspicious_jurisdiction"},
            ],
            "hosting_providers": [{"id": "h-1", "name": "BPI"}],
        }
        backend = OSINTSemanticBackend()
        result = backend.analyze(data)
        assert result.classification_label == "MERCENARY_ECOSYSTEM"
        assert result.confidence_score > 0.0
        assert "graph_metrics" in result.metadata

    def test_isolated_entity_classification(self):
        data = {
            "vendors": [{"id": "v-1", "name": "SmallCorp"}],
            "hosting_providers": [],
        }
        backend = OSINTSemanticBackend()
        result = backend.analyze(data)
        assert result.classification_label == "ISOLATED_ENTITY"
        assert "graph_metrics" in result.metadata

    def test_graph_metrics_in_metadata(self):
        data = {
            "vendors": [{"id": "v-1", "name": "Corp", "jurisdiction": "suspicious_jurisdiction"},
                        {"id": "v-2", "name": "Sub", "jurisdiction": "suspicious_jurisdiction"}],
            "hosting_providers": [{"id": "h-1", "name": "ISP"}],
        }
        backend = OSINTSemanticBackend()
        result = backend.analyze(data)
        metrics = result.metadata["graph_metrics"]
        assert metrics["node_count"] >= 3
        assert metrics["edge_count"] >= 2
