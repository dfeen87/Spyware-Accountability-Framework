import json
import logging
import argparse

import networkx as nx

from ailee_core.models_stub import SyntheticOSINTModelStub, ailee_policy_gate
from ailee_core.privacy import redact_pii

# Configure basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def run_pipeline(input_path: str, output_path: str) -> None:
    """
    Executes the OSINT Vendor Mapping Pipeline on structured OSINT data.

    This pipeline ingests entities, builds relationships, and asks an AILEE
    OSINT analyzer to score the risk level of the entire cluster.
    """
    logging.info(f"Starting OSINT Vendor Mapping Pipeline with input: {input_path}")

    # 1. Ingest Data
    try:
        with open(input_path, 'r') as f:
            data = json.load(f)
            logging.info(f"Loaded OSINT dataset: {len(data.get('vendors', []))} vendors.")
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_path}")
        return
    except json.JSONDecodeError:
        logging.error(f"Failed to parse JSON input: {input_path}")
        return

    # 2. Apply PII redaction before any further processing (v3 privacy overlay)
    data = redact_pii(data)

    # 3. Analyze via AILEE interfaces
    analyzer = SyntheticOSINTModelStub()
    analysis_result = analyzer.analyze(data)

    logging.info(f"AI Classification: {analysis_result.classification_label}")
    logging.info(f"Confidence: {analysis_result.confidence_score}, Risk: {analysis_result.risk_score}")

    # 4. Apply AILEE Governance Policy
    if ailee_policy_gate(analysis_result):
        logging.info("Analysis passed AILEE policy gate. Creating relationship graph representation.")

        # Build a NetworkX DiGraph for advanced graph analytics (v3)
        nx_graph = nx.DiGraph()

        graph_nodes = []
        graph_edges = []

        for vendor in data.get("vendors", []):
            vid = vendor["id"]
            nx_graph.add_node(vid, label=vendor["name"], type="Vendor")
            graph_nodes.append({"id": vid, "label": vendor["name"], "type": "Vendor"})
            if "jurisdiction" in vendor:
                j_id = f"j-{vendor['jurisdiction']}"
                if not any(n["id"] == j_id for n in graph_nodes):
                    nx_graph.add_node(j_id, label=vendor["jurisdiction"], type="Jurisdiction")
                    graph_nodes.append({"id": j_id, "label": vendor["jurisdiction"], "type": "Jurisdiction"})
                nx_graph.add_edge(vid, j_id, relationship="REGISTERED_IN")
                graph_edges.append({"source": vid, "target": j_id, "label": "REGISTERED_IN"})

        for host in data.get("hosting_providers", []):
            hid = host["id"]
            nx_graph.add_node(hid, label=host["name"], type="Infrastructure")
            graph_nodes.append({"id": hid, "label": host["name"], "type": "Infrastructure"})
            # Link vendors to the infrastructure they use
            for vendor in data.get("vendors", []):
                vid = vendor["id"]
                nx_graph.add_edge(vid, hid, relationship="HOSTS_WITH")
                graph_edges.append({"source": vid, "target": hid, "label": "HOSTS_WITH"})

        # Support v2 additional domains entity
        for dom in data.get("domains", []):
            d_id = f"d-{dom['domain']}"
            if not any(n["id"] == d_id for n in graph_nodes):
                nx_graph.add_node(d_id, label=dom["domain"], type="Domain")
                graph_nodes.append({"id": d_id, "label": dom["domain"], "type": "Domain"})
            if "registered_by" in dom:
                nx_graph.add_edge(dom["registered_by"], d_id, relationship="OWNS_DOMAIN")
                graph_edges.append({"source": dom["registered_by"], "target": d_id, "label": "OWNS_DOMAIN"})
            if "hosted_on" in dom:
                nx_graph.add_edge(d_id, dom["hosted_on"], relationship="RESOLVES_TO")
                graph_edges.append({"source": d_id, "target": dom["hosted_on"], "label": "RESOLVES_TO"})

        # Compute graph analytics metrics (v3 advanced analytics)
        graph_metrics: dict = {}
        if nx_graph.number_of_nodes() > 0:
            centrality = nx.degree_centrality(nx_graph) if nx_graph.number_of_nodes() > 1 else {}
            components = list(nx.weakly_connected_components(nx_graph))
            graph_metrics = {
                "node_count": nx_graph.number_of_nodes(),
                "edge_count": nx_graph.number_of_edges(),
                "num_weakly_connected_components": len(components),
                "largest_component_size": max((len(c) for c in components), default=0),
                "top_nodes_by_centrality": sorted(centrality, key=lambda n: centrality.get(n, 0.0), reverse=True)[:3] if centrality else [],
            }
            logging.info(f"Graph analytics: {graph_metrics}")

        report = {
            "status": "ACTIONABLE",
            "findings": analysis_result.model_dump(),
            "graph": {
                "nodes": graph_nodes,
                "edges": graph_edges,
                "analytics": graph_metrics,
            }
        }
    else:
        logging.warning("Analysis failed AILEE policy gate (low confidence or benign profile). Graph generation skipped.")
        report = {
            "status": "HUMAN_REVIEW_REQUIRED",
            "findings": analysis_result.model_dump(),
            "graph": {}
        }

    # 5. Output Results
    try:
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
        logging.info(f"Pipeline complete. Graph report written to {output_path}")
    except IOError as e:
        logging.error(f"Failed to write output report: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the OSINT Vendor Mapping Pipeline.")
    parser.add_argument("--input", required=True, help="Path to structured OSINT JSON dataset.")
    parser.add_argument("--output", required=True, help="Path to write the resulting JSON graph and report.")

    args = parser.parse_args()
    run_pipeline(args.input, args.output)
