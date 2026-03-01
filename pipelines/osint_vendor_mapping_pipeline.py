import json
import logging
from typing import Dict, Any
import argparse

from ailee_core.models_stub import SyntheticOSINTModelStub, ailee_policy_gate

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

    # 2. Analyze via AILEE interfaces
    analyzer = SyntheticOSINTModelStub()
    analysis_result = analyzer.analyze(data)

    logging.info(f"AI Classification: {analysis_result.classification_label}")
    logging.info(f"Confidence: {analysis_result.confidence_score}, Risk: {analysis_result.risk_score}")

    # 3. Apply AILEE Governance Policy
    if ailee_policy_gate(analysis_result):
        logging.info("Analysis passed AILEE policy gate. Creating relationship graph representation.")

        # Simulate generating a GraphML or relational mapping object
        # For simplicity in this stub, we create a JSON graph representation
        graph_nodes = []
        graph_edges = []

        for vendor in data.get("vendors", []):
            graph_nodes.append({"id": vendor["id"], "label": vendor["name"], "type": "Vendor"})

        for host in data.get("hosting_providers", []):
            graph_nodes.append({"id": host["id"], "label": host["name"], "type": "Infrastructure"})
            # Link vendors to the infrastructure they use
            for vendor in data.get("vendors", []):
                 graph_edges.append({"source": vendor["id"], "target": host["id"], "label": "HOSTS_WITH"})

        report = {
            "status": "ACTIONABLE",
            "findings": analysis_result.model_dump(),
            "graph": {
                "nodes": graph_nodes,
                "edges": graph_edges
            }
        }
    else:
        logging.warning("Analysis failed AILEE policy gate (low confidence or benign profile). Graph generation skipped.")
        report = {
            "status": "HUMAN_REVIEW_REQUIRED",
            "findings": analysis_result.model_dump(),
            "graph": {}
        }

    # 4. Output Results
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
