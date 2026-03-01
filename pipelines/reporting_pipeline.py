import json
import logging
from typing import Dict, Any, List
import argparse
from pathlib import Path

# Configure basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def generate_brief(network_data: Dict[str, Any], osint_data: Dict[str, Any], output_path: str) -> None:
    """
    Generates a human-readable Markdown brief summarizing the AILEE-vetted findings.
    """
    logging.info(f"Generating defensive intelligence brief...")

    status_msg = "Critical Alert: Spyware Ecosystem Mapped"
    if network_data.get("status") != "ACTIONABLE" or osint_data.get("status") != "ACTIONABLE":
        status_msg = "Draft Intelligence Brief: Human Review Required"

    brief_content = f"""# 🛡️ Defensive Intelligence Brief

**Status:** {status_msg}

## 1. Executive Summary
This report aggregates findings from network telemetry and OSINT vendor mapping. The infrastructure profiled here exhibits characteristics of mercenary spyware operations.

**Confidence levels:**
- Network Indicators: {network_data.get('findings', {}).get('confidence_score', 'N/A')}
- Vendor Attribution: {osint_data.get('findings', {}).get('confidence_score', 'N/A')}

## 2. Infrastructure Details
The network forensic pipeline flagged the following domains or fingerprints as highly suspicious.
"""

    # List IOCs from network findings
    iocs = network_data.get("extracted_iocs", [])
    if iocs:
        for ioc in iocs:
            brief_content += f"- `{ioc}`\n"
    else:
        brief_content += "\nNo verifiable IOCs extracted or AILEE trust threshold not met.\n"

    brief_content += "\n## 3. Vendor Ecosystem Graph\n"

    # Summarize graph data
    graph = osint_data.get("graph", {})
    if graph:
        nodes = graph.get("nodes", [])
        for node in nodes:
            brief_content += f"- Entity: {node.get('label')} (Type: {node.get('type')})\n"
    else:
         brief_content += "\nNo verifiable vendor structures found or AILEE trust threshold not met.\n"

    brief_content += "\n## 4. Methodological Note & Limitations\n"
    brief_content += "This brief is generated automatically by the Spyware Accountability Framework. "
    brief_content += "It relies on synthetic examples or user-provided inputs evaluated by the AILEE layer. "
    brief_content += "Always confirm findings via human analysis before taking defensive action or attributing attacks."

    with open(f"{output_path}/defensive_brief.md", 'w') as f:
        f.write(brief_content)

    logging.info(f"Brief successfully written to {output_path}/defensive_brief.md")


def run_pipeline(network_report_path: str, osint_graph_path: str, output_dir: str) -> None:
    """
    Executes the Reporting Pipeline to aggregate outputs.
    """
    logging.info("Starting Reporting Pipeline...")

    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # 1. Ingest Data
    try:
        with open(network_report_path, 'r') as f:
            network_data = json.load(f)
    except FileNotFoundError:
        logging.error(f"Network report not found: {network_report_path}")
        network_data = {}

    try:
        with open(osint_graph_path, 'r') as f:
            osint_data = json.load(f)
    except FileNotFoundError:
        logging.error(f"OSINT graph not found: {osint_graph_path}")
        osint_data = {}

    # 2. Generate Brief
    generate_brief(network_data, osint_data, output_dir)

    # 3. Generate Machine-Readable Artifacts (IOC list)
    ioc_output = f"{output_dir}/actionable_iocs.json"
    iocs = network_data.get("extracted_iocs", [])
    try:
        with open(ioc_output, 'w') as f:
            json.dump({"verified_iocs": iocs}, f, indent=4)
        logging.info(f"Machine-readable IOCs written to {ioc_output}")
    except IOError as e:
        logging.error(f"Failed to write IOC report: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Reporting Pipeline.")
    parser.add_argument("--network-report", required=True, help="Path to network forensics JSON report.")
    parser.add_argument("--osint-graph", required=True, help="Path to OSINT graph JSON report.")
    parser.add_argument("--output-dir", required=True, help="Directory to place final briefs and IOCs.")

    args = parser.parse_args()
    run_pipeline(args.network_report, args.osint_graph, args.output_dir)
