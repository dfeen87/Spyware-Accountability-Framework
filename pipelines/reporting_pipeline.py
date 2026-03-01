import json
import logging
from typing import Dict, Any
import argparse
from pathlib import Path

# Configure basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def generate_brief(network_data: Dict[str, Any], osint_data: Dict[str, Any], output_path: str) -> None:
    """
    Generates a human-readable Markdown brief summarizing the AILEE-vetted findings
    using the v2 automated threat briefing template.
    """
    logging.info("Generating defensive intelligence brief...")

    status_msg = "Critical Alert: Spyware Ecosystem Mapped"
    if network_data.get("status") != "ACTIONABLE" or osint_data.get("status") != "ACTIONABLE":
        status_msg = "Draft Intelligence Brief: Human Review Required"

    # List IOCs from network findings
    iocs = network_data.get("extracted_iocs", [])
    iocs_list = ""
    if iocs:
        for ioc in iocs:
            iocs_list += f"- `{ioc}`\n"
    else:
        iocs_list = "No verifiable IOCs extracted or AILEE trust threshold not met.\n"

    # Summarize graph data (ASCII representation/JSON dump)
    graph = osint_data.get("graph", {})
    infrastructure_graph = ""
    if graph:
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        infrastructure_graph += "```json\n"
        infrastructure_graph += json.dumps(graph, indent=2)
        infrastructure_graph += "\n```\n\n**Visual Summary:**\n"
        for edge in edges:
            source = next((n['label'] for n in nodes if n['id'] == edge['source']), edge['source'])
            target = next((n['label'] for n in nodes if n['id'] == edge['target']), edge['target'])
            infrastructure_graph += f"- [{source}] --({edge['label']})--> [{target}]\n"
    else:
         infrastructure_graph = "No verifiable vendor structures found or AILEE trust threshold not met.\n"

    # Read template (path resolved relative to this module's location)
    template_path = Path(__file__).resolve().parent.parent / "reports" / "templates" / "brief_template.md"
    try:
        with open(template_path, 'r') as f:
            template = f.read()
    except FileNotFoundError:
        logging.error(f"Template not found at {template_path}. Ensure you are running from repo root.")
        return

    # Replace placeholders
    brief_content = template
    brief_content = brief_content.replace("{{ status_msg }}", status_msg)

    net_findings = network_data.get('findings', {})
    brief_content = brief_content.replace("{{ network_confidence }}", str(net_findings.get('confidence_score', 'N/A')))
    brief_content = brief_content.replace("{{ network_risk }}", str(net_findings.get('risk_score', 'N/A')))
    brief_content = brief_content.replace("{{ network_classification }}", str(net_findings.get('classification_label', 'N/A')))

    osint_findings = osint_data.get('findings', {})
    brief_content = brief_content.replace("{{ osint_confidence }}", str(osint_findings.get('confidence_score', 'N/A')))
    brief_content = brief_content.replace("{{ osint_risk }}", str(osint_findings.get('risk_score', 'N/A')))
    brief_content = brief_content.replace("{{ osint_classification }}", str(osint_findings.get('classification_label', 'N/A')))

    brief_content = brief_content.replace("{{ iocs_list }}", iocs_list)
    brief_content = brief_content.replace("{{ infrastructure_graph }}", infrastructure_graph)

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
