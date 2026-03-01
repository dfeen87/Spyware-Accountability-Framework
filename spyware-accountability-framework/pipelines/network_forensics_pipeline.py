import json
import logging
from typing import Dict, Any, List
import argparse

from ailee_core.models_stub import SyntheticNetworkModelStub, ailee_policy_gate

# Configure basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def run_pipeline(input_path: str, output_path: str) -> None:
    """
    Executes the Network Forensics Pipeline on synthetic or pre-processed network telemetry.

    This pipeline reads network features (domains, IPs, TLS fingerprints),
    passes them to the (stubbed) AI analyzer, checks the result against the AILEE policy,
    and produces actionable insights if the AI result is trustworthy.
    """
    logging.info(f"Starting Network Forensics Pipeline with input: {input_path}")

    # 1. Ingest Data
    try:
        with open(input_path, 'r') as f:
            if input_path.endswith('.json'):
                data = json.load(f)
            else:
                # For Markdown descriptions or other structured text, we simulate
                # an extraction step by creating a mock structured payload based on keywords.
                content = f.read()
                data = extract_features_from_markdown(content)
                logging.info(f"Extracted features from text input: {data}")
    except FileNotFoundError:
        logging.error(f"Input file not found: {input_path}")
        return
    except json.JSONDecodeError:
        logging.error(f"Failed to parse JSON input: {input_path}")
        return

    # 2. Analyze via AILEE interfaces
    analyzer = SyntheticNetworkModelStub()
    analysis_result = analyzer.analyze(data)

    logging.info(f"AI Classification: {analysis_result.classification_label}")
    logging.info(f"Confidence: {analysis_result.confidence_score}, Risk: {analysis_result.risk_score}")

    # 3. Apply AILEE Governance Policy
    if ailee_policy_gate(analysis_result):
        logging.info("Analysis passed AILEE policy gate. Generating actionable report.")
        report = {
            "status": "ACTIONABLE",
            "findings": analysis_result.model_dump(),
            "extracted_iocs": data.get("domains", []) + data.get("tls_fingerprints", [])
        }
    else:
        logging.warning("Analysis failed AILEE policy gate (low confidence or benign). Requires human review.")
        report = {
            "status": "HUMAN_REVIEW_REQUIRED",
            "findings": analysis_result.model_dump(),
            "extracted_iocs": []
        }

    # 4. Output Results
    try:
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
        logging.info(f"Pipeline complete. Report written to {output_path}")
    except IOError as e:
        logging.error(f"Failed to write output report: {e}")


def extract_features_from_markdown(content: str) -> Dict[str, List[str]]:
    """
    Simulates parsing unstructured or semi-structured markdown notes from an analyst
    into structured indicators for the AI pipeline.
    """
    domains = []
    tls_fingerprints = []

    # Simple regex or string matching simulation
    for word in content.split():
        if word.endswith(".xyz") or word.endswith(".com"):
            domains.append(word.strip("`.,\"'()"))
        elif len(word) == 64 and all(c in "0123456789abcdef" for c in word.lower()):
            tls_fingerprints.append(word)

    return {"domains": domains, "tls_fingerprints": tls_fingerprints}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the Network Forensics Pipeline.")
    parser.add_argument("--input", required=True, help="Path to synthetic network capture or description.")
    parser.add_argument("--output", required=True, help="Path to write the resulting JSON report.")

    args = parser.parse_args()
    run_pipeline(args.input, args.output)
