import json
import logging
from typing import Dict, List, Optional
import argparse
import requests
from requests.exceptions import RequestException

from ailee_core.models_stub import SyntheticNetworkModelStub, ailee_policy_gate
from ailee_core.privacy import redact_pii

# Configure basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def run_pipeline(input_path: str, output_path: str, webhook_url: Optional[str] = None) -> None:
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

                # Check if it's the v2 format with a list of flows
                if "flows" in data:
                    domains = []
                    tls_fingerprints = []
                    for flow in data["flows"]:
                        if "sni_domain" in flow:
                            domains.append(flow["sni_domain"])
                        if "tls_fingerprint" in flow:
                            tls_fingerprints.append(flow["tls_fingerprint"])
                    data["domains"] = domains
                    data["tls_fingerprints"] = tls_fingerprints
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

    # 2. Apply PII redaction before any further processing (v3 privacy overlay)
    data = redact_pii(data)

    # 3. Analyze via AILEE interfaces
    analyzer = SyntheticNetworkModelStub()
    analysis_result = analyzer.analyze(data)

    logging.info(f"AI Classification: {analysis_result.classification_label}")
    logging.info(f"Confidence: {analysis_result.confidence_score}, Risk: {analysis_result.risk_score}")

    # 4. Apply AILEE Governance Policy
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

    # 5. Output Results
    try:
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
        logging.info(f"Pipeline complete. Report written to {output_path}")
    except IOError as e:
        logging.error(f"Failed to write output report: {e}")

    # 6. Optional Webhook Forwarding (Active Prevention Handoff)
    if webhook_url and report.get("status") == "ACTIONABLE":
        logging.info(f"Forwarding actionable report to webhook: {webhook_url}")
        try:
            # We strictly POST data. We do not process a response or modify local state based on it.
            # Timeout is relatively short so the pipeline doesn't hang indefinitely on a bad endpoint.
            response = requests.post(webhook_url, json=report, timeout=10.0)
            response.raise_for_status()
            logging.info("Webhook forwarding successful.")
        except RequestException as e:
            # We log the error but do NOT crash the pipeline. SAF's core job is done (generating the output).
            logging.error(f"Failed to forward report to webhook: {e}")


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
    parser.add_argument("--webhook-url", required=False, help="Optional URL to POST actionable JSON reports to an external Trust Layer or SIEM for active prevention.")

    args = parser.parse_args()
    run_pipeline(args.input, args.output, args.webhook_url)
