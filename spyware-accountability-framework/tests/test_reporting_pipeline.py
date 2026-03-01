import json
import os
import pytest
from pathlib import Path
from pipelines.reporting_pipeline import run_pipeline

def test_reporting_pipeline_success(tmp_path):
    """
    Tests that the reporting pipeline successfully aggregates outputs
    from the network and OSINT pipelines into actionable briefs and IOC lists.
    """
    network_input = tmp_path / "network_report.json"
    osint_input = tmp_path / "osint_graph.json"
    output_dir = tmp_path / "reports"

    # Mock network data
    mock_network = {
        "status": "ACTIONABLE",
        "findings": {
            "classification_label": "SUSPICIOUS_BEACON",
            "confidence_score": 0.95
        },
        "extracted_iocs": ["c2.example.com", "deadbeef1234"]
    }
    with open(network_input, 'w') as f:
        json.dump(mock_network, f)

    # Mock OSINT data
    mock_osint = {
        "status": "ACTIONABLE",
        "findings": {
            "classification_label": "MERCENARY_INFRASTRUCTURE",
            "confidence_score": 0.88
        },
        "graph": {
            "nodes": [
                {"id": "v-1", "label": "BadVendor", "type": "Vendor"}
            ]
        }
    }
    with open(osint_input, 'w') as f:
        json.dump(mock_osint, f)

    run_pipeline(str(network_input), str(osint_input), str(output_dir))

    # Assert artifacts were created
    assert os.path.exists(output_dir)
    assert os.path.exists(output_dir / "defensive_brief.md")
    assert os.path.exists(output_dir / "actionable_iocs.json")

    # Check IOC list content
    with open(output_dir / "actionable_iocs.json", 'r') as f:
        iocs = json.load(f)
        assert len(iocs["verified_iocs"]) == 2
        assert "c2.example.com" in iocs["verified_iocs"]

    # Check Markdown brief content
    with open(output_dir / "defensive_brief.md", 'r') as f:
        content = f.read()
        assert "Critical Alert" in content
        assert "c2.example.com" in content
        assert "BadVendor" in content

def test_reporting_pipeline_missing_inputs(tmp_path):
    """
    Tests that the reporting pipeline handles missing files gracefully and still
    generates a partial brief.
    """
    output_dir = tmp_path / "reports_missing"

    run_pipeline("nonexistent_network.json", "nonexistent_osint.json", str(output_dir))

    assert os.path.exists(output_dir / "defensive_brief.md")

    with open(output_dir / "defensive_brief.md", 'r') as f:
        content = f.read()
        assert "Draft Intelligence Brief" in content
        assert "No verifiable IOCs" in content
