import json
import os
import pytest
from pipelines.osint_vendor_mapping_pipeline import run_pipeline

def test_osint_vendor_mapping_pipeline_malicious_input(tmp_path):
    """
    Tests that the pipeline correctly maps structured OSINT to a risk score
    via the AILEE stub, and produces a graph if the trust threshold is met.
    """
    input_file = tmp_path / "test_osint_input.json"
    output_file = tmp_path / "test_osint_output.json"

    # Create mock malicious input
    mock_data = {
      "vendors": [
        {
          "id": "v-1001",
          "name": "FakeSpywareCorp LLC",
          "jurisdiction": "Offshore Haven A"
        }
      ],
      "hosting_providers": [
        {
          "id": "h-2001",
          "name": "BulletproofHosting Example",
          "asn": "AS64496"
        }
      ]
    }

    with open(input_file, 'w') as f:
        json.dump(mock_data, f)

    run_pipeline(str(input_file), str(output_file))

    # Assert output exists and is structured correctly
    assert os.path.exists(output_file)
    with open(output_file, 'r') as f:
        report = json.load(f)

    assert report["status"] == "ACTIONABLE"
    assert report["findings"]["classification_label"] == "MERCENARY_INFRASTRUCTURE"
    assert report["findings"]["risk_score"] > 8.0

    # Check the graph representation
    graph = report["graph"]
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) == 2  # One vendor, one host
    assert len(graph["edges"]) == 1  # Link between them
    assert graph["edges"][0]["source"] == "v-1001"
    assert graph["edges"][0]["target"] == "h-2001"


def test_osint_vendor_mapping_pipeline_benign_input(tmp_path):
    """
    Tests that benign OSINT inputs fail the AILEE policy gate and do not
    generate actionable intelligence graphs.
    """
    input_file = tmp_path / "test_osint_input_benign.json"
    output_file = tmp_path / "test_osint_output_benign.json"

    # Create mock benign input
    mock_data = {
      "vendors": [
        {
          "id": "v-2001",
          "name": "Legit Local ISP",
          "jurisdiction": "US"
        }
      ],
      "hosting_providers": []
    }

    with open(input_file, 'w') as f:
        json.dump(mock_data, f)

    run_pipeline(str(input_file), str(output_file))

    assert os.path.exists(output_file)
    with open(output_file, 'r') as f:
        report = json.load(f)

    assert report["status"] == "HUMAN_REVIEW_REQUIRED"
    assert report["findings"]["classification_label"] == "STANDARD_CORPORATE"
    assert "graph" in report
    assert len(report["graph"]) == 0
