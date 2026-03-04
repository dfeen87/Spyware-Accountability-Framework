import json
import os
from unittest.mock import patch
from requests.exceptions import RequestException

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
    assert len(graph["nodes"]) == 3  # One vendor, one jurisdiction, one host
    assert len(graph["edges"]) == 2  # Two relationships

    # Check edges
    targets = [e["target"] for e in graph["edges"]]
    assert "h-2001" in targets
    assert "j-Offshore Haven A" in targets


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

@patch("pipelines.osint_vendor_mapping_pipeline.requests.post")
def test_osint_vendor_mapping_pipeline_webhook_success(mock_post, tmp_path):
    """
    Tests that a successful webhook POST occurs when an actionable report is generated
    and a webhook_url is provided.
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

    webhook_url = "https://example.com/webhook"
    run_pipeline(str(input_file), str(output_file), webhook_url=webhook_url)

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == webhook_url
    assert "json" in kwargs
    assert kwargs["json"]["status"] == "ACTIONABLE"

@patch("pipelines.osint_vendor_mapping_pipeline.requests.post")
def test_osint_vendor_mapping_pipeline_webhook_failure_no_crash(mock_post, tmp_path):
    """
    Tests that if the webhook POST fails (e.g., Timeout or ConnectionError),
    the pipeline handles it gracefully and does not crash.
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

    mock_post.side_effect = RequestException("Mocked connection error")
    webhook_url = "https://example.com/webhook"

    # Should not raise an exception
    run_pipeline(str(input_file), str(output_file), webhook_url=webhook_url)

    mock_post.assert_called_once()
    assert os.path.exists(output_file)

@patch("pipelines.osint_vendor_mapping_pipeline.requests.post")
def test_osint_vendor_mapping_pipeline_webhook_not_actionable(mock_post, tmp_path):
    """
    Tests that the webhook is NOT called if the report is not ACTIONABLE,
    even if a webhook URL is provided.
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

    webhook_url = "https://example.com/webhook"
    run_pipeline(str(input_file), str(output_file), webhook_url=webhook_url)

    mock_post.assert_not_called()
    assert os.path.exists(output_file)
