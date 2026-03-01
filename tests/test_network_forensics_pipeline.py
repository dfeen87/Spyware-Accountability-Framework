import json
import os
from pipelines.network_forensics_pipeline import run_pipeline

def test_network_forensics_pipeline_malicious_input(tmp_path):
    """
    Tests that the pipeline correctly parses input, identifies synthetic
    malicious indicators via the AILEE stub, and outputs an actionable report.
    """
    input_file = tmp_path / "test_input.json"
    output_file = tmp_path / "test_output.json"

    # Create mock malicious input
    mock_data = {
        "domains": ["update.example-spyware.xyz", "benign.com"],
        "tls_fingerprints": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    }

    with open(input_file, 'w') as f:
        json.dump(mock_data, f)

    run_pipeline(str(input_file), str(output_file))

    # Assert output exists and is structured correctly
    assert os.path.exists(output_file)
    with open(output_file, 'r') as f:
        report = json.load(f)

    assert report["status"] == "ACTIONABLE"
    assert report["findings"]["classification_label"] == "SUSPICIOUS_BEACON"
    assert report["findings"]["confidence_score"] > 0.90
    assert len(report["extracted_iocs"]) > 0
    assert "update.example-spyware.xyz" in report["extracted_iocs"]

def test_network_forensics_pipeline_benign_input(tmp_path):
    """
    Tests that the pipeline handles benign traffic by failing the AILEE policy gate
    and requiring human review rather than generating an alert.
    """
    input_file = tmp_path / "test_input_benign.json"
    output_file = tmp_path / "test_output_benign.json"

    # Create mock benign input
    mock_data = {
        "domains": ["google.com", "ubuntu.com"],
        "tls_fingerprints": ["1234567890abcdef"]
    }

    with open(input_file, 'w') as f:
        json.dump(mock_data, f)

    run_pipeline(str(input_file), str(output_file))

    assert os.path.exists(output_file)
    with open(output_file, 'r') as f:
        report = json.load(f)

    assert report["status"] == "HUMAN_REVIEW_REQUIRED"
    assert report["findings"]["classification_label"] == "BENIGN_TRAFFIC"
    assert len(report["extracted_iocs"]) == 0
