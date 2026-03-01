import json
import os
from unittest.mock import patch
from requests.exceptions import RequestException

from pipelines.network_forensics_pipeline import run_pipeline, extract_features_from_markdown

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

@patch("pipelines.network_forensics_pipeline.requests.post")
def test_network_forensics_pipeline_webhook_success(mock_post, tmp_path):
    """
    Tests that a successful webhook POST occurs when an actionable report is generated
    and a webhook_url is provided.
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

    webhook_url = "http://example.com/webhook"
    run_pipeline(str(input_file), str(output_file), webhook_url=webhook_url)

    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert args[0] == webhook_url
    assert "json" in kwargs
    assert kwargs["json"]["status"] == "ACTIONABLE"

@patch("pipelines.network_forensics_pipeline.requests.post")
def test_network_forensics_pipeline_webhook_failure_no_crash(mock_post, tmp_path):
    """
    Tests that if the webhook POST fails (e.g., Timeout or ConnectionError),
    the pipeline handles it gracefully and does not crash.
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

    mock_post.side_effect = RequestException("Mocked connection error")
    webhook_url = "http://example.com/webhook"

    # Should not raise an exception
    run_pipeline(str(input_file), str(output_file), webhook_url=webhook_url)

    mock_post.assert_called_once()
    assert os.path.exists(output_file)

@patch("pipelines.network_forensics_pipeline.requests.post")
def test_network_forensics_pipeline_webhook_not_actionable(mock_post, tmp_path):
    """
    Tests that the webhook is NOT called if the report is not ACTIONABLE,
    even if a webhook URL is provided.
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

    webhook_url = "http://example.com/webhook"
    run_pipeline(str(input_file), str(output_file), webhook_url=webhook_url)

    mock_post.assert_not_called()
    assert os.path.exists(output_file)


def test_extract_features_from_markdown_strips_punctuation():
    """
    Tests that extract_features_from_markdown correctly extracts domains and
    TLS fingerprints even when they are followed by punctuation (commas, periods,
    quotes) in markdown prose — a common real-world formatting pattern.
    """
    content = (
        "The malware contacted malicious.com, and also update.example-spyware.xyz, "
        "using TLS fingerprint e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855."
    )
    result = extract_features_from_markdown(content)
    assert "malicious.com" in result["domains"]
    assert "update.example-spyware.xyz" in result["domains"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in result["tls_fingerprints"]


def test_extract_features_from_markdown_clean_words():
    """
    Tests that extraction also works on words without any trailing punctuation
    (to ensure the strip-first approach doesn't break the baseline case).
    """
    content = "Observed beacon to c2.example-spyware.xyz and normal.com"
    result = extract_features_from_markdown(content)
    assert "c2.example-spyware.xyz" in result["domains"]
    assert "normal.com" in result["domains"]
