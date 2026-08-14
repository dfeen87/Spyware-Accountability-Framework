# Copyright (c) Don Michael Feeney Jr.
# Licensed under the MIT License.

import json
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from examples.local_defensive_plugin import (
    SAFWebhookHandler,
    is_ip_address,
    load_existing_lines,
    process_report_data,
    update_firewall_script,
    update_hosts_list,
    update_pihole_list,
)


@pytest.fixture
def temp_dir():
    dirpath = tempfile.mkdtemp()
    yield Path(dirpath)
    shutil.rmtree(dirpath)


def test_is_ip_address():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.254") is True
    assert is_ip_address("256.256.256.256") is False
    assert is_ip_address("not_an_ip.com") is False
    assert is_ip_address("2001:db8::1") is True
    assert is_ip_address("  192.168.1.50   ") is True


def test_load_existing_lines(temp_dir):
    filepath = temp_dir / "test_file.txt"
    assert load_existing_lines(filepath) == set()

    with open(filepath, "w") as f:
        f.write("# comment\n")
        f.write("domain.com\n")
        f.write("  another.org\n")
        f.write("\n")

    lines = load_existing_lines(filepath)
    assert lines == {"domain.com", "another.org"}


def test_update_pihole_list(temp_dir):
    new_domains = {"malicious1.xyz", "malicious2.xyz"}
    added = update_pihole_list(temp_dir, new_domains)
    assert added == 2

    # Check file exists and has domains
    filepath = temp_dir / "pihole_blocklist.txt"
    assert filepath.exists()
    content = filepath.read_text()
    assert "malicious1.xyz" in content
    assert "malicious2.xyz" in content

    # Test updating with duplicate domains
    added_again = update_pihole_list(temp_dir, {"malicious1.xyz", "malicious3.xyz"})
    assert added_again == 1


def test_update_hosts_list(temp_dir):
    new_domains = {"malicious1.xyz", "malicious2.xyz"}
    added = update_hosts_list(temp_dir, new_domains)
    assert added == 2

    filepath = temp_dir / "hosts_blocklist.txt"
    assert filepath.exists()
    content = filepath.read_text()
    assert "0.0.0.0 malicious1.xyz" in content
    assert "0.0.0.0 malicious2.xyz" in content


def test_update_firewall_script(temp_dir):
    new_ips = {"192.0.2.1", "198.51.100.5"}
    added = update_firewall_script(temp_dir, new_ips)
    assert added == 2

    filepath = temp_dir / "firewall_block.sh"
    assert filepath.exists()
    content = filepath.read_text()
    assert '"192.0.2.1"' in content
    assert '"198.51.100.5"' in content
    assert "iptables" in content
    assert "pfctl" in content


def test_process_report_data_not_actionable(temp_dir):
    report = {
        "status": "HUMAN_REVIEW_REQUIRED",
        "findings": {},
        "extracted_iocs": ["malicious.xyz"]
    }
    processed = process_report_data(report, temp_dir)
    assert processed is False


def test_process_report_data_actionable(temp_dir):
    report = {
        "status": "ACTIONABLE",
        "findings": {
            "classification_label": "MERCENARY_C2_BEACON"
        },
        "extracted_iocs": [
            "malicious.xyz",
            "192.0.2.55",
            "an-ip-address-that-is-invalid",
            "127.0.0.1",
            "another-malicious.com"
        ]
    }
    processed = process_report_data(report, temp_dir)
    assert processed is True

    pihole_file = temp_dir / "pihole_blocklist.txt"
    assert "malicious.xyz" in pihole_file.read_text()
    assert "another-malicious.com" in pihole_file.read_text()

    firewall_file = temp_dir / "firewall_block.sh"
    assert '"192.0.2.55"' in firewall_file.read_text()
    assert '"127.0.0.1"' in firewall_file.read_text()


def test_webhook_handler_post_actionable(temp_dir):
    # Mocking BaseHTTPRequestHandler mechanics to test handler processing
    mock_server = MagicMock()
    mock_server.output_dir = temp_dir

    class MockHandler(SAFWebhookHandler):
        def __init__(self, *args, **kwargs):
            # Override constructor to avoid socket.Server base logic
            pass

    handler = MockHandler()
    handler.server = mock_server
    handler.headers = {"Content-Length": "120"}

    report_bytes = json.dumps({
        "status": "ACTIONABLE",
        "extracted_iocs": ["some-malicious-domain.com"]
    }).encode("utf-8")

    handler.rfile = MagicMock()
    handler.rfile.read.return_value = report_bytes
    handler.wfile = MagicMock()
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()

    handler.do_POST()

    handler.send_response.assert_called_with(200)
    pihole_file = temp_dir / "pihole_blocklist.txt"
    assert "some-malicious-domain.com" in pihole_file.read_text()
