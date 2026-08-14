# Copyright (c) Don Michael Feeney Jr.
# Licensed under the MIT License.

"""
examples/local_defensive_plugin.py - Local Defensive Integration Plugin (v3)

A lightweight, self-contained Python script to easily adopt the Spyware Accountability
Framework (SAF) on personal computers and home networks. It acts as an optional
defensive handler that consumes passive SAF reports and safely generates local
defense artifacts (hosts files, Pi-hole domain lists, local firewall rules).

Supported Modes:
1. WATCH mode: Continuous monitoring of a directory (e.g., /tmp/saf_reports) for new JSON reports.
2. SERVER mode: Starts a lightweight local HTTP webhook server to receive live reports from SAF.

Generated Artifacts:
- pihole_blocklist.txt: A plain-text domain list compatible with Pi-hole or AdGuard Home.
- hosts_blocklist.txt: A standard /etc/hosts formatting (0.0.0.0 <domain>).
- firewall_block.sh: Shell script template for blocking malicious IPs via iptables (Linux) or pf (macOS).
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("local_defensive_plugin")

IP_V4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
IP_V6_PATTERN = re.compile(r"^[0-9a-fA-F:]+$")


def is_ip_address(ioc: str) -> bool:
    """
    Determines if a string is a valid IPv4 or potential IPv6 address.
    """
    ioc_stripped = ioc.strip()
    if IP_V4_PATTERN.match(ioc_stripped):
        parts = ioc_stripped.split(".")
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    if ":" in ioc_stripped and IP_V6_PATTERN.match(ioc_stripped):
        return True
    return False


def load_existing_lines(filepath: Path) -> set[str]:
    """
    Safely reads existing non-comment lines from a file.
    """
    if not filepath.exists():
        return set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip() and not line.strip().startswith("#")}
    except Exception as e:
        logger.warning("Failed to read existing file %s: %s", filepath, e)
        return set()


def update_pihole_list(output_dir: Path, new_domains: set[str]) -> int:
    """
    Updates the Pi-hole/AdGuard Home compatible blocklist (one domain per line).
    """
    filepath = output_dir / "pihole_blocklist.txt"
    existing_domains = load_existing_lines(filepath)
    all_domains = existing_domains.union(new_domains)
    if not all_domains:
        return 0
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# SAF Pi-hole/AdGuard Home Blocklist\n")
            f.write("# Copyright (c) Don Michael Feeney Jr. - Licensed under the MIT License.\n")
            f.write(f"# Updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
            f.writelines(f"{domain}\n" for domain in sorted(all_domains))
        logger.info("Updated Pi-hole blocklist at %s (Total: %d domains)", filepath, len(all_domains))
        return len(all_domains) - len(existing_domains)
    except Exception as e:
        logger.error("Failed to write Pi-hole blocklist: %s", e)
        return 0


def update_hosts_list(output_dir: Path, new_domains: set[str]) -> int:
    """
    Updates the hosts_blocklist.txt in /etc/hosts format (0.0.0.0 <domain>).
    """
    filepath = output_dir / "hosts_blocklist.txt"
    existing_domains = set()
    if filepath.exists():
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2:
                            existing_domains.add(parts[1])
        except Exception as e:
            logger.warning("Failed to read existing hosts file: %s", e)

    all_domains = existing_domains.union(new_domains)
    if not all_domains:
        return 0
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("# SAF Local Hosts Blocklist\n")
            f.write("# Copyright (c) Don Michael Feeney Jr. - Licensed under the MIT License.\n")
            f.write("# Append these lines to your system's /etc/hosts file to block domains locally.\n")
            f.write(f"# Updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
            f.writelines(f"0.0.0.0 {domain}\n" for domain in sorted(all_domains))
        logger.info("Updated hosts blocklist at %s (Total: %d domains)", filepath, len(all_domains))
        return len(all_domains) - len(existing_domains)
    except Exception as e:
        logger.error("Failed to write hosts blocklist: %s", e)
        return 0


def update_firewall_script(output_dir: Path, new_ips: set[str]) -> int:
    """
    Generates a local shell script (firewall_block.sh) to apply IP drop rules.
    """
    filepath = output_dir / "firewall_block.sh"
    existing_ips = set()
    if filepath.exists():
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                in_list = False
                for line in f:
                    line = line.strip()
                    if line.startswith("IP_LIST=("):
                        in_list = True
                        continue
                    if in_list:
                        if line == ")":
                            in_list = False
                            continue
                        cleaned = line.strip('"\' ')
                        if cleaned:
                            existing_ips.add(cleaned)
        except Exception as e:
            logger.warning("Failed to read existing firewall script: %s", e)

    all_ips = existing_ips.union(new_ips)
    if not all_ips:
        return 0
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write("#!/bin/bash\n")
            f.write("# SAF Local Firewall Blocklist Script\n")
            f.write("# Copyright (c) Don Michael Feeney Jr. - Licensed under the MIT License.\n")
            f.write("# WARNING: Review the IP list below before executing with sudo.\n")
            f.write(f"# Updated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")

            f.write("IP_LIST=(\n")
            f.writelines(f"  \"{ip}\"\n" for ip in sorted(all_ips))
            f.write(")\n\n")

            f.write("""echo "Applying IP block rules to local firewall..."
for ip in "${IP_LIST[@]}"; do
    if [ -x "$(command -v iptables)" ]; then
        echo "Adding Linux iptables DROP rule for $ip..."
        sudo iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null || sudo iptables -A OUTPUT -d "$ip" -j DROP
    fi
    if [ -x "$(command -v pfctl)" ]; then
        echo "Adding macOS pfctl block instruction for $ip..."
        echo "block drop out quick to $ip" | sudo pfctl -a com.apple/saf_block -f - 2>/dev/null || true
    fi
done
echo "Firewall update complete."
""")
        try:
            filepath.chmod(0o755)
        except Exception as e:
            logger.debug("Failed to set executable permission on %s: %s", filepath, e)
        logger.info("Updated firewall block script at %s (Total: %d IPs)", filepath, len(all_ips))
        return len(all_ips) - len(existing_ips)
    except Exception as e:
        logger.error("Failed to write firewall script: %s", e)
        return 0


def process_report_data(report_data: dict[str, Any], output_dir: Path) -> bool:
    """
    Processes a raw report dictionary. If status is ACTIONABLE, extracts IOCs
    and regenerates/updates defensive files.
    """
    if not isinstance(report_data, dict):
        logger.warning("Received invalid report format (not a dictionary).")
        return False

    status = report_data.get("status")
    if status != "ACTIONABLE":
        logger.debug("Ignoring report; status is '%s', not 'ACTIONABLE'.", status)
        return False

    extracted_iocs = report_data.get("extracted_iocs", [])
    if not isinstance(extracted_iocs, list):
        logger.warning("Report 'extracted_iocs' is not a list.")
        return False

    domains = set()
    ips = set()

    for ioc in extracted_iocs:
        if not isinstance(ioc, str):
            continue
        ioc_clean = ioc.strip()
        if not ioc_clean:
            continue
        if is_ip_address(ioc_clean):
            ips.add(ioc_clean)
        else:
            if "." in ioc_clean and " " not in ioc_clean:
                domains.add(ioc_clean)

    if not domains and not ips:
        logger.warning("No valid domains or IP addresses found in the report.")
        return False

    added_domains = 0
    added_ips = 0

    if domains:
        added_domains += update_pihole_list(output_dir, domains)
        added_domains += update_hosts_list(output_dir, domains)

    if ips:
        added_ips += update_firewall_script(output_dir, ips)

    logger.info("Successfully processed actionable SAF report. Merged %d new domains, %d new IPs.", added_domains // 2, added_ips)
    return True


class SAFWebhookHandler(BaseHTTPRequestHandler):
    """
    Request handler for webhook receiver.
    """
    def do_POST(self) -> None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Empty request body.")
            return

        body = self.rfile.read(content_length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON payload.")
            return

        try:
            processed = process_report_data(payload, self.server.output_dir)  # type: ignore
            if processed:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {"status": "success", "message": "Report processed successfully."}
                self.wfile.write(json.dumps(response).encode("utf-8"))
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                response = {"status": "ignored", "message": "Report was not actionable or had no IOCs."}
                self.wfile.write(json.dumps(response).encode("utf-8"))
        except Exception as e:
            logger.exception("Error processing webhook payload")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Internal error: {e}".encode("utf-8"))


class SAFHTTPServer(HTTPServer):
    """
    Subclass HTTPServer to store output_dir configuration.
    """
    def __init__(self, server_address: tuple[str, int], RequestHandlerClass: type[BaseHTTPRequestHandler], output_dir: Path):
        super().__init__(server_address, RequestHandlerClass)
        self.output_dir = output_dir


def watch_directory(watch_dir: Path, output_dir: Path, interval: float = 2.0) -> None:
    """
    Continuously polls a directory for newly created/modified SAF JSON report files.
    """
    logger.info("Starting WATCH mode on directory: %s", watch_dir)
    logger.info("Generating defense artifacts in: %s", output_dir)

    if not watch_dir.exists():
        try:
            watch_dir.mkdir(parents=True, exist_ok=True)
            logger.info("Created watch directory at %s", watch_dir)
        except Exception as e:
            logger.error("Could not create watch directory: %s", e)
            sys.exit(1)

    processed_files: set[Path] = set()

    try:
        while True:
            for filepath in watch_dir.glob("*.json"):
                if filepath not in processed_files:
                    logger.info("Found new file: %s", filepath.name)
                    try:
                        with open(filepath, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        process_report_data(data, output_dir)
                    except json.JSONDecodeError:
                        logger.warning("Skipping file %s; failed to parse valid JSON.", filepath.name)
                    except Exception as e:
                        logger.error("Error processing file %s: %s", filepath.name, e)
                    processed_files.add(filepath)
            time.sleep(interval)
    except KeyboardInterrupt:
        logger.info("Stopping watch mode.")


def run_server(host: str, port: int, output_dir: Path) -> None:
    """
    Starts the lightweight HTTP server to act as a webhook receiver.
    """
    logger.info("Starting SERVER mode listening on %s:%d", host, port)
    logger.info("Generating defense artifacts in: %s", output_dir)

    server_address = (host, port)
    try:
        httpd = SAFHTTPServer(server_address, SAFWebhookHandler, output_dir)
        logger.info("Webhook server running. Send SAF actionable reports (JSON) as POST requests.")
        logger.info("Example: curl -X POST -H \"Content-Type: application/json\" -d @report.json http://%s:%d/", host, port)
        httpd.serve_forever()
    except KeyboardInterrupt:
        logger.info("Stopping webhook server.")
    except Exception as e:
        logger.error("Failed to start server: %s", e)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SAF Local Defensive Plugin - Integrate SAF with local personal computer & network defenses.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples of usage:
  Watch a local directory for incoming SAF reports:
    python examples/local_defensive_plugin.py watch --watch-dir /tmp/saf_reports --output-dir ./local_defense

  Start a webhook server to receive live reports from SAF pipelines:
    python examples/local_defensive_plugin.py server --port 8080 --output-dir ./local_defense
""",
    )

    subparsers = parser.add_subparsers(dest="mode", required=True, help="Plugin operation mode.")

    # Watch parser
    watch_parser = subparsers.add_parser("watch", help="Watch a directory for SAF JSON report files.")
    watch_parser.add_argument(
        "--watch-dir",
        type=Path,
        default=Path("/tmp/saf_reports"),
        help="Directory path to watch for JSON files (default: /tmp/saf_reports).",
    )
    watch_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./local_defense_output"),
        help="Directory where defense lists/scripts will be generated.",
    )
    watch_parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Directory poll interval in seconds (default: 2.0).",
    )

    # Server parser
    server_parser = subparsers.add_parser("server", help="Start an HTTP webhook server to receive SAF reports.")
    server_parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address to bind the server to (default: 127.0.0.1).",
    )
    server_parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port to bind the server to (default: 8080).",
    )
    server_parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./local_defense_output"),
        help="Directory where defense lists/scripts will be generated.",
    )

    args = parser.parse_args()

    if args.mode == "watch":
        watch_directory(args.watch_dir, args.output_dir, args.interval)
    elif args.mode == "server":
        run_server(args.host, args.port, args.output_dir)


if __name__ == "__main__":
    main()
