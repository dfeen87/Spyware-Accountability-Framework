import sys
import re
import argparse
from pathlib import Path

def lint_yara(file_path: Path) -> bool:
    """
    Validates that a YARA rule adheres to the framework's synthetic-only policy.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"❌ {file_path} failed validation: {e}")
        return False

    errors = []

    # 1. Structural check
    if not re.search(r'rule\s+\w+\s*{', content):
        errors.append("Invalid YARA format: 'rule <name> {' missing.")

    if "condition:" not in content:
        errors.append("Invalid YARA format: 'condition:' missing.")

    # 2. Synthetic constraint check
    lower_content = content.lower()

    # Must contain 'synthetic' or 'example' as a safety mechanism
    if "synthetic" not in lower_content and "example" not in lower_content:
        errors.append("POLICY VIOLATION: Rule does not contain 'synthetic' or 'example' markers. Real IOCs are prohibited.")

    # Check for real IP addresses (basic heuristic)
    # This regex looks for IPs that are NOT in the synthetic/reserved ranges we allow (192.0.2.x, 198.51.100.x, 203.0.113.x, 10.x.x.x)
    ip_pattern = r'\b(?!(?:10|192\.0\.2|198\.51\.100|203\.0\.113)\.)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    real_ips = re.findall(ip_pattern, content)
    if real_ips:
        errors.append(f"POLICY VIOLATION: Possible real IP address found: {real_ips}. Only synthetic/reserved IPs are allowed.")

    if errors:
        print(f"❌ {file_path} failed validation:")
        for error in errors:
            print(f"  - {error}")
        return False

    print(f"✅ {file_path} passed.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="YARA Rule Linter")
    parser.add_argument("files", nargs="+", type=Path, help="YARA files to lint")
    args = parser.parse_args()

    all_passed = True
    for file in args.files:
        if not lint_yara(file):
            all_passed = False

    if not all_passed:
        sys.exit(1)
    sys.exit(0)
