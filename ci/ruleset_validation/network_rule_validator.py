import sys
import argparse
from pathlib import Path

def lint_network_rule(file_path: Path) -> bool:
    """
    Validates generic network rules (like Suricata/Snort) for synthetic policy adherence.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except (FileNotFoundError, PermissionError, OSError) as e:
        print(f"❌ {file_path} failed validation: {e}")
        return False

    errors = []

    # Check for basic synthetic markers
    lower_content = content.lower()
    if "synthetic" not in lower_content and "example" not in lower_content:
        errors.append("POLICY VIOLATION: Rule does not contain 'synthetic' or 'example' markers. Real IOCs are prohibited.")

    if errors:
        print(f"❌ {file_path} failed validation:")
        for error in errors:
            print(f"  - {error}")
        return False

    print(f"✅ {file_path} passed.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Rule Validator")
    parser.add_argument("files", nargs="+", type=Path, help="Network rule files to lint")
    args = parser.parse_args()

    all_passed = True
    for file in args.files:
        if not lint_network_rule(file):
            all_passed = False

    if not all_passed:
        sys.exit(1)
    sys.exit(0)
