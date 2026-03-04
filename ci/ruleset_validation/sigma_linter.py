import sys
import yaml
import argparse
from pathlib import Path

def lint_sigma(file_path: Path) -> bool:
    """
    Validates that a Sigma rule adheres to the framework's synthetic-only policy.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            rule = yaml.safe_load(f)
    except yaml.YAMLError as e:
        print(f"❌ {file_path} failed validation: Invalid YAML format - {e}")
        return False

    if not isinstance(rule, dict):
        print(f"❌ {file_path} failed validation: YAML did not parse to a mapping.")
        return False

    errors = []

    # 1. Structural check
    required_fields = ["title", "logsource", "detection"]
    for field in required_fields:
        if field not in rule:
            errors.append(f"Invalid Sigma format: missing required field '{field}'.")

    # 2. Synthetic constraint check
    rule_str = str(rule).lower()

    if "synthetic" not in rule_str and "example" not in rule_str:
        errors.append("POLICY VIOLATION: Rule does not contain 'synthetic' or 'example' markers. Real IOCs are prohibited.")

    if errors:
        print(f"❌ {file_path} failed validation:")
        for error in errors:
            print(f"  - {error}")
        return False

    print(f"✅ {file_path} passed.")
    return True

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sigma Rule Linter")
    parser.add_argument("files", nargs="+", type=Path, help="Sigma files to lint")
    args = parser.parse_args()

    all_passed = True
    for file in args.files:
        if not lint_sigma(file):
            all_passed = False

    if not all_passed:
        sys.exit(1)
    sys.exit(0)
