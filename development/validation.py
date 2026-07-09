"""
Validate detection TOML files in detections/ against schema.py: valid TOML
syntax, required fields for the rule's type, threshold sub-fields, a
present MITRE ATT&CK mapping, and unique rule_ids across the repo.

Usage:
    python development/validation.py [--detections-dir PATH]
"""
import argparse
import sys
import tomllib
import uuid
from pathlib import Path

from schema import SUPPORTED_RULE_TYPES, THRESHOLD_REQUIRED_FIELDS, required_fields_for


def is_valid_uuid(value: str) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def validate_file(path: Path) -> list[str]:
    """Return a list of error strings for this file (empty if valid)."""
    errors = []

    try:
        with open(path, "rb") as f:
            alert = tomllib.load(f)
    except tomllib.TOMLDecodeError as e:
        return [f"invalid TOML syntax: {e}"]

    if "creation_date" not in alert.get("metadata", {}):
        errors.append("metadata table is missing creation_date")

    rule = alert.get("rule", {})
    rule_type = rule.get("type")

    if rule_type not in SUPPORTED_RULE_TYPES:
        errors.append(f"unsupported or missing rule.type: {rule_type!r}")
        return errors  # can't check type-specific fields without a known type

    for field in required_fields_for(rule_type):
        if field not in rule:
            errors.append(f"rule.{field} is required for type '{rule_type}' but missing")

    if rule_type == "threshold" and "threshold" in rule:
        for field in THRESHOLD_REQUIRED_FIELDS:
            if field not in rule["threshold"]:
                errors.append(f"rule.threshold.{field} is required but missing")

    if "rule_id" in rule and not is_valid_uuid(rule["rule_id"]):
        errors.append(f"rule_id is not a valid UUID: {rule['rule_id']!r}")

    if not rule.get("threat"):
        errors.append("rule.threat (MITRE ATT&CK mapping) is required but missing or empty")

    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate detection TOML files")
    parser.add_argument("--detections-dir", default="detections", help="Path to detections directory")
    args = parser.parse_args()

    detections_path = Path(args.detections_dir)
    if not detections_path.exists():
        print(f"Error: detections directory not found: {detections_path}", file=sys.stderr)
        sys.exit(1)

    failure = False
    seen_rule_ids: dict[str, Path] = {}

    for toml_file in sorted(detections_path.glob("*.toml")):
        errors = validate_file(toml_file)

        if not errors:
            try:
                with open(toml_file, "rb") as f:
                    rule_id = tomllib.load(f).get("rule", {}).get("rule_id")
            except tomllib.TOMLDecodeError:
                rule_id = None

            if rule_id in seen_rule_ids:
                errors.append(f"duplicate rule_id, already used by {seen_rule_ids[rule_id]}")
            elif rule_id:
                seen_rule_ids[rule_id] = toml_file

        if errors:
            failure = True
            print(f"FAIL: {toml_file}")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"PASS: {toml_file}")

    if failure:
        sys.exit(1)


if __name__ == "__main__":
    main()
