"""
Build JSON payloads from detection TOML files and upload them to Kibana's
Detection Engine via the createRule API:
https://www.elastic.co/docs/api/doc/kibana/operation/operation-createrule

Each detection's [rule] table is already shaped to match the API request
body 1:1 (see detections/README.md), so the payload is just that table
passed through as JSON. If a rule_id already exists in Kibana (expected -
these detections were exported from manually-built rules), the create
attempt's 409 triggers a fallback update instead.

Usage:
    python development/upload_to_elastic.py [--dry-run] [--detections-dir PATH]

Environment Variables:
    ELASTIC_URL:      Kibana base URL, e.g. http://<ubuntu-public-ip>:5601
                       (no default - the lab's IP changes on every terraform
                       apply, so a stale hardcoded default would silently
                       point at the wrong host)
    ELASTIC_USERNAME:  Kibana username (defaults to "labadmin")
    ELASTIC_PASSWORD:  Kibana password for ELASTIC_USERNAME
                       (terraform output -raw kibana_admin_password)
"""
import argparse
import json
import os
import sys
import tomllib
from pathlib import Path

import requests

from schema import SUPPORTED_RULE_TYPES

RULES_PATH = "/api/detection_engine/rules"


def load_detection(file_path: Path) -> dict:
    with open(file_path, "rb") as f:
        return tomllib.load(f)


def build_payload(alert: dict) -> dict | None:
    """Return the rule.* table as-is - it's already shaped to match the API."""
    rule = alert.get("rule", {})
    if rule.get("type") not in SUPPORTED_RULE_TYPES:
        return None
    return dict(rule)


def upsert_rule(session: requests.Session, base_url: str, payload: dict) -> dict:
    """POST to create; on 409 (rule_id already exists), PUT to update instead."""
    url = base_url.rstrip("/") + RULES_PATH

    response = session.post(url, json=payload)
    if response.status_code == 409:
        response = session.put(url, json=payload)
    response.raise_for_status()
    return response.json()


def main():
    parser = argparse.ArgumentParser(description="Upload TOML detections to Elastic Security")
    parser.add_argument("--dry-run", action="store_true", help="Print payloads without uploading")
    parser.add_argument("--detections-dir", default="detections", help="Path to detections directory")
    args = parser.parse_args()

    detections_path = Path(args.detections_dir)
    if not detections_path.exists():
        print(f"Error: detections directory not found: {detections_path}", file=sys.stderr)
        sys.exit(1)

    session = None
    base_url = None

    if not args.dry_run:
        base_url = os.environ.get("ELASTIC_URL")
        password = os.environ.get("ELASTIC_PASSWORD")

        if not base_url:
            print("Error: ELASTIC_URL environment variable not set", file=sys.stderr)
            sys.exit(1)
        if not password:
            print("Error: ELASTIC_PASSWORD environment variable not set", file=sys.stderr)
            sys.exit(1)

        username = os.environ.get("ELASTIC_USERNAME", "labadmin")

        session = requests.Session()
        session.auth = (username, password)
        session.headers.update({
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
        })

    failure = False

    for toml_file in sorted(detections_path.glob("*.toml")):
        print(f"Processing: {toml_file}")

        try:
            alert = load_detection(toml_file)
            payload = build_payload(alert)

            if payload is None:
                rule_type = alert.get("rule", {}).get("type", "unknown")
                print(f"  Skipped: unsupported rule type {rule_type!r}")
                continue

            if args.dry_run:
                print(f"  Payload: {json.dumps(payload, indent=2)}")
            else:
                result = upsert_rule(session, base_url, payload)
                print(f"  Uploaded: {result.get('name', 'unknown')} ({result.get('id', 'no-id')})")

        except requests.RequestException as e:
            failure = True
            print(f"  Error uploading: {e}", file=sys.stderr)
        except Exception as e:
            failure = True
            print(f"  Error processing: {e}", file=sys.stderr)

    if failure:
        sys.exit(1)


if __name__ == "__main__":
    main()
