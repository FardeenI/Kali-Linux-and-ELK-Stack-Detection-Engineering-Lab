"""
Validate the [[rule.threat]] MITRE ATT&CK mappings in detections/*.toml
against the live MITRE ATT&CK Enterprise STIX dataset.

Checks per detection:
    - every technique/sub-technique id exists in the current ATT&CK dataset
    - the technique/sub-technique name matches MITRE's canonical name
    - the technique/sub-technique is not deprecated or revoked
    - the tactic id/name pair is a real ATT&CK tactic
    - the technique actually belongs to the claimed tactic (kill chain phase)

Usage:
    python development/mitre.py [--detections-dir PATH]
"""
import argparse
import sys
import tomllib
from pathlib import Path

import requests

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def load_attack_data(url: str = ATTACK_STIX_URL) -> tuple[dict, dict]:
    """
    Fetch the ATT&CK STIX bundle and return (technique_map, tactic_map).

    technique_map: {T-id: {"name", "phases": {shortnames}, "deprecated": bool}}
    tactic_map:    {TA-id: {"name", "shortname"}}
    """
    response = requests.get(url, headers={"accept": "application/json"})
    response.raise_for_status()
    stix_objects = response.json()["objects"]

    technique_map = {}
    tactic_map = {}

    for obj in stix_objects:
        external_refs = obj.get("external_references", [])
        attack_id = next(
            (ref["external_id"] for ref in external_refs if ref.get("external_id", "").startswith(("T", "TA"))),
            None,
        )
        if not attack_id:
            continue

        if obj["type"] == "attack-pattern" and attack_id.startswith("T"):
            phases = {phase["phase_name"] for phase in obj.get("kill_chain_phases", [])}
            technique_map[attack_id] = {
                "name": obj["name"],
                "phases": phases,
                "deprecated": bool(obj.get("x_mitre_deprecated") or obj.get("revoked")),
            }
        elif obj["type"] == "x-mitre-tactic" and attack_id.startswith("TA"):
            tactic_map[attack_id] = {
                "name": obj["name"],
                "shortname": obj.get("x_mitre_shortname", ""),
            }

    return technique_map, tactic_map


def validate_technique(technique: dict, technique_map: dict, tactic_shortname: str | None, label: str) -> list[str]:
    errors = []
    tid = technique.get("id")
    tname = technique.get("name")

    if tid not in technique_map:
        errors.append(f"unknown {label} id: {tid!r}")
        return errors

    canonical = technique_map[tid]

    if tname != canonical["name"]:
        errors.append(f"{label} {tid} name mismatch: expected {canonical['name']!r}, got {tname!r}")

    if canonical["deprecated"]:
        errors.append(f"{label} {tid} is deprecated/revoked in ATT&CK")

    if tactic_shortname and tactic_shortname not in canonical["phases"]:
        errors.append(
            f"{label} {tid} does not belong to the claimed tactic "
            f"(technique's phases: {sorted(canonical['phases'])})"
        )

    return errors


def validate_file(path: Path, technique_map: dict, tactic_map: dict) -> list[str]:
    errors = []

    with open(path, "rb") as f:
        alert = tomllib.load(f)

    for threat in alert.get("rule", {}).get("threat", []):
        if threat.get("framework") != "MITRE ATT&CK":
            continue

        tactic = threat.get("tactic")
        tactic_shortname = None

        if tactic:
            tac_id = tactic.get("id")
            tac_name = tactic.get("name")

            if tac_id not in tactic_map:
                errors.append(f"unknown tactic id: {tac_id!r}")
            else:
                canonical_tactic = tactic_map[tac_id]
                tactic_shortname = canonical_tactic["shortname"]
                if tac_name != canonical_tactic["name"]:
                    errors.append(f"tactic {tac_id} name mismatch: expected {canonical_tactic['name']!r}, got {tac_name!r}")

        for technique in threat.get("technique", []):
            errors.extend(validate_technique(technique, technique_map, tactic_shortname, "technique"))

            for subtechnique in technique.get("subtechnique", []):
                errors.extend(validate_technique(subtechnique, technique_map, tactic_shortname, "sub-technique"))

    return errors


def main():
    parser = argparse.ArgumentParser(description="Validate MITRE ATT&CK mappings in detection TOML files")
    parser.add_argument("--detections-dir", default="detections", help="Path to detections directory")
    args = parser.parse_args()

    detections_path = Path(args.detections_dir)
    if not detections_path.exists():
        print(f"Error: detections directory not found: {detections_path}", file=sys.stderr)
        sys.exit(1)

    print("Fetching MITRE ATT&CK Enterprise dataset...")
    technique_map, tactic_map = load_attack_data()

    failure = False

    for toml_file in sorted(detections_path.glob("*.toml")):
        errors = validate_file(toml_file, technique_map, tactic_map)

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
