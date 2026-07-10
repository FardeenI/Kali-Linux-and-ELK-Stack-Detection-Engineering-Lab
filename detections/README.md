# Detections

TOML-formatted detection rules for Elastic Security's Detection Engine, mapped to MITRE ATT&CK. Each file's fields correspond directly to the Kibana [`createRule`](https://www.elastic.co/docs/api/doc/kibana/operation/operation-createrule) API request body.

## Structure

- `templates/` — one template per rule type (`query`, `eql`, `threshold`), showing every required field and the common optional ones. Copy the template matching your rule type as a starting point for a new detection.
- Top-level `*.toml` files — the actual detection rules deployed to the lab's SIEM.

## Required fields by rule type

| Field | query | eql | threshold | Notes |
|---|---|---|---|---|
| `name`, `description`, `type`, `risk_score`, `severity` | ✓ | ✓ | ✓ | required for every rule type |
| `rule_id` | ✓ | ✓ | ✓ | UUID, must be unique. Generate with `python -c "import uuid; print(uuid.uuid4())"` |
| `index` | ✓ | ✓ | ✓ | array of index patterns to search, e.g. `["winlogbeat-*"]` |
| `query` | ✓ | ✓ | ✓ | KQL (query), EQL (eql), or base filter (threshold) |
| `language` | | ✓ (`"eql"`) | | literal required value for eql rules |
| `threshold` | | | ✓ | table with `field` (array, `[]` for "All results"/no grouping) and `value` (int) |

Optional fields with Elastic-side defaults if omitted: `enabled` (true), `interval` (`"5m"`), `from` (`"now-6m"`), `max_signals` (100), `tags` (array).

`threshold.cardinality` is optional — an array of `{field, value}` tables, used when a threshold rule also requires a minimum count of *distinct* values (Kibana's "count distinct values of" option). Only include it if the rule actually sets this in Kibana; `field = []` on `rule.threshold` is not the same thing and just means no grouping.

We standardize on `index = [...]` rather than Kibana's exported `data_view_id`, since `index` is self-contained for the `createRule` API and doesn't depend on a pre-existing Data View saved object — useful if the SIEM is ever rebuilt from Terraform.

`[[rule.threat]]` (MITRE ATT&CK mapping) isn't strictly required by the API, but every detection in this repo must include one — validated by `development/mitre.py` against the live MITRE ATT&CK STIX dataset.

## Adding a new detection

1. Copy the template matching your rule type from `templates/`.
2. Fill in `name`, `description`, a fresh `rule_id`, your query logic, and the correct MITRE ATT&CK technique/tactic.
3. Run `python development/validation.py` to check required fields.
4. Run `python development/mitre.py` to verify the MITRE mapping is accurate.
