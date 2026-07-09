"""
Single source of truth for what a valid detection TOML file must contain,
per the Kibana createRule API (rule.type-dependent):
https://www.elastic.co/docs/api/doc/kibana/operation/operation-createrule
"""

SUPPORTED_RULE_TYPES = ("query", "eql", "threshold")

# Fields required on every rule regardless of type.
COMMON_REQUIRED_FIELDS = (
    "name",
    "description",
    "type",
    "risk_score",
    "severity",
    "rule_id",
)

# Additional fields required per rule.type.
TYPE_REQUIRED_FIELDS = {
    "query": ("index", "query"),
    "eql": ("index", "query", "language"),
    "threshold": ("index", "query", "threshold"),
}

# Sub-fields required within the rule.threshold table, when type == "threshold".
THRESHOLD_REQUIRED_FIELDS = ("field", "value")


def required_fields_for(rule_type: str) -> tuple[str, ...]:
    """All required top-level rule.* fields for a given rule type."""
    return COMMON_REQUIRED_FIELDS + TYPE_REQUIRED_FIELDS.get(rule_type, ())
