"""Structured output schema for plain-language security-rule translation."""

from __future__ import annotations

from functools import lru_cache

from assessments.search.security_rules.compiler import (
    FIELD_OPERATOR_REGISTRY,
    SECURITY_RULE_MODEL,
)


COMMON_BOOLEAN_PROPERTIES = {
    "negated": {"type": "boolean"},
    "case_sensitive": {"type": "boolean"},
    "include_any": {"type": "boolean"},
}


def build_field_clause_schema(field_name: str, supported_operators: set[str]) -> dict:
    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "field": {"type": "string", "const": field_name},
            "op": {
                "type": "string",
                "enum": sorted(supported_operators),
            },
            "value": {"type": "string"},
            **COMMON_BOOLEAN_PROPERTIES,
        },
        "required": ["field", "op", "value", "negated", "case_sensitive", "include_any"],
    }


@lru_cache(maxsize=1)
def build_security_rule_query_json_schema() -> dict:
    clause_schemas = [
        build_field_clause_schema(field_name, supported_operators)
        for field_name, supported_operators in sorted(FIELD_OPERATOR_REGISTRY.items())
    ]
    return {
        "name": "security_rule_search_query",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "model": {"type": "string", "const": SECURITY_RULE_MODEL},
                "operator": {"type": "string", "enum": ["and", "or"]},
                "clauses": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/node"},
                },
            },
            "required": ["model", "operator", "clauses"],
            "$defs": {
                "group": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "operator": {"type": "string", "enum": ["and", "or"]},
                        "clauses": {
                            "type": "array",
                            "items": {"$ref": "#/$defs/node"},
                        },
                    },
                    "required": ["operator", "clauses"],
                },
                "node": {
                    "anyOf": [
                        {"$ref": "#/$defs/group"},
                        *clause_schemas,
                    ]
                },
            },
        },
    }
