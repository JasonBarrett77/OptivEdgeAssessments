"""Canonical search syntax validation."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.registry import get_model_entry


def validate_search_payload(node):
    """Validate a canonical search payload and return a normalized copy."""
    if not isinstance(node, dict):
        raise SearchSyntaxError("Search root must be an object.")
    if "operator" not in node:
        raise SearchSyntaxError("Search root must be a group.")
    return validate_search_group(node, is_root=True)


def validate_search_group(group, *, is_root=False, model_name=None):
    allowed_keys = {"operator", "clauses", "model"} if is_root else {"operator", "clauses"}
    if set(group.keys()) != allowed_keys:
        if is_root:
            raise SearchSyntaxError(
                "Search root group must only contain 'model', 'operator', and 'clauses'."
            )
        raise SearchSyntaxError("Search group must only contain 'operator' and 'clauses'.")

    if is_root:
        raw_model_name = group.get("model")
        if not isinstance(raw_model_name, str) or not raw_model_name:
            raise SearchSyntaxError("Search root must include a non-empty 'model' string.")
        model_name = raw_model_name
        get_model_entry(model_name)

    operator = group["operator"]
    if operator not in {"and", "or"}:
        raise SearchSyntaxError("Search group operator must be 'and' or 'or'.")

    clauses = group["clauses"]
    if not isinstance(clauses, list) or not clauses:
        raise SearchSyntaxError("Search group must contain a non-empty 'clauses' list.")

    return {
        **({"model": model_name} if is_root else {}),
        "operator": operator,
        "clauses": [
            validate_search_group(clause, is_root=False, model_name=model_name)
            if isinstance(clause, dict) and "operator" in clause
            else validate_search_clause(clause, model_name=model_name)
            for clause in clauses
        ],
    }


def validate_search_clause(clause, *, model_name):
    if not isinstance(clause, dict):
        raise SearchSyntaxError("Search clause must be an object.")
    required_keys = {"field", "op", "value"}
    optional_keys = {"negated", "case_sensitive", "include_any"}
    unknown_keys = set(clause.keys()) - required_keys - optional_keys
    if unknown_keys:
        raise SearchSyntaxError(
            f"Search clause contains unsupported keys: {', '.join(sorted(unknown_keys))}."
        )
    if not required_keys.issubset(clause.keys()):
        missing_keys = required_keys - set(clause.keys())
        raise SearchSyntaxError(
            f"Search clause is missing required keys: {', '.join(sorted(missing_keys))}."
        )

    field = clause["field"]
    op = clause["op"]
    value = clause["value"]
    negated = clause.get("negated", False)
    case_sensitive = clause.get("case_sensitive", False)
    include_any = clause.get("include_any", False)

    if not isinstance(field, str) or not field:
        raise SearchSyntaxError("Search clause 'field' must be a non-empty string.")
    if not isinstance(op, str) or not op:
        raise SearchSyntaxError("Search clause 'op' must be a non-empty string.")
    model_entry = get_model_entry(model_name)
    field_operators = model_entry["field_operators"]
    if field not in field_operators:
        raise SearchSyntaxError(f"Unsupported search field for {model_name}: {field}.")
    if op not in field_operators[field]:
        raise SearchSyntaxError(f"Unsupported operator for {model_name}.{field}: {op}.")
    if not isinstance(negated, bool):
        raise SearchSyntaxError("Search clause 'negated' must be a boolean.")
    if not isinstance(case_sensitive, bool):
        raise SearchSyntaxError("Search clause 'case_sensitive' must be a boolean.")
    if not isinstance(include_any, bool):
        raise SearchSyntaxError("Search clause 'include_any' must be a boolean.")

    return {
        "field": field,
        "op": op,
        "value": value,
        "negated": negated,
        "case_sensitive": case_sensitive,
        "include_any": include_any,
    }
