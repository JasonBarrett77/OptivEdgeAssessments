"""Validation for control catalog payloads and seed artifacts."""

from __future__ import annotations

from django.core.exceptions import ValidationError

from assessments.models import Control
from assessments.search.exceptions import SearchSyntaxError
from assessments.search.syntax import validate_search_payload


CATALOG_PAYLOAD_TYPE = "optivedge.assessments.catalog"
CATALOG_SEED_TYPE = "optivedge.assessments.catalog_seed"
SUPPORTED_SCHEMA_VERSION = "1.0"


def _raise_validation_error(message: str) -> None:
    raise ValidationError(message)


def _require_string(mapping: dict, key: str, *, context: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        _raise_validation_error(f"{context} must include a non-empty '{key}' string.")
    return value.strip()


def _require_bool(mapping: dict, key: str, *, context: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        _raise_validation_error(f"{context} must include a boolean '{key}'.")
    return value


def _validate_catalog_metadata(metadata: dict) -> dict:
    if not isinstance(metadata, dict):
        _raise_validation_error("Catalog payload 'catalog' must be an object.")
    return {
        "key": _require_string(metadata, "key", context="Catalog metadata"),
        "label": _require_string(metadata, "label", context="Catalog metadata"),
        "version": _require_string(metadata, "version", context="Catalog metadata"),
        "description": str(metadata.get("description", "") or ""),
    }


def _validate_canonical_query(payload: dict, *, context: str) -> dict:
    if not isinstance(payload, dict):
        _raise_validation_error(f"{context} canonical_query must be an object.")
    try:
        return validate_search_payload(payload)
    except SearchSyntaxError as exc:
        raise ValidationError(f"{context} canonical_query is invalid: {exc}") from exc


def _validate_query_payload(query_payload: dict, *, control_id: str) -> dict:
    if not isinstance(query_payload, dict):
        _raise_validation_error(f"Control '{control_id}' query must be an object.")

    name = _require_string(query_payload, "name", context=f"Control '{control_id}' query")
    normalized_query = {
        "name": name,
        "short_description": str(query_payload.get("short_description", "") or ""),
        "canonical_query": _validate_canonical_query(
            query_payload.get("canonical_query"),
            context=f"Control '{control_id}' query '{name}'",
        ),
        "is_baseline": _require_bool(
            query_payload,
            "is_baseline",
            context=f"Control '{control_id}' query '{name}'",
        ),
        "adjusted_severity": query_payload.get("adjusted_severity"),
        "is_active": _require_bool(
            query_payload,
            "is_active",
            context=f"Control '{control_id}' query '{name}'",
        ),
    }

    adjusted_severity = normalized_query["adjusted_severity"]
    if adjusted_severity not in (None, "") and adjusted_severity not in Control.Severity.values:
        _raise_validation_error(
            f"Control '{control_id}' query '{name}' adjusted_severity must be a supported severity."
        )
    if normalized_query["is_baseline"] and adjusted_severity not in (None, ""):
        _raise_validation_error(
            f"Control '{control_id}' query '{name}' cannot define adjusted_severity when is_baseline is true."
        )
    normalized_query["adjusted_severity"] = adjusted_severity or None
    return normalized_query


def _validate_control_payload(control_payload: dict) -> dict:
    if not isinstance(control_payload, dict):
        _raise_validation_error("Each control entry must be an object.")

    control_id = _require_string(control_payload, "control_id", context="Control")
    control_type = _require_string(control_payload, "control_type", context=f"Control '{control_id}'")
    default_severity = _require_string(
        control_payload,
        "default_severity",
        context=f"Control '{control_id}'",
    )
    if control_type not in Control.ControlType.values:
        _raise_validation_error(f"Control '{control_id}' has unsupported control_type '{control_type}'.")
    if default_severity not in Control.Severity.values:
        _raise_validation_error(
            f"Control '{control_id}' has unsupported default_severity '{default_severity}'."
        )

    queries = control_payload.get("queries")
    if not isinstance(queries, list):
        _raise_validation_error(f"Control '{control_id}' must include a 'queries' list.")

    normalized_queries = []
    seen_query_names: set[str] = set()
    for query_payload in queries:
        normalized_query = _validate_query_payload(query_payload, control_id=control_id)
        if normalized_query["name"] in seen_query_names:
            _raise_validation_error(
                f"Control '{control_id}' contains duplicate query name '{normalized_query['name']}'."
            )
        seen_query_names.add(normalized_query["name"])
        normalized_queries.append(normalized_query)

    return {
        "control_id": control_id,
        "name": _require_string(control_payload, "name", context=f"Control '{control_id}'"),
        "control_type": control_type,
        "description": _require_string(
            control_payload,
            "description",
            context=f"Control '{control_id}'",
        ),
        "rationale": str(control_payload.get("rationale", "") or ""),
        "audit": str(control_payload.get("audit", "") or ""),
        "remediation": str(control_payload.get("remediation", "") or ""),
        "default_severity": default_severity,
        "implementation_version": str(control_payload.get("implementation_version", "v1") or "v1"),
        "is_active": _require_bool(
            control_payload,
            "is_active",
            context=f"Control '{control_id}'",
        ),
        "queries": normalized_queries,
    }


def validate_catalog_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        _raise_validation_error("Catalog payload must be an object.")
    if payload.get("type") != CATALOG_PAYLOAD_TYPE:
        _raise_validation_error(f"Catalog payload type must be '{CATALOG_PAYLOAD_TYPE}'.")
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        _raise_validation_error(
            f"Catalog payload schema_version must be '{SUPPORTED_SCHEMA_VERSION}'."
        )

    controls = payload.get("controls")
    if not isinstance(controls, list):
        _raise_validation_error("Catalog payload must include a 'controls' list.")

    normalized_controls = []
    seen_control_ids: set[str] = set()
    for control_payload in controls:
        normalized_control = _validate_control_payload(control_payload)
        if normalized_control["control_id"] in seen_control_ids:
            _raise_validation_error(
                f"Catalog payload contains duplicate control_id '{normalized_control['control_id']}'."
            )
        seen_control_ids.add(normalized_control["control_id"])
        normalized_controls.append(normalized_control)

    return {
        "type": CATALOG_PAYLOAD_TYPE,
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "catalog": _validate_catalog_metadata(payload.get("catalog")),
        "controls": normalized_controls,
    }


def validate_catalog_seed_payload(payload: dict) -> dict:
    if not isinstance(payload, dict):
        _raise_validation_error("Catalog seed payload must be an object.")
    if payload.get("type") != CATALOG_SEED_TYPE:
        _raise_validation_error(f"Catalog seed payload type must be '{CATALOG_SEED_TYPE}'.")
    if payload.get("schema_version") != SUPPORTED_SCHEMA_VERSION:
        _raise_validation_error(
            f"Catalog seed payload schema_version must be '{SUPPORTED_SCHEMA_VERSION}'."
        )

    catalogs = payload.get("catalogs")
    if not isinstance(catalogs, list):
        _raise_validation_error("Catalog seed payload must include a 'catalogs' list.")

    normalized_catalogs = []
    seen_keys: set[str] = set()
    for catalog_payload in catalogs:
        normalized_catalog = validate_catalog_payload(catalog_payload)
        catalog_key = normalized_catalog["catalog"]["key"]
        if catalog_key in seen_keys:
            _raise_validation_error(
                f"Catalog seed payload contains duplicate catalog key '{catalog_key}'."
            )
        seen_keys.add(catalog_key)
        normalized_catalogs.append(normalized_catalog)

    return {
        "type": CATALOG_SEED_TYPE,
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "catalogs": normalized_catalogs,
    }
