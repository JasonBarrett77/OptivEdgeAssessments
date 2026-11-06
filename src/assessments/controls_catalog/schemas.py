"""Validation for control catalog payloads and seed artifacts."""

from __future__ import annotations

import re

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


#: The longest a `short_remediation` may be. Measured on the built document 2026-11-06: at this
#: length the Summary of Findings table falls from about 12.6 pages to 5, and the Recommendation
#: column stops being what sets the height of any row - so a tighter cap would buy nothing.
SHORT_REMEDIATION_LIMIT = 100

#: What a client-facing recommendation must not contain. A backtick or an angle bracket is a
#: command or a UI path; a control id is this application's own vocabulary, which the Finding
#: column beside it already carries.
_NOT_FOR_A_CLIENT = (
    ("`", "a command or a quoted setting"),
    (">", "a UI path"),
)
_CONTROL_ID = re.compile(r"\b[A-Z]{2,4}-[A-Z]{2,5}-\d{3}\b")
#: A full stop that ends a sentence, as opposed to the one in `TLS 1.2`.
_SENTENCE_END = re.compile(r"\.(?:\s|$)")


def _validate_short_remediation(control_payload: dict, control_id: str, is_active: bool,
                                *, required: bool) -> str:
    """The one-sentence recommendation the health check document prints, and its rules.

    WHY IT IS CHECKED HERE. This is the only sentence of a control that a CLIENT reads - the
    Summary of Findings and Recommendations table, on the page after the executive summary - and
    the thing it replaced was `remediation`, which on 96 of the 218 controls opens with a CLI
    command or a UI path. A control added tomorrow with no short line, or with its full
    remediation pasted in, would put that straight back in front of a client. Refusing the
    CATALOGUE is what makes that impossible, rather than a test that a new control's author has
    to know to run.

    An INACTIVE control is exempt: it is graded by nothing, so it reaches no document.

    SO IS A SNAPSHOT, which is the reason `required` exists. `exporters.export_control_catalog`
    builds a payload out of the controls ALREADY IN THE DATABASE - `apply_catalog` takes one as
    a backup before it replaces them. On a deployment upgraded from a release before this field,
    those rows carry nothing, and refusing their snapshot would refuse the upgrade itself. A
    record of what is already there is not a proposal for what to ship. The FORMAT rules below
    still apply either way: a line that exists must be fit to print.
    """
    value = str(control_payload.get("short_remediation", "") or "").strip()
    context = f"Control '{control_id}'"
    if not value:
        if not is_active or not required:
            return ""
        _raise_validation_error(
            f"{context} must include a 'short_remediation': one imperative sentence of "
            f"{SHORT_REMEDIATION_LIMIT} characters or fewer, naming the change rather than the "
            f"steps. It is what a client reads in the health check document.")
    if len(value) > SHORT_REMEDIATION_LIMIT:
        _raise_validation_error(
            f"{context} has a 'short_remediation' of {len(value)} characters; the limit is "
            f"{SHORT_REMEDIATION_LIMIT}. The full instruction belongs in 'remediation'.")
    if len(_SENTENCE_END.findall(value)) != 1 or not value.endswith("."):
        _raise_validation_error(
            f"{context} must have a 'short_remediation' of exactly one sentence, ending in a "
            f"full stop.")
    for mark, what in _NOT_FOR_A_CLIENT:
        if mark in value:
            _raise_validation_error(
                f"{context} has {what} in its 'short_remediation'. That belongs in "
                f"'remediation', which the remediation pages and the findings workbook print.")
    if _CONTROL_ID.search(value):
        _raise_validation_error(
            f"{context} names a control id in its 'short_remediation'. The column beside it in "
            f"the document already carries one.")
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
        "asserted_fields": [
            str(field) for field in (query_payload.get("asserted_fields") or [])
            if str(field).strip()
        ],
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


def _validate_control_payload(control_payload: dict, *,
                              require_short_remediation: bool = True) -> dict:
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

    target_model = str(control_payload.get("target_model", "") or "")

    _RECOGNIZED_TYPE_TARGET_MODEL = {
        "security_rule": "integrations.SecurityRule",
        "config": "",
    }
    if control_type in _RECOGNIZED_TYPE_TARGET_MODEL:
        expected = _RECOGNIZED_TYPE_TARGET_MODEL[control_type]
        if target_model != expected:
            _raise_validation_error(
                f"Control '{control_id}' has control_type '{control_type}' which requires "
                f"target_model '{expected}' but got '{target_model}'."
            )

    if target_model:
        for query in normalized_queries:
            q_model = query["canonical_query"].get("model")
            if q_model != target_model:
                _raise_validation_error(
                    f"Control '{control_id}' query '{query['name']}' targets "
                    f"{q_model!r} but control target_model is '{target_model}'."
                )

    is_active = _require_bool(control_payload, "is_active", context=f"Control '{control_id}'")

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
        "short_remediation": _validate_short_remediation(
            control_payload, control_id, is_active, required=require_short_remediation),
        #: The severity a finding reports when only the baseline query matched. A non-baseline
        #: query's `adjusted_severity` overrides it, worst match winning.
        "default_severity": default_severity,
        "implementation_version": str(control_payload.get("implementation_version", "v1") or "v1"),
        "target_model": target_model,
        "is_active": is_active,
        "queries": normalized_queries,
    }


def validate_catalog_payload(payload: dict, *, require_short_remediation: bool = True) -> dict:
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
        normalized_control = _validate_control_payload(
            control_payload, require_short_remediation=require_short_remediation)
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
