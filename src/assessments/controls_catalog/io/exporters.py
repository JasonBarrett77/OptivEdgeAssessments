"""Catalog export helpers."""

from __future__ import annotations

from assessments.controls_catalog.schemas import (
    CATALOG_PAYLOAD_TYPE,
    CATALOG_SEED_TYPE,
    SUPPORTED_SCHEMA_VERSION,
    validate_catalog_payload,
    validate_catalog_seed_payload,
)
from assessments.models import Catalog, Control


def export_control_catalog(*, key: str, label: str, version: str, description: str) -> dict:
    controls = (
        Control.objects.prefetch_related("queries")
        .order_by("control_id", "pk")
    )
    payload = {
        "type": CATALOG_PAYLOAD_TYPE,
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "catalog": {
            "key": key,
            "label": label,
            "version": version,
            "description": description,
        },
        "controls": [],
    }

    for control in controls:
        control_payload = {
            "control_id": control.control_id,
            "name": control.name,
            "control_type": control.control_type,
            "description": control.description,
            "rationale": control.rationale,
            "audit": control.audit,
            "remediation": control.remediation,
            "default_severity": control.default_severity,
            "implementation_version": control.implementation_version,
            "target_model": control.target_model,
            "is_active": control.is_active,
            "queries": [],
        }
        for query in control.queries.order_by("-is_baseline", "name", "pk"):
            control_payload["queries"].append(
                {
                    "name": query.name,
                    "short_description": query.short_description,
                    "canonical_query": query.canonical_query,
                    "is_baseline": query.is_baseline,
                    "adjusted_severity": query.adjusted_severity,
                    "is_active": query.is_active,
                }
            )
        payload["controls"].append(control_payload)

    return validate_catalog_payload(payload)


def export_catalog_seed_payload(*, catalogs=None) -> dict:
    catalog_rows = list(catalogs if catalogs is not None else Catalog.objects.order_by("pk"))
    payload = {
        "type": CATALOG_SEED_TYPE,
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "catalogs": [catalog.payload for catalog in catalog_rows],
    }
    return validate_catalog_seed_payload(payload)
