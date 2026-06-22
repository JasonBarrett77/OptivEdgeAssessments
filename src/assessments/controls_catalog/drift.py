"""Catalog drift detection via structural hash.

Computes a SHA-256 hash over the assessment-relevant fields of controls and
queries, sorted deterministically. Two hashes that match mean the live control
state is identical to the catalog payload for assessment purposes.

Fields included: control_id, control_type, default_severity, is_active,
implementation_version, and per-query name, canonical_query, is_baseline,
adjusted_severity, is_active.

Fields excluded: pk, created_at, updated_at, name, description, rationale,
audit, remediation, short_description — these do not affect query evaluation
or finding generation.
"""

from __future__ import annotations

import hashlib
import json

from assessments.models import Control


def _control_fingerprint(
    control_id: str,
    control_type: str,
    default_severity: str,
    is_active: bool,
    implementation_version: str,
    queries: list[dict],
) -> dict:
    return {
        "control_id": control_id,
        "control_type": control_type,
        "default_severity": default_severity,
        "is_active": is_active,
        "implementation_version": implementation_version,
        "queries": sorted(queries, key=lambda q: q["name"]),
    }


def _query_fingerprint(query: dict) -> dict:
    return {
        "name": query["name"],
        "canonical_query": query["canonical_query"],
        "is_baseline": query["is_baseline"],
        "adjusted_severity": query["adjusted_severity"],
        "is_active": query["is_active"],
    }


def _fingerprint_to_hash(fingerprints: list[dict]) -> str:
    serialized = json.dumps(fingerprints, sort_keys=True)
    return hashlib.sha256(serialized.encode()).hexdigest()


def hash_live_controls() -> str:
    """Return a hash of the current live control and query state."""
    controls = (
        Control.objects.prefetch_related("queries")
        .order_by("control_id")
    )
    fingerprints = []
    for control in controls:
        queries = [
            _query_fingerprint({
                "name": q.name,
                "canonical_query": q.canonical_query,
                "is_baseline": q.is_baseline,
                "adjusted_severity": q.adjusted_severity,
                "is_active": q.is_active,
            })
            for q in control.queries.order_by("name")
        ]
        fingerprints.append(_control_fingerprint(
            control.control_id,
            control.control_type,
            control.default_severity,
            control.is_active,
            control.implementation_version,
            queries,
        ))
    return _fingerprint_to_hash(fingerprints)


def hash_catalog_payload(payload: dict) -> str:
    """Return a hash of a catalog payload using the same field set."""
    controls = sorted(payload.get("controls", []), key=lambda c: c["control_id"])
    fingerprints = []
    for control in controls:
        queries = [
            _query_fingerprint(q)
            for q in control.get("queries", [])
        ]
        fingerprints.append(_control_fingerprint(
            control["control_id"],
            control["control_type"],
            control["default_severity"],
            control["is_active"],
            control["implementation_version"],
            queries,
        ))
    return _fingerprint_to_hash(fingerprints)


def catalog_has_drifted(catalog_payload: dict) -> bool:
    """Return True if live controls differ from the given catalog payload."""
    return hash_live_controls() != hash_catalog_payload(catalog_payload)
