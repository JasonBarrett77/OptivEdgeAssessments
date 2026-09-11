"""Build Control + ControlQuery rows from a seed spec, the way the importer does.

Every control test used to hand-roll this, and each copy chose its own subset of the fields
`controls_catalog.io.importers.apply_catalog` sets. That was invisible until 2026-09-09, when
severity moved onto the queries: three modules were passing `name`, `canonical_query`,
`is_baseline` and `is_active` and dropping `adjusted_severity`, so every graded control tested
at its default severity and four tests that had been asserting real band severities started
failing. The tests were right; their seeder had never been.

So there is one seeder, and it takes its field list from the same place the importer does.
"""

from __future__ import annotations

from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import Control, ControlQuery


def seed_specs():
    """{control_id: payload} for every control in the shipped catalog."""
    return {c["control_id"]: c
            for cat in load_seed_payload()["catalogs"] for c in cat["controls"]}


def seed_control(spec, *, control_type=None, **overrides):
    """One Control and all of its queries, with every field the importer sets."""
    fields = {
        "control_id": spec["control_id"],
        "name": spec["name"],
        "control_type": control_type or spec["control_type"],
        "description": spec["description"],
        "default_severity": spec["default_severity"],
        "target_model": spec.get("target_model", ""),
        "is_active": spec.get("is_active", True),
    }
    fields.update(overrides)
    control = Control.objects.create(**fields)
    for query in spec["queries"]:
        ControlQuery.objects.create(
            control=control,
            name=query["name"],
            short_description=query.get("short_description", ""),
            canonical_query=query["canonical_query"],
            is_baseline=query["is_baseline"],
            adjusted_severity=query.get("adjusted_severity"),
            is_active=query["is_active"],
        )
    return control


def seed_controls(control_ids, *, control_type=None):
    specs = seed_specs()
    return [seed_control(specs[cid], control_type=control_type) for cid in control_ids]
