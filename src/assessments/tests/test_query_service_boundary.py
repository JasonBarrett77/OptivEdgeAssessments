"""Normalized models are queried through the search service, and nowhere else.

The goal this serves is not tidiness. It is that every assertion about a device rests on
NORMALIZED data - which means the discovery process was followed, the shape was measured, and
the value has a column with a documented implicit state behind it. A module that reaches
around normalization to a raw payload, or invents its own filter over a normalized model, is
implementing a special case: it decides what the configuration means privately, where no
payload contract records it and no test pins it.

Three boundaries, checked statically because they must hold for code that no test exercises:

  1. Filtering an ASSERTED model happens only in `assessments/search/`. Elsewhere a queryset
     may be BUILT (`.objects.all()`, `.select_related()`) and narrowed by PRIMARY KEY, which
     is how a finding generator turns the service's result back into objects - but never by a
     field lookup, which is an assessment decision.

  2. No module reads a collected Snapshot payload or a `raw_*` field. That is the raw vendor
     data normalization exists to interpret.

  3. No lookup reaches into a JSONField. `test_findings_rest_on_columns` proves this for the
     registry at runtime; this catches it in code the registry never sees.

"Asserted" is derived rather than listed: a model is covered when a control query can target
it or a finding is recorded against it. So the set grows on its own as domains land, and it
excludes models that carry no verdict - a view filtering FieldProvenance for display is
presentation, not an assertion about a device.

NOT a naming convention. Detecting a JSON field by its NAME would need nineteen renames across
thirteen models and would still miss the twentieth, whereas the model metadata already says
which fields are JSONFields - so these read `_meta` and ask, rather than trusting a prefix.

Known limit, stated rather than hidden: this is AST analysis, so it follows names within a
statement and not through arbitrary variables. `qs = Model.objects.all()` on one line and
`qs.filter(weak=True)` twenty lines later is not caught. It catches the shape a special case
is actually written in.
"""

from __future__ import annotations

import ast
import pathlib

from django.apps import apps
from django.db.models import JSONField
from django.test import TestCase

ASSESSMENTS = pathlib.Path(__file__).resolve().parent.parent
#: The query service. The one place allowed to decide which normalized objects match.
SERVICE_LAYER = ASSESSMENTS / "search"
FILTERING_METHODS = {"filter", "exclude", "get", "annotate", "aggregate", "values", "values_list"}
#: Narrowing by identity is not an assessment decision - it is how a generator turns the
#: service's answer back into objects.
IDENTITY_LOOKUPS = {"pk", "pk__in", "id", "id__in"}


def _python_files():
    for path in sorted(ASSESSMENTS.rglob("*.py")):
        parts = set(path.parts)
        if "tests" in parts or "migrations" in parts:
            continue
        yield path


def _asserted_models():
    """The normalized models a control can make an assertion about.

    DERIVED, not listed. A model is covered when a control query can target it (it is in the
    search registry) or when a finding is recorded against it. That is exactly the set whose
    fields carry a verdict, and it extends itself: the day Zone becomes a control target, this
    boundary starts applying to Zone without anyone remembering to add it.

    It deliberately excludes models that carry no verdict - IntegrationRun is a collection run
    record and FieldProvenance says where a value came from. Filtering those in a view is
    presentation, not a private interpretation of a device's configuration.
    """
    from assessments.search.registry import MODEL_REGISTRY

    covered = {entry["model_class"] for entry in MODEL_REGISTRY.values()}
    for model in apps.get_app_config("assessments").get_models():
        if not model.__name__.endswith("Finding"):
            continue
        for field in model._meta.get_fields():
            if (getattr(field, "many_to_one", False)
                    and field.related_model._meta.app_label == "integrations"):
                covered.add(field.related_model)
    return {model.__name__: model for model in covered}


def _all_normalized_models():
    return {model.__name__: model for model in apps.get_app_config("integrations").get_models()}


def _json_field_names(models):
    names = set()
    for model in models.values():
        names.update(f.name for f in model._meta.get_fields() if isinstance(f, JSONField))
    return names


def _imported_normalized_names(tree, models):
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and "integrations.models" in node.module:
            for alias in node.names:
                name = alias.asname or alias.name
                if alias.name in models:
                    imported.add(name)
    return imported


class QueryServiceBoundaryTests(TestCase):
    def test_asserted_models_are_filtered_only_in_the_search_service(self):
        models = _asserted_models()
        violations = []

        for path in _python_files():
            if SERVICE_LAYER in path.parents or path.parent == SERVICE_LAYER:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = _imported_normalized_names(tree, models)
            if not imported:
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr not in FILTERING_METHODS:
                    continue
                expression = ast.unparse(node.func)
                model = next((m for m in imported if f"{m}.objects" in expression), None)
                if model is None:
                    continue
                lookups = {kw.arg for kw in node.keywords if kw.arg}
                if lookups and lookups <= IDENTITY_LOOKUPS:
                    continue
                if not lookups and node.func.attr in {"values", "values_list", "annotate"}:
                    continue
                violations.append(
                    f"{path.relative_to(ASSESSMENTS)}:{node.lineno} "
                    f"{model}.objects.{node.func.attr}({sorted(lookups)}) outside the search service")

        self.assertEqual(
            violations, [],
            "normalized models must be filtered through assessments/search/, so every "
            "assertion about a device rests on a measured field rather than a private "
            f"interpretation: {violations}")

    def test_nothing_reads_a_raw_payload_or_snapshot(self):
        models = _all_normalized_models()
        raw_attributes = {
            f.name for model in models.values()
            for f in model._meta.get_fields()
            if isinstance(f, JSONField) and f.name.startswith("raw_")
        }
        # Snapshot.payload is the collected vendor response itself.
        snapshot_payload = "payload"
        violations = []

        for path in _python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imported = _imported_normalized_names(tree, models)
            reads_snapshot = "Snapshot" in imported
            for node in ast.walk(tree):
                if not isinstance(node, ast.Attribute):
                    continue
                if node.attr in raw_attributes:
                    violations.append(
                        f"{path.relative_to(ASSESSMENTS)}:{node.lineno} reads {node.attr}")
                elif reads_snapshot and node.attr == snapshot_payload:
                    source = ast.unparse(node)
                    if "snapshot" in source.lower():
                        violations.append(
                            f"{path.relative_to(ASSESSMENTS)}:{node.lineno} reads {source}")

        self.assertEqual(
            violations, [],
            "raw vendor data is normalization's input, not an assessment's. Reading it here "
            f"means deciding what the configuration means privately: {violations}")

    def test_no_static_lookup_reaches_into_a_json_field(self):
        models = _all_normalized_models()
        json_names = _json_field_names(models)
        violations = []

        for path in _python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                for keyword in node.keywords:
                    if not keyword.arg or "__" not in keyword.arg:
                        continue
                    if keyword.arg.split("__", 1)[0] in json_names:
                        violations.append(
                            f"{path.relative_to(ASSESSMENTS)}:{node.lineno} {keyword.arg}")
                # Lookups also arrive as string literals into **kwargs dicts.
                for child in ast.walk(node):
                    if isinstance(child, ast.Constant) and isinstance(child.value, str):
                        if "__" in child.value and child.value.split("__", 1)[0] in json_names:
                            violations.append(
                                f"{path.relative_to(ASSESSMENTS)}:{child.lineno} "
                                f"{child.value!r}")

        self.assertEqual(
            violations, [],
            "a lookup into a JSONField is unindexed and matches nothing when the vendor "
            f"renames a key. Promote the value to a column: {sorted(set(violations))}")
