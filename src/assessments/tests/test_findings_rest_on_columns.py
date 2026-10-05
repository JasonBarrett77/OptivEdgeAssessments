"""Enforce that no control query can reach a JSON field or a raw payload.

This is a BEHAVIOURAL check, not a grep. It compiles every registered search field with every
operator that field accepts, then WALKS THE QUERY STRUCTURE and asserts no JSON column is
referenced. Source inspection would miss a lookup built by string interpolation, and a naming
convention would miss a JSON column not called `raw_` anything.

It walks the query rather than reading its SQL because Django refuses to render SQL for a
filter it can prove matches nothing - `EmptyResultSet` - which is the normal state for several
security-rule address queries against an empty test database. Rendering would have left those
fields uninspected, and an uninspected field is precisely the hole this exists to close.

Why the rule needs enforcing rather than remembering: two of its failure modes are SILENT. A
JSON lookup is unindexed, and it matches NOTHING when the vendor renames a key - so a control
resting on one stops finding anything instead of failing, and nothing in the test suite or the
UI says so. It also writes a vendor payload's shape into a control definition, where no schema
protects it and no migration catches it. Raw payloads (`raw_rule`, `raw_profile`) are the same
rule's limiting case: they are JSONFields too, so one check covers both halves.

WHAT THIS GUARANTEES: no control query can reach a JSON column, exhaustively over the
registry, which is the only path from a control to the database. `Control.target_model` is
resolved through `MODEL_REGISTRY`, every finding generator evaluates through it, and a field
name absent from it raises SearchSyntaxError.

WHAT IT DOES NOT: it cannot stop someone writing raw ORM inside a finding generator and
bypassing the registry entirely. `test_every_finding_generator_targets_a_registered_model`
below narrows that, but the honest limit is that this enforces the query path, not all
possible code.
"""

from __future__ import annotations

import importlib

from django.db.models import JSONField
from django.test import TestCase

from assessments.models import Control
from assessments.search.exceptions import SearchSyntaxError
from assessments.finding_registry import FINDING_KINDS
from assessments.search.registry import MODEL_REGISTRY

#: Tried in order until one is accepted. A field that accepts NONE of them is a FAILURE rather
#: than a skip - a field this cannot probe is a field this cannot vouch for, and silently
#: skipping it would be the same class of hole the rule exists to close.
#:
#: The list grew when the guard refused to vouch for twelve security-rule fields: the address
#: compilers want a parseable IPv4 value or the literal "any", and the choice compilers want a
#: value from their own choice map. If a new field rejects everything here, add a value; do not
#: exempt the field.
PROBE_VALUES = (
    "",
    "probe",
    1,
    True,
    False,
    "any",              # address semantics accept this literal
    "10.0.0.1",         # a parseable IPv4 for the address compilers
    "10.0.0.0/24",
    "local",            # a real config_source choice
)


def referenced_columns(node, found=None):
    """Every model field a WHERE tree touches, including through subqueries.

    A JSON lookup appears as a KeyTransform whose `lhs` chain terminates at the JSONField, so
    walking the chain finds the column by name without having to recognise JSON syntax in any
    particular database dialect.
    """
    found = set() if found is None else found
    for child in getattr(node, "children", []):
        if hasattr(child, "children"):
            referenced_columns(child, found)
            continue
        lhs = getattr(child, "lhs", None)
        while lhs is not None:
            target = getattr(lhs, "target", None)
            if target is not None:
                found.add(target.name)
            lhs = getattr(lhs, "lhs", None)
        rhs = getattr(child, "rhs", None)
        inner = getattr(rhs, "query", None)
        if inner is not None:
            referenced_columns(inner.where, found)
            for annotation in getattr(inner, "annotations", {}).values():
                sub = getattr(annotation, "query", None)
                if sub is not None:
                    referenced_columns(sub.where, found)
    return found


def _clause(field_name, op, value):
    return {
        "field": field_name,
        "op": op,
        "value": value,
        "negated": False,
        "case_sensitive": False,
        "include_any": False,
    }


class FindingsRestOnColumnsTests(TestCase):
    def test_no_registered_search_field_can_reach_a_json_column(self):
        violations = []
        unprobeable = []

        for model_name, entry in MODEL_REGISTRY.items():
            model = entry["model_class"]
            compile_node = entry["compiler"]
            json_columns = {
                f.name for f in model._meta.get_fields() if isinstance(f, JSONField)
            }
            if not json_columns:
                continue

            # The per-field compilers return the `.values("pk")` queryset directly, which is
            # what has to be inspected. Going through the node compiler instead yields
            # Q(pk__in=Subquery(...)), and Django raises EmptyResultSet rather than render SQL
            # for a filter it can prove matches nothing - which would leave a field
            # uninspected, and an uninspected field is exactly what this must not allow.
            field_compilers = importlib.import_module(
                compile_node.__module__).FIELD_COMPILERS

            for field_name, operators in sorted(entry["field_operators"].items()):
                for op in sorted(operators):
                    touched = None
                    for value in PROBE_VALUES:
                        try:
                            queryset = field_compilers[field_name](
                                _clause(field_name, op, value))
                            touched = referenced_columns(queryset.query.where)
                            break
                        except (SearchSyntaxError, ValueError, TypeError):
                            continue
                    if touched is None:
                        unprobeable.append(f"{model_name}.{field_name} op={op}")
                        continue

                    for column in json_columns & touched:
                        violations.append(
                            f"{model_name}.{field_name} (op={op}) reaches JSON column "
                            f"'{column}'")

        self.assertEqual(
            unprobeable, [],
            "these search fields accepted none of the probe values, so this test cannot "
            f"vouch for them - add a probe value or fix the compiler: {unprobeable}")
        self.assertEqual(
            violations, [],
            "a control query can reach a JSON column. Promote the value to a real column in "
            f"normalization and query that instead: {violations}")

    def test_every_json_column_is_absent_from_the_searchable_field_names(self):
        """A second, cheaper net, in a different dimension from the SQL check.

        The SQL check catches a compiler that FILTERS on a JSON column. This catches a
        registry that merely NAMES one, which would be a mistake in the making even if the
        compiler happened not to filter on it yet.
        """
        offenders = []
        for model_name, entry in MODEL_REGISTRY.items():
            model = entry["model_class"]
            json_columns = {f.name for f in model._meta.get_fields()
                            if isinstance(f, JSONField)}
            for field_name in entry["field_operators"]:
                if field_name in json_columns:
                    offenders.append(f"{model_name}.{field_name}")
        self.assertEqual(offenders, [],
                         f"JSON columns registered as searchable: {offenders}")

    def test_every_control_type_targets_a_registered_model(self):
        """A control type whose target model is not in the registry could not be evaluated
        through the checked path at all, which is how this rule would get bypassed."""
        missing = []
        for control_type in Control.ControlType:
            target = Control._CONTROL_TYPE_TARGET_MODEL.get(control_type.value, "")
            if not target:
                continue
            if target not in MODEL_REGISTRY:
                missing.append(f"{control_type.value} -> {target}")
        self.assertEqual(missing, [],
                         f"control type(s) whose target model bypasses the registry: {missing}")

    def test_every_finding_generator_targets_a_registered_model(self):
        """Narrows the gap the docstring admits: a generator could query a model directly.

        Every *Finding model's subject must be a model the registry knows, so a finding cannot
        be produced against something no checked query path can reach.
        """
        registered = {entry["model_class"] for entry in MODEL_REGISTRY.values()}
        unregistered = []
        # The SUBJECT comes from the registry, which names it per kind. It used to be inferred
        # as "any FK into integrations", which was true for as long as a finding had exactly
        # one - until `FindingBase.snapshot` gave every finding a second, and the inference
        # started reporting Snapshot as twenty-four unreachable subjects. A snapshot is the
        # configuration a finding was computed FROM; nothing asserts anything about it, and
        # `Snapshot.payload` is the one thing the boundary forbids reading outright.
        for kind in FINDING_KINDS:
            subject = kind.model._meta.get_field(kind.subject_field).related_model
            if subject not in registered:
                unregistered.append(f"{kind.model.__name__} -> {subject.__name__}")
        self.assertEqual(
            unregistered, [],
            f"finding subject(s) no registered query path can reach: {unregistered}")
