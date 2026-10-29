"""The test seeder against the importer it claims to mirror.

WHY THIS FILE EXISTS. `tests/_seed.py` was written because every control test used to hand-roll
its Control and ControlQuery rows and each copy chose its own subset of fields - a drift that hid
for months and then failed four tests at once when severity moved onto the queries. Its docstring
says "there is one seeder, and it takes its field list from the same place the importer does".

IT DOES NOT. It hand-lists them, which is the same defect one layer up, and on 2026-10-28
`asserted_fields` fell straight into it: the field landed on `ControlQuery`, the importer set it,
the seeder did not, and so EVERY control test in this repo ran with it empty and took the fallback
path. The suite passed 840 tests and said nothing about the behaviour the field exists for. It was
found by printing one row by hand.

So this compares the two call sites field by field, from the source, because the drift is between
two argument lists and not between two behaviours. A field added to one and not the other fails
here with the name of the field.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

from django.test import SimpleTestCase

from assessments.controls_catalog.io import importers
from assessments.tests import _seed


def _create_kwargs(path: Path, model: str) -> set[str]:
    """The field names passed to `<model>.objects.create(...)`, anywhere in a module.

    `**fields` IS RESOLVED, because the seeder builds its Control arguments as a dict and splats
    it while the importer passes them one by one. Reading keywords alone made the two look like
    agreement where the seeder passed nothing at all, which is the opposite of what this file is
    for. A splat of anything but a plain local name is left unresolved and reported, so the test
    fails loudly rather than quietly comparing less than it claims.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    dicts: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if not (len(targets) == 1 and isinstance(targets[0], ast.Name)):
            continue
        if isinstance(node.value, ast.Dict):
            dicts.setdefault(targets[0].id, set()).update(
                key.value for key in node.value.keys
                if isinstance(key, ast.Constant) and isinstance(key.value, str))

    found: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or ast.unparse(node.func) != f"{model}.objects.create":
            continue
        for keyword in node.keywords:
            if keyword.arg:
                found.add(keyword.arg)
            elif isinstance(keyword.value, ast.Name):
                if keyword.value.id not in dicts:
                    raise AssertionError(
                        f"{path.name} splats `{keyword.value.id}` into "
                        f"{model}.objects.create and this cannot resolve it, so the comparison "
                        f"below would be weaker than it claims")
                found |= dicts[keyword.value.id]
            else:
                raise AssertionError(
                    f"{path.name} splats an expression into {model}.objects.create: "
                    f"{ast.unparse(keyword.value)}")
    return found


class TheSeederSetsEveryFieldTheImporterSets(SimpleTestCase):
    """Not "every field on the model" - a field the importer deliberately leaves at its default
    is not the seeder's to invent. The claim is only that the two agree."""

    def _sources(self):
        return (Path(inspect.getfile(importers)), Path(inspect.getfile(_seed)))

    def test_the_query_field_lists_agree(self):
        importer, seeder = self._sources()
        missing = (_create_kwargs(importer, "ControlQuery")
                   - _create_kwargs(seeder, "ControlQuery") - {"control"})
        self.assertEqual(set(), missing,
                         f"the importer sets these on a ControlQuery and the test seeder does "
                         f"not, so no test in this repo exercises them: {sorted(missing)}")

    def test_the_control_field_lists_agree(self):
        """`implementation_version` is the one the seeder omits deliberately - it is the
        catalog's own bookkeeping and no control test reads it - so it is named here rather
        than silently subtracted."""
        importer, seeder = self._sources()
        missing = (_create_kwargs(importer, "Control")
                   - _create_kwargs(seeder, "Control") - {"catalog", "implementation_version"})
        self.assertEqual(set(), missing,
                         f"the importer sets these on a Control and the test seeder does not: "
                         f"{sorted(missing)}")


class TheSeederActuallyCarriesAssertedFields(SimpleTestCase):
    """The field list agreeing is a source check. This is the value arriving, on the control the
    omission was found on."""

    def test_PAN_IKE_008_queries_name_what_they_assert_on(self):
        specs = _seed.seed_specs()
        asserted = {q["name"]: q.get("asserted_fields")
                    for q in specs["PAN-IKE-008"]["queries"]}
        self.assertEqual(asserted["IKEv2 idle liveness probe switched off"],
                         ["ikev2_dpd_enabled"])
        # The companion query asserts on the `_known` flag the BASELINE record calls
        # applicability, which is why the role is stored per query rather than derived.
        self.assertEqual(asserted["IKEv1 dead-peer-detection switch not established"],
                         ["ikev1_dpd_enabled_known"])
        for name, fields in asserted.items():
            self.assertNotIn("gateway_is_active", fields or [],
                             f"{name} marks the cell that let the gateway qualify")
