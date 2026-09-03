"""The registry must hold every finding model, or it is just another list to forget."""

from __future__ import annotations

from django.test import TestCase

from assessments.finding_registry import FINDING_KINDS, FINDING_MODELS, KIND_BY_MODEL
from assessments.models import FindingBase


def _concrete_finding_models():
    def walk(cls):
        for sub in cls.__subclasses__():
            if not sub._meta.abstract:
                yield sub
            yield from walk(sub)
    return set(walk(FindingBase))


class FindingRegistryTests(TestCase):
    def test_the_registry_holds_every_concrete_finding_model(self):
        """The whole point. A new finding model that is not registered fails HERE, rather than
        quietly narrowing the report the way five models already did."""
        missing = _concrete_finding_models() - set(FINDING_MODELS)
        self.assertEqual(missing, set(),
                         f"finding models missing from FINDING_KINDS: "
                         f"{sorted(m.__name__ for m in missing)}")

    def test_the_registry_names_no_model_that_is_not_a_finding(self):
        self.assertEqual(set(FINDING_MODELS) - _concrete_finding_models(), set())

    def test_every_kind_names_a_real_subject_field(self):
        for kind in FINDING_KINDS:
            with self.subTest(kind.name):
                kind.model._meta.get_field(kind.subject_field)

    def test_every_kind_names_a_real_control_type(self):
        from assessments.models import Control
        valid = {choice for choice, _ in Control.ControlType.choices}
        for kind in FINDING_KINDS:
            self.assertIn(kind.control_type, valid, kind.name)

    def test_labels_are_unique_and_prose_shaped(self):
        labels = [k.label for k in FINDING_KINDS]
        self.assertEqual(len(labels), len(set(labels)))
        for label in labels:
            self.assertFalse(label.endswith("s"), f"{label!r} should be singular")

    def test_counts_cover_every_kind(self):
        from assessments.finding_registry import open_finding_counts
        self.assertEqual(set(open_finding_counts()), {k.label for k in FINDING_KINDS})
