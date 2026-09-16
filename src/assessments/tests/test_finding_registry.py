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

    #: Labels the singular rule does not apply to, each with the reason. The rule is a
    #: heuristic for catching "certificates" where "certificate" was meant; a label whose
    #: SUBJECT is plural in the vendor's own UI is not that mistake.
    PLURAL_BY_NAME = {
        # Device > Setup > Management > Authentication Settings. "authentication setting"
        # names nothing - the screen is one object made of several values.
        "authentication settings",
        # Device > Setup > Services. "update server setting" names nothing either.
        "update server settings",
        # Device > Setup > Management > Logging and Reporting Settings.
        "logging settings",
    }

    def test_labels_are_unique_and_prose_shaped(self):
        labels = [k.label for k in FINDING_KINDS]
        self.assertEqual(len(labels), len(set(labels)))
        for label in labels:
            if label in self.PLURAL_BY_NAME:
                continue
            self.assertFalse(label.endswith("s"), f"{label!r} should be singular")

    def test_counts_cover_every_kind(self):
        from assessments.finding_registry import open_finding_counts
        self.assertEqual(set(open_finding_counts()), {k.label for k in FINDING_KINDS})


class FindingPathConvergenceTests(TestCase):
    """One path for every finding kind, policy included.

    `RuleFinding` sat on `FindingBase` while the other 22 kinds moved to `ObjectFindingBase`,
    and the divergence was invisible: nothing failed, the policy findings just could not say
    which rule they were about. Asserted over the REGISTRY so a new model cannot reintroduce it.
    """

    #: Kinds that legitimately have no named subject, each with the reason. Empty today: every
    #: finding in the corpus is about something with a name. A device-wide setting finding would
    #: belong here - and adding to this set should be a deliberate argument, not a shortcut.
    NO_NAMED_SUBJECT: set[str] = set()

    def test_every_finding_model_is_an_object_finding(self):
        from assessments.models import ObjectFindingBase
        divergent = sorted(
            kind.name for kind in FINDING_KINDS
            if kind.name not in self.NO_NAMED_SUBJECT
            and not issubclass(kind.model, ObjectFindingBase))
        self.assertEqual(divergent, [],
                         f"finding models not on the shared object path: {divergent}. "
                         "Extend ObjectFindingBase and generate with an ObjectFindingSpec, or "
                         "add the model to NO_NAMED_SUBJECT with a reason.")

    def test_every_finding_model_freezes_a_subject_name(self):
        for kind in FINDING_KINDS:
            if kind.name in self.NO_NAMED_SUBJECT:
                continue
            with self.subTest(kind.name):
                kind.model._meta.get_field("subject_name")
