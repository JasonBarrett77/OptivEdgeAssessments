"""The normalization coverage framework — can a finding be made about an object that is absent?

These tests exist because of what this framework is for. Every other finding model reports on a
row that normalized; this one reports on the record left behind when normalization FAILED, and
the whole value of it rests on one property: a `NormalizationIssue` row exists when the object
does not. If generation cannot produce a finding from an issue row, the framework is plumbing
that reports nothing, and the gap it was built for stays invisible.

NO CATALOG CONTROL IS SEEDED HERE. The controls themselves are control work and belong to the
process that writes control prose; `PAN-COV-004` and its siblings are not in the catalog yet.
The controls below are fixtures, built in the test, which is what lets the plumbing be
exercised before any of it ships to a report.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.models import (
    AssessmentRun,
    Control,
    ControlQuery,
    NormalizationFinding,
)
from assessments.normalization_findings import generate_normalization_findings
from assessments.search.exceptions import SearchSyntaxError
from assessments.search.normalization_issue.compiler import FIELD_COMPILERS
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    NormalizationIssue,
)

MODEL = "integrations.NormalizationIssue"


class NormalizationFindingTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.norm")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-norm",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-NORM", hostname="fw-norm")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group, vsys_name="vsys1")
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())

    def _issue(self, **kwargs):
        fields = dict(
            management_station=self.station, enforcement_point=self.point,
            kind="address object", name="oep-broken",
            severity=NormalizationIssue.Severity.ERROR,
            disposition=NormalizationIssue.Disposition.SKIPPED,
            reason="the entry carried no ip-netmask", is_consequent=False,
            node="address", source="show_merged_config",
        )
        fields.update(kwargs)
        return NormalizationIssue.objects.create(**fields)

    def _control(self, control_id, clauses, *, severity=Control.Severity.INFORMATIONAL):
        """A fixture control, not a catalog one. See the module docstring."""
        control = Control.objects.create(
            control_id=control_id, name=f"{control_id} fixture",
            control_type=Control.ControlType.NORMALIZATION,
            description="fixture", default_severity=severity)
        ControlQuery.objects.create(
            control=control, name="Baseline", is_baseline=True,
            canonical_query={"model": MODEL, "operator": "and", "clauses": clauses})
        return control

    def _findings(self):
        generate_normalization_findings(self.run)
        return {(f.control.control_id, f.subject_name): f
                for f in NormalizationFinding.objects.select_related("control")}

    # -- the case the framework exists for ---------------------------------------------

    def test_an_object_that_did_not_normalize_reports(self):
        """The whole point. There is no downstream object row here - only the issue record -
        and a finding is still produced, naming the object by the name it had on the device."""
        self._issue()
        self._control("FIX-ROOT", [
            {"field": "severity", "op": "eq", "value": "error"},
            {"field": "disposition", "op": "eq", "value": "skipped"},
            {"field": "is_consequent", "op": "eq", "value": False},
        ])

        found = self._findings()

        self.assertEqual(list(found), [("FIX-ROOT", "oep-broken")])
        summary = found[("FIX-ROOT", "oep-broken")].summary
        self.assertIn("does not exist downstream", summary)
        self.assertIn("no control in this assessment has looked at it", summary)
        self.assertIn("the entry carried no ip-netmask", summary)

    def test_the_severity_comes_from_the_control(self):
        """Informational by Jason's decision of 2026-10-28, and carried on the finding row
        rather than computed from the matched queries."""
        self._issue()
        self._control("FIX-ROOT", [{"field": "severity", "op": "eq", "value": "error"}])

        found = self._findings()

        self.assertEqual(len(found), 1)
        self.assertEqual(found[("FIX-ROOT", "oep-broken")].severity,
                         Control.Severity.INFORMATIONAL)

    # -- cause separated from consequence ---------------------------------------------

    def test_a_root_baseline_excludes_the_consequences(self):
        """`is_consequent` is what lets one fault report once instead of 1,301 times. The
        field comment in Integrations records the measured case: "a report counts 1,301 errors
        where there is one cause and 1,300 symptoms, and points at the symptoms"."""
        self._issue(name="oep-root")
        self._issue(name="oep-rule-1", kind="security rule", is_consequent=True,
                    related_object_name="oep-root")
        self._control("FIX-ROOT", [
            {"field": "is_consequent", "op": "eq", "value": False},
        ])

        self.assertEqual(list(self._findings()), [("FIX-ROOT", "oep-root")])

    def test_a_consumer_baseline_reports_each_affected_object_and_names_the_cause(self):
        """Jason's requirement of 2026-10-28: the rules that tried to use the broken object get
        findings of their own, not just a count. They cost one control, because Integrations
        already wrote `related_object_name` on every consequent row."""
        self._issue(name="oep-root")
        self._issue(name="oep-rule-1", kind="security rule", is_consequent=True,
                    related_object_name="oep-root")
        self._issue(name="oep-rule-2", kind="security rule", is_consequent=True,
                    related_object_name="oep-root")
        self._control("FIX-CONSUMER", [
            {"field": "is_consequent", "op": "eq", "value": True},
        ])

        found = self._findings()

        self.assertEqual(sorted(found), [("FIX-CONSUMER", "oep-rule-1"),
                                         ("FIX-CONSUMER", "oep-rule-2")])
        self.assertIn("failed as a consequence of oep-root",
                      found[("FIX-CONSUMER", "oep-rule-1")].summary)

    def test_a_kept_object_says_it_was_assessed_on_data_we_could_not_read(self):
        """The third state, and the one that is worse than a silence: the object IS reported on,
        confidently, from data the normalizer flagged. The prose has to say so."""
        self._issue(name="oep-kept", disposition=NormalizationIssue.Disposition.KEPT)
        self._control("FIX-KEPT", [
            {"field": "disposition", "op": "eq", "value": "kept"},
        ])

        summary = self._findings()[("FIX-KEPT", "oep-kept")].summary

        self.assertIn("was normalized and kept", summary)
        self.assertIn("could not read in full", summary)

    # -- the two field-width facts ----------------------------------------------------

    def test_a_nameless_object_still_gets_a_subject(self):
        """`name` is "Empty when the entry had no @name; that is itself the problem", so the
        rows most worth reading are the ones that would arrive with a blank subject cell."""
        self._issue(name="", kind="address object")
        self._control("FIX-ROOT", [{"field": "severity", "op": "eq", "value": "error"}])

        self.assertEqual(list(self._findings()), [("FIX-ROOT", "<unnamed address object>")])

    def test_an_over_long_name_is_truncated_to_the_column(self):
        """`NormalizationIssue.name` is 255 and `subject_name` is 64. Harmless for every other
        finding model; not harmless here, because a malformed payload is the normal case."""
        self._issue(name="x" * 200)
        self._control("FIX-ROOT", [{"field": "severity", "op": "eq", "value": "error"}])

        subject = next(iter(self._findings()))[1]

        self.assertEqual(subject, "x" * 64)

    # -- the compiler -----------------------------------------------------------------

    def test_a_value_outside_the_choices_is_refused_rather_than_matching_nothing(self):
        """The read-side half of the gap this framework reports. `scalar_choice.py` returns an
        empty queryset for a value that is not a member, so a mistyped clause is
        indistinguishable from a clean estate. For a package whose subject is "something we
        could not interpret", silence is the wrong answer."""
        with self.assertRaises(SearchSyntaxError):
            FIELD_COMPILERS["severity"](
                {"field": "severity", "op": "eq", "value": "catastrophic"})

    def test_the_payload_column_is_not_reachable_by_any_clause(self):
        """`raw_entry` holds the verbatim entry that failed. It is evidence a human reads, and
        a control that clauses on it would rest a verdict on an uncontracted payload shape."""
        self.assertNotIn("raw_entry", FIELD_COMPILERS)
