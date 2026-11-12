"""`print_unattributed_findings`: how big the attribution gap is, and what shape it is.

The health check's Affected Devices line names every firewall carrying a control's findings.
Where a
snapshot resolves to no firewall the line says so rather than dropping the finding - Jason,
2026-11-10, on a production report: *"the PAN-POL-008 Findings count is not adding up with the
Firewalls counts."* This command answers the next question, which is why, and it has to be
answered against the environment that produced the report: every one of the lab's findings
resolves to an appliance, so a clean run there proves nothing about an estate.
"""

from __future__ import annotations

import datetime as dt
import io

from django.core.management import call_command
from django.test import TestCase

from assessments import finding_registry
from assessments.artifacts import health_check
from assessments.finding_run import regenerate_findings
from assessments.tests._seed import seed_controls
from assessments.tests.test_findings_views import build_estate
from optivedge_integrations.integrations.models import ManagementStation, Snapshot


class UnattributedFindingsCommandTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        build_estate()
        seed_controls(["PAN-MGT-007", "PAN-MGT-001", "PAN-POL-008"])
        regenerate_findings()

    def run_command(self, *args) -> str:
        out = io.StringIO()
        call_command("print_unattributed_findings", *args, stdout=out)
        return out.getvalue()

    def orphan_every_snapshot_carrying_a_finding(self) -> None:
        carrying = {snapshot for kind in finding_registry.FINDING_KINDS
                    for snapshot in kind.model.objects.values_list("snapshot_id", flat=True)
                    if snapshot}
        self.assertTrue(carrying)
        Snapshot.objects.filter(pk__in=carrying).update(
            appliance=None, appliance_group=None, enforcement_point=None,
            management_station=ManagementStation.objects.first())

    def test_an_estate_that_resolves_cleanly_says_so_and_stops(self):
        output = self.run_command()

        self.assertIn("findings naming no firewall:          0 over 0 snapshots", output)
        self.assertIn("Every finding resolves to a firewall", output)
        self.assertNotIn("by cause", output)

    def test_it_counts_the_findings_and_names_the_cause(self):
        self.orphan_every_snapshot_carrying_a_finding()
        total = sum(kind.model.objects.count() for kind in finding_registry.FINDING_KINDS)

        output = self.run_command()

        self.assertIn(f"findings in total:            {total:>9,}", output)
        self.assertIn(f"findings naming no firewall:  {total:>9,}", output)
        self.assertIn(health_check.FROM_THE_MANAGEMENT_STATION, output)
        for control_id in {control_id for kind in finding_registry.FINDING_KINDS
                           for control_id in kind.model.objects.values_list(
                               "control__control_id", flat=True)}:
            self.assertIn(control_id, output)

    def test_controls_zero_means_every_control_rather_than_none(self):
        """`0` reaches `Counter.most_common(None)`, which is all of them. Passed straight
        through it would be `most_common(0)`, which is an empty list and a silent lie."""
        self.orphan_every_snapshot_carrying_a_finding()
        firing = len({control_id for kind in finding_registry.FINDING_KINDS
                      for control_id in kind.model.objects.values_list(
                          "control__control_id", flat=True)})

        self.assertIn(f"the controls it costs most ({firing} of {firing}):",
                      self.run_command("--controls", "0"))
        self.assertIn(f"the controls it costs most ({firing} of {firing}):",
                      self.run_command("--controls", "1"))

    def test_it_can_name_the_snapshots_so_a_reader_can_go_and_look(self):
        self.orphan_every_snapshot_carrying_a_finding()
        orphan = Snapshot.objects.filter(appliance=None).first()

        output = self.run_command("--snapshots")

        self.assertIn(f"snapshot {orphan.pk}", output)

    def test_it_writes_nothing(self):
        """A reader runs this against production. It reads three tables and touches none."""
        self.orphan_every_snapshot_carrying_a_finding()
        before = [(kind.model.objects.count(),) for kind in finding_registry.FINDING_KINDS]
        collected = list(Snapshot.objects.values_list("id", "appliance_id", "collected_at"))

        self.run_command("--snapshots")

        self.assertEqual([(kind.model.objects.count(),)
                          for kind in finding_registry.FINDING_KINDS], before)
        self.assertEqual(list(Snapshot.objects.values_list("id", "appliance_id",
                                                           "collected_at")), collected)
        self.assertEqual(Snapshot.objects.filter(
            collected_at__gt=dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc)).count(), 0)
