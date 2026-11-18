"""Remove the rows a device that no longer exists left behind, and everything read from it.

WHY THIS EXISTS. A cloud NGFW instance registers to Panorama with its own serial, so a
redeploy mints a new `Appliance` row beside the old one - `Appliance` is unique per (station,
serial number), not per hostname. Nothing retires the old one: `retire_superseded_enforcement_
points` fires when an appliance MOVES GROUP, which is the HA-pair case, and a replaced instance
does not move, it is simply never seen again. Its enforcement point, its snapshots, its rules
and its findings stay, and every findings run regenerates them.

Measured on a production estate 2026-11-18: `scem-p-cfw-elz-001-westus3` was ten appliance
rows, ten standalone groups and ten vsys1 enforcement points - five instances registered
2026-07-29 and five more on 2026-09-23 that replaced them. Two points carried findings: the
September one that is in scope, 23,205 of them, and the July one that is not, 22,743. The same
rulebase assessed twice, 45,948 findings of 179,431 - a quarter of the deliverable, half of it
read from instances that had ceased to exist.

WHAT IT REMOVES, and nothing else: the appliance rows named on the command line, the
enforcement points that reach them, the snapshots taken from either, every finding read from
those snapshots, and any appliance group left holding nothing. `SecurityRule`, `EnforcementNode`
and the rest cascade from those.

    python manage.py remove_decommissioned_devices --appliances 56 66 75 77 81

The ids are the ones `print_device_identity` prints. They are taken EXPLICITLY rather than
inferred from a sync date, because deciding which of ten identities is dead is a judgement
about an estate and this command's job is to carry it out exactly.

WHAT IT REFUSES. It will not remove an appliance this engagement is on, an enforcement point
that is in scope, or a point that also reaches an appliance not named - which would be one
shared with a device that is still live. Each refusal names the row, because any of the three
means the ids are wrong rather than that the command needs persuading.

FINDINGS GO FIRST, and that is not tidiness: `FindingBase.snapshot` is `on_delete=PROTECT`, so
deleting a snapshot a finding was read from raises `ProtectedError` and the whole delete rolls
back. The findings on the doomed snapshots are removed by this command; the rest cascade
through their own subjects.

IT WRITES. Everything happens in one transaction, and the counts it prints are measured before
and after rather than predicted. Re-run the findings afterwards so the run's own totals settle.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction


class Command(BaseCommand):
    help = ("Remove the appliance rows a decommissioned device left behind, the enforcement "
            "points and snapshots that hang off them, and the findings read from those. "
            "Writes.")

    def add_arguments(self, parser):
        parser.add_argument(
            "--appliances", type=int, nargs="+", required=True, metavar="ID",
            help="the appliance row ids to remove, as `print_device_identity` prints them")

    def handle(self, *args, **options):
        from django.db.models import Q

        from assessments import finding_registry
        from assessments.artifacts import scope
        from optivedge_integrations.integrations.models import (
            Appliance, ApplianceGroup, EnforcementPoint, SecurityRule, Snapshot)

        wanted = list(options["appliances"])
        appliances = list(Appliance.objects.filter(pk__in=wanted)
                          .select_related("appliance_group"))
        missing = sorted(set(wanted) - {appliance.pk for appliance in appliances})
        if missing:
            raise CommandError(
                f"no appliance row has {'id' if len(missing) == 1 else 'ids'} "
                f"{', '.join(str(pk) for pk in missing)}")

        in_scope = set(scope.appliances_in_scope().values_list("pk", flat=True))
        held = [appliance for appliance in appliances if appliance.pk in in_scope]
        if held:
            raise CommandError(
                "this engagement is on " + ", ".join(
                    f"appliance {appliance.pk} ({appliance.hostname or appliance.serial_number})"
                    for appliance in held)
                + " - `scope.appliances_in_scope` holds it, so removing it would delete the "
                  "configuration the report rests on")

        groups = {appliance.appliance_group_id for appliance in appliances
                  if appliance.appliance_group_id}
        points = list(EnforcementPoint.objects.filter(
            Q(appliance_id__in=wanted) | Q(nodes__appliance_id__in=wanted)
            | Q(appliance_group_id__in=groups)).distinct().prefetch_related("nodes"))

        ticked = [point for point in points if point.in_scope]
        if ticked:
            raise CommandError(
                "in scope: " + ", ".join(f"point {point.pk} {point.vsys_name}"
                                         for point in ticked)
                + " - an enforcement point this engagement is on is not a decommissioned row")

        shared = {point.pk: sorted({node.appliance_id for node in point.nodes.all()}
                                   - set(wanted))
                  for point in points}
        shared = {pk: others for pk, others in shared.items() if others}
        if shared:
            raise CommandError(
                "shared with an appliance that was not named: "
                + "; ".join(f"point {pk} also runs on "
                            + ", ".join(f"appliance {other}" for other in others)
                            for pk, others in sorted(shared.items()))
                + " - name those appliances too, or leave the point alone")

        snapshots = set(Snapshot.objects.filter(
            Q(enforcement_point_id__in=[point.pk for point in points])
            | Q(appliance_id__in=wanted) | Q(appliance_group_id__in=groups)
        ).values_list("pk", flat=True))

        before = self.census(SecurityRule, Snapshot, EnforcementPoint, Appliance, ApplianceGroup)
        with transaction.atomic():
            removed_findings = 0
            for kind in finding_registry.FINDING_KINDS:
                # `FindingBase.snapshot` is PROTECT, so these have to go before the snapshots
                # they were read from; everything else cascades through its own subject.
                #
                # The PER-MODEL half of what `delete()` returns, not its total: the total
                # counts the control-query link rows that cascade from each finding too, and
                # a line reading `findings removed: 2` for one finding is a wrong number in a
                # command whose whole output is numbers.
                _total, detail = kind.model.objects.filter(snapshot_id__in=snapshots).delete()
                removed_findings += detail.get(kind.model._meta.label, 0)
            EnforcementPoint.objects.filter(pk__in=[point.pk for point in points]).delete()
            Appliance.objects.filter(pk__in=wanted).delete()
            # Only the groups the removal itself emptied. A group still holding an appliance
            # is a live row that happened to be named here, and is left where it is.
            ApplianceGroup.objects.filter(
                pk__in=groups, appliances__isnull=True,
                enforcement_points__isnull=True).delete()
        after = self.census(SecurityRule, Snapshot, EnforcementPoint, Appliance, ApplianceGroup)

        self.stdout.write(f"findings removed:        {removed_findings:>9,}")
        for label in before:
            self.stdout.write(f"{label + ' removed:':<25}{before[label] - after[label]:>9,}")
        self.stdout.write(self.style.SUCCESS(
            "\nRe-run the findings so the run's own totals settle, then rebuild the document: "
            "`print_unattributed_findings` should report fewer findings naming no firewall, "
            "and the Occurrences line of every block should add up to its Affected Devices "
            "line."))

    @staticmethod
    def census(*models) -> dict:
        """How many rows each model holds, measured rather than predicted.

        `delete()` returns what IT deleted, which is the cascade's own account of itself and
        not the same question - a row removed by a second cascade is counted under whichever
        label reached it first. Counting the tables before and after says what actually left.
        """
        return {model.__name__: model.objects.count() for model in models}
