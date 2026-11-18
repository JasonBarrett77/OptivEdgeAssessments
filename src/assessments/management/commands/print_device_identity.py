"""Every row this estate holds for one firewall, and which of them the engagement is on.

WHY THIS EXISTS. `print_unattributed_findings` said that 22,743 of a production report's
findings hang off one enforcement point whose firewall is out of scope - `vsys1 (point 46),
in_scope=False, runs on scem-p-cfw-elz-001-westus3`. Jason, 2026-11-18: *"scem-p-cfw-elz-001-
westus3 is in scope. This is a cloud NGFW device... On the enforcement-points tab, I see ten
rows with this appliance name, and two of the rows have a Last Sync that isn't null."*

Ten rows for one firewall is the shape to chase, and nothing in the app lays them beside each
other. A scope tick lives on ONE `EnforcementPoint` row; the rules, the snapshots and the
findings hang off whichever row the collection used. When those are different rows the
engagement is on a vsys that carries nothing and the configuration that was assessed belongs,
on paper, to a firewall nobody assessed. `Appliance` is unique per (station, SERIAL), so one
hostname can legitimately hold several rows - which is how a cloud NGFW that re-registers
accumulates identities.

WHAT IT PRINTS. One block per appliance row matching the name, with its serial, group, sync
state and what hangs off it; then every enforcement point that reaches any of those rows, in
one table, with its scope tick beside its snapshot and finding counts. The last line is the
verdict: whether `scope.appliances_in_scope` - the function every artifact filters on - holds
any of them.

IT COUNTS SNAPSHOTS RATHER THAN RULES, and the reason is a boundary rather than a preference.
`test_query_service_boundary` holds that a normalized model a control asserts about is
filtered only in `assessments/search/`; `SecurityRule.objects.filter(enforcement_point_id=...)`
here is exactly the private interpretation it forbids, and there is no registered search field
naming an enforcement point to ask through. The snapshot count is the better answer anyway:
the question is which row the collection ran through, and the snapshot IS the collection.

    python manage.py print_device_identity --name scem-p-cfw-elz-001
    python manage.py print_device_identity --name 160TTOQ95F5S6A4

WHY IT IS A COMMAND, and the same reason as its two siblings: the question is about one
estate's rows and the lab cannot stand in. Its four appliances each hold one identity.

IT ONLY READS. No row is written, no appliance is touched, nothing is collected.
"""

from __future__ import annotations

from collections import Counter

from django.core.management.base import BaseCommand, CommandError


def when(moment) -> str:
    return moment.strftime("%Y-%m-%d %H:%M") if moment else "never"


class Command(BaseCommand):
    help = ("Report every appliance and enforcement point row this estate holds for one "
            "firewall, and which of them this engagement's scope is on. Reads only.")

    def add_arguments(self, parser):
        parser.add_argument(
            "--name", required=True,
            help="text to match against an appliance hostname or serial number")

    def handle(self, *args, **options):
        from django.db.models import Q

        from optivedge_integrations.integrations.models import Appliance, Snapshot
        from assessments import finding_registry
        from assessments.artifacts import scope

        name = options["name"]
        appliances = list(Appliance.objects.filter(
            Q(hostname__icontains=name) | Q(serial_number__icontains=name)
        ).select_related("appliance_group", "management_station").distinct())
        if not appliances:
            raise CommandError(f"no appliance's hostname or serial number contains {name!r}")

        in_scope = set(scope.appliances_in_scope().values_list("pk", flat=True))
        points = self.points_reaching(appliances)
        snapshots = Counter(Snapshot.objects.filter(
            enforcement_point_id__in=points).values_list("enforcement_point_id", flat=True))
        findings = Counter()
        for kind in finding_registry.FINDING_KINDS:
            findings.update(Counter(kind.model.objects.filter(
                snapshot__enforcement_point_id__in=points).values_list(
                    "snapshot__enforcement_point_id", flat=True)))

        self.stdout.write(f"appliance rows whose hostname or serial contains {name!r}: "
                          f"{len(appliances)}")
        for appliance in sorted(appliances, key=lambda one: one.pk):
            group = appliance.appliance_group
            self.stdout.write(
                f"\n  appliance {appliance.pk}  {appliance.hostname or '(no hostname)'}  "
                f"serial {appliance.serial_number or '(none)'}"
                + ("  IN SCOPE" if appliance.pk in in_scope else "  out of scope"))
            self.stdout.write(
                f"      group:        {group.name if group else 'none'}"
                f"{f' ({group.pk})' if group else ''}"
                f"   members: {self.members(group)}")
            self.stdout.write(
                f"      last synced:  {when(appliance.last_synced_at)}"
                f"   missing: {appliance.is_missing}"
                f"   model: {appliance.model or 'unrecorded'}")

        self.stdout.write(f"\nenforcement points reaching any of them ({len(points)}):")
        self.stdout.write("   point  vsys        in_scope  last synced       snapshots"
                          "  findings  group")
        for point in sorted(points.values(), key=lambda one: one.pk):
            group = point.appliance_group
            self.stdout.write(
                f"  {point.pk:>6}  {point.vsys_name:<10}  {str(point.in_scope):<8}  "
                f"{when(point.last_synced_at):<16}  {snapshots[point.pk]:>9,}  "
                f"{findings[point.pk]:>8,}  {group.name if group else 'none'}")
            self.stdout.write(f"          runs on: {self.nodes(point)}")

        self.verdict(appliances, points, in_scope, snapshots, findings)

    @staticmethod
    def members(group) -> str:
        """The group's own appliance rows, BY PRIMARY KEY as well as by name.

        A cloud NGFW that re-registers leaves several appliance rows carrying one hostname -
        `Appliance` is unique per (station, serial) - so a line that prints names alone cannot
        be read: `runs on: fw-x` and `members: fw-x` look like agreement whether the two are
        the same row or not, and whether they are is the whole question.
        """
        if group is None:
            return "none"
        names = [f"{appliance.hostname or appliance.serial_number or 'unnamed'} "
                 f"(appliance {appliance.pk}, serial {appliance.serial_number or 'none'})"
                 for appliance in group.appliances.all()]
        return ", ".join(names) or "none"

    @staticmethod
    def nodes(point) -> str:
        names = [f"{node.appliance.hostname or node.appliance.serial_number or 'unnamed'} "
                 f"(appliance {node.appliance_id}, serial "
                 f"{node.appliance.serial_number or 'none'})"
                 for node in point.nodes.select_related("appliance")]
        return ", ".join(names) or "no node row"

    @staticmethod
    def points_reaching(appliances: list) -> dict:
        """Every enforcement point that names one of these appliances, any of the three ways.

        THE THREE WAYS ARE `flows.get_in_scope_appliances`'S OWN - the point's `appliance`, its
        node rows, its group's members - so a point this finds is a point that would put the
        appliance in scope if it were ticked, and one it misses could not.
        """
        from django.db.models import Q

        from optivedge_integrations.integrations.models import EnforcementPoint

        pks = [appliance.pk for appliance in appliances]
        groups = {appliance.appliance_group_id for appliance in appliances
                  if appliance.appliance_group_id}
        reaching = EnforcementPoint.objects.filter(
            Q(appliance_id__in=pks) | Q(nodes__appliance_id__in=pks)
            | Q(appliance_group_id__in=groups))
        return {point.pk: point for point in reaching.distinct().select_related(
            "appliance_group", "management_station")}

    def verdict(self, appliances, points, in_scope, snapshots, findings) -> None:
        """The two sentences the run is for: where the scope tick is, and where the work is.

        A POINT CARRYING ONLY SNAPSHOTS COUNTS AS THE ONE THAT WAS COLLECTED THROUGH. Findings
        are what a run made of the configuration and can be legitimately absent - a run not
        re-run since, a vsys nothing fired on - while the snapshot IS the collection. The
        question here is which row the engagement actually read, so the broader of the two is
        the right test.
        """
        ticked = [point for point in points.values() if point.in_scope]
        carrying = [point for point in points.values()
                    if snapshots[point.pk] or findings[point.pk]]
        self.stdout.write("")
        if not ticked:
            self.stdout.write(self.style.WARNING(
                "No enforcement point reaching this firewall is in scope, so "
                "`appliances_in_scope` holds none of its appliance rows and every artifact "
                "leaves it out - while its findings stay in the finding tables."))
        else:
            self.stdout.write(
                "in scope: " + ", ".join(f"point {point.pk} {point.vsys_name}"
                                         for point in sorted(ticked, key=lambda p: p.pk)))
        if carrying:
            self.stdout.write(
                "carrying collected configuration: "
                + ", ".join(f"point {point.pk} ({snapshots[point.pk]:,} snapshots, "
                            f"{findings[point.pk]:,} findings)"
                            for point in sorted(carrying, key=lambda p: p.pk)))
        unticked = [point for point in carrying if not point.in_scope]
        if ticked and unticked:
            self.stdout.write(self.style.WARNING(
                "THE TICK AND THE WORK ARE ON DIFFERENT ROWS. The configuration that was "
                "assessed hangs off "
                + ", ".join(f"point {point.pk}" for point in sorted(unticked, key=lambda p: p.pk))
                + ", which no scope decision is on."))
        held = [appliance.pk for appliance in appliances if appliance.pk in in_scope]
        self.stdout.write(
            f"\n`scope.appliances_in_scope` holds {len(held)} of {len(appliances)} appliance "
            f"{'row' if len(appliances) == 1 else 'rows'} for this firewall"
            + (f": {', '.join(str(pk) for pk in held)}" if held else ""))
