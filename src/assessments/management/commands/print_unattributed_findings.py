"""Which findings the health check can name no firewall for, and why.

WHY THIS EXISTS. The Affected Devices line of a Detailed Findings block names every firewall
the control's findings at that grade. A finding whose snapshot resolves to no firewall used to
be absent from that line without a word, so the row's two numbers disagreed - Jason, 2026-11-10,
spot-checking a production report: *"the PAN-POL-008 Findings count is not adding up with the
Firewalls counts."* The line now states those findings instead of dropping them, which makes the
row honest; it does not make the gap go away. This command says how big the gap is and which of
seven shapes the snapshots behind it are, because each shape is a different repair.

WHAT IT IS FOR, 2026-11-18. Jason, on a production build: *"for several controls, I'm seeing
an item in affected devices that says: 'n' more that the configuration they were read from
names no firewall for... PAN-POL-008, PAN-POL-004, PAN-POL-003, PAN-AVW-003, PAN-VLN-001 and
others."* All five of those are `security_rule` controls, which narrows the cause before the
command is even run: a rule's snapshot is either the appliance's merged config, which always
names a firewall, or the vsys's pushed shared policy, which does not name one directly. So the
gap is in the pushed path, or the finding carries no snapshot at all.

ONE CAUSE IN THAT PATH IS FIXED AND THIS SAYS WHETHER ANY REMAINS. `firewalls_by_snapshot`
resolved a pushed snapshot only through the appliance group its enforcement point names, which
answers nothing once the appliance has been regrouped; it now goes through the point's own
`EnforcementNode` rows first. What this command still reports is therefore a different shape -
a vsys whose firewalls this engagement did not assess, a collection that recorded no node row,
or a finding with no snapshot - and it names which, and prints what each failing vsys runs on.

AND THAT IS WHAT THE PRODUCTION RUN SAID. 23,340 findings of 179,431, over 19 controls, and
22,743 of them on ONE point: `vsys1 (point 46), in_scope=False, runs on
scem-p-cfw-elz-001-westus3`, a cloud NGFW whose rules are defined in Panorama alone. The
attribution is right and the scope tick is not where the collected configuration is -
`print_device_identity` is the command for that half.

WHY IT IS A COMMAND. It has to be answered against the environment that produced the report, and
the lab cannot stand in: all 17,555 of its findings resolve to an appliance, so it prints zero
there whatever is wrong elsewhere. It was a loose script first and ran as
`manage.py shell < probe.py`, which PowerShell has no redirection for.

    python manage.py print_unattributed_findings

IT ONLY READS. No row is written, no appliance is touched, and nothing is collected. The
counting is the health check's own: `measure`'s join over every finding kind, and
`firewalls_by_snapshot` for the attribution, so this cannot disagree with the document it
explains.
"""

from __future__ import annotations

from collections import Counter

from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = ("Report the findings the health check can name no firewall for, by cause and by "
            "control. Reads only.")

    def add_arguments(self, parser):
        parser.add_argument(
            "--controls", type=int, default=10,
            help="how many controls to list, worst first (default 10, 0 for all)")
        parser.add_argument(
            "--snapshots", action="store_true",
            help="also list the snapshot ids, so a reader can go and look at one")

    def handle(self, *args, **options):
        from assessments import finding_registry
        from assessments.artifacts.health_check import (
            FINDING_WITHOUT_A_SNAPSHOT, firewalls_by_snapshot, plural,
            why_no_firewall_is_named)

        owners = firewalls_by_snapshot()
        findings = Counter()
        by_control = Counter()
        for kind in finding_registry.FINDING_KINDS:
            for control_id, snapshot_id in kind.model.objects.values_list(
                    "control__control_id", "snapshot_id"):
                if owners.get(snapshot_id):
                    continue
                findings[snapshot_id] += 1
                by_control[control_id] += 1

        total = sum(kind.model.objects.count() for kind in finding_registry.FINDING_KINDS)
        unattributed = sum(findings.values())
        snapshots = len([snapshot_id for snapshot_id in findings if snapshot_id is not None])
        self.stdout.write(f"findings in total:            {total:>9,}")
        self.stdout.write(f"findings naming no firewall:  {unattributed:>9,} over "
                          f"{snapshots:,} {plural(snapshots, 'snapshot')}"
                          + (f", and {findings[None]:,} recording no snapshot"
                             if findings.get(None) else ""))
        if not unattributed:
            self.stdout.write(self.style.SUCCESS(
                "\nEvery finding resolves to a firewall, so every Affected Devices line in "
                "the document adds up to the Occurrences line beside it."))
            return

        reasons = why_no_firewall_is_named()
        shapes = Counter()
        for snapshot_id, count in findings.items():
            if snapshot_id is None:
                shapes[FINDING_WITHOUT_A_SNAPSHOT] += count
                continue
            shapes[reasons.get(snapshot_id, "unresolved for a reason this command cannot "
                                            "name - the snapshot is gone")] += count
        self.stdout.write("\nby cause, counted in findings:")
        for shape, count in shapes.most_common():
            self.stdout.write(f"  {count:>9,}  {shape}")

        listed = by_control.most_common(options["controls"] or None)
        self.stdout.write(f"\nthe controls it costs most ({len(listed)} of "
                          f"{len(by_control)}):")
        for control_id, count in listed:
            self.stdout.write(f"  {count:>9,}  {control_id}")

        self.points(findings)

        if options["snapshots"]:
            self.stdout.write("\nthe snapshots, worst first:")
            for snapshot_id, count in findings.most_common():
                if snapshot_id is None:
                    self.stdout.write(f"  {count:>9,}  {FINDING_WITHOUT_A_SNAPSHOT}")
                    continue
                self.stdout.write(f"  {count:>9,}  snapshot {snapshot_id}  "
                                  f"{self.where(snapshot_id)}  "
                                  f"{reasons.get(snapshot_id, 'gone')}")

    def where(self, snapshot_id) -> str:
        """What the snapshot was read from, for one line of the listing."""
        from optivedge_integrations.integrations.models import Snapshot

        row = Snapshot.objects.filter(pk=snapshot_id).values_list(
            "source_type", "enforcement_point__vsys_name").first()
        if row is None:
            return "snapshot gone"
        source_type, vsys = row
        return f"{source_type}{' ' + vsys if vsys else ''}"

    def points(self, findings: Counter) -> None:
        """The enforcement points behind the unattributed findings, and what each one knows.

        THE LINES THAT NAME THE REPAIR. A point-scoped snapshot is attributed through the
        firewalls its vsys runs on - its `EnforcementNode` rows - and failing those through its
        appliance group's members in scope. Printing both, beside the point's own `in_scope`,
        separates the repairs: nodes naming a firewall this engagement did not assess is a scope
        declaration to widen, a group whose members have moved on is attribution the node path
        now covers, and no node row at all is a collection that never recorded which appliances
        the vsys runs on.
        """
        from optivedge_integrations.integrations.models import (
            EnforcementNode, EnforcementPoint, Snapshot)

        by_point = Counter()
        for snapshot_id, count in findings.items():
            if snapshot_id is None:
                continue
            point_id = Snapshot.objects.filter(pk=snapshot_id).values_list(
                "enforcement_point_id", flat=True).first()
            if point_id:
                by_point[point_id] += count
        if not by_point:
            return
        self.stdout.write(f"\nthe enforcement points behind them ({len(by_point)}):")
        for point_id, count in by_point.most_common():
            point = EnforcementPoint.objects.filter(pk=point_id).select_related(
                "appliance_group").first()
            nodes = [self.name_of(node.appliance) for node in EnforcementNode.objects.filter(
                enforcement_point_id=point_id).select_related("appliance")]
            group = point.appliance_group
            members = ([self.name_of(appliance) for appliance in group.appliances.all()]
                       if group else [])
            self.stdout.write(
                f"  {count:>9,}  {point.vsys_name} (point {point_id}), "
                f"in_scope={point.in_scope}")
            self.stdout.write(f"             runs on: {', '.join(nodes) or 'no node row'}")
            self.stdout.write(f"             group:   {group.name if group else 'none'}"
                              f"  members: {', '.join(members) or 'none'}")

    @staticmethod
    def name_of(appliance) -> str:
        """Name AND primary key, because one hostname can be several appliance rows.

        `Appliance` is unique per (station, serial number), so a device that re-registers -
        a cloud NGFW instance, for one - accumulates rows carrying the same hostname. Printing
        the name alone makes `runs on` and `members` read as agreement when they may be two
        different rows, which is exactly what has to be told apart here.
        """
        return (f"{appliance.hostname or appliance.serial_number or 'unnamed'} "
                f"(appliance {appliance.pk}, serial {appliance.serial_number or 'none'})")
