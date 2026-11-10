"""Which findings the health check can name no firewall for, and why.

WHY THIS EXISTS. The Firewalls line of a Detailed Findings block names every firewall carrying
the control's findings at that grade. A finding whose snapshot resolves to no firewall used to
be absent from that line without a word, so the row's two numbers disagreed - Jason, 2026-11-10,
spot-checking a production report: *"the PAN-POL-008 Findings count is not adding up with the
Firewalls counts."* The line now states those findings instead of dropping them, which makes the
row honest; it does not make the gap go away. This command says how big the gap is and which of
six shapes the snapshots behind it are, because each shape is a different repair.

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
            firewalls_by_snapshot, plural, why_no_firewall_is_named)

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
        self.stdout.write(f"findings in total:            {total:>9,}")
        self.stdout.write(f"findings naming no firewall:  {unattributed:>9,} over "
                          f"{len(findings):,} {plural(len(findings), 'snapshot')}")
        if not unattributed:
            self.stdout.write(self.style.SUCCESS(
                "\nEvery finding resolves to a firewall, so every Firewalls line in the "
                "document adds up to the Findings line beside it."))
            return

        reasons = why_no_firewall_is_named()
        shapes = Counter()
        for snapshot_id, count in findings.items():
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

        if options["snapshots"]:
            self.stdout.write("\nthe snapshots, worst first:")
            for snapshot_id, count in findings.most_common():
                self.stdout.write(f"  {count:>9,}  snapshot {snapshot_id}  "
                                  f"{reasons.get(snapshot_id, 'gone')}")
