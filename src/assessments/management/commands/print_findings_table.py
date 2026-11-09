"""Build a pipeline domain's estate from its stage 6 artifact, reconcile it against stage 8's
diff, and print the findings table it produces - in a throwaway database, through the committed
normalizers.

WHY THIS IS A COMMAND AND NOT A SCRIPT. Five stage 9 runs each wrote and threw away their own
seeder - `ike-crypto`, `ipsec-crypto`, `device-id-iot`, `zone-dos-protection`, `url-filtering` -
and the last of them put it at roughly the first third of its run, the single largest cost of
the stage. Eleven domains were left to pay it. There is no collected data a stage 9 run may read
instead: the OEA dev database is behind its migrations, so measuring a report tab against it
reports a false clean. Board record P403.

WHY IT IS AN OEA COMMAND AND NOT AN OEP `probe.*` ONE. Two runs asked for
`manage.py print_findings_table <domain-slug>` and a third for `probe.seed_findings <domain>`.
It cannot be the OEP one, and the reason is measured rather than argued: OptivEdgeProbe's
`probe.*` tooling runs under `~/PythonProjects/OptivEdgeIntegrations/.venv`, which has no
`xlsxwriter`. That venv CAN import the bare `assessments` package - the import that fails is
`assessments.artifacts.layout`, reached from `assessments.artifacts.__init__`, so
`django check` on OEA dies under it and so does anything that builds or reads a findings table.
Since printing that table is this command's entire output, it has to run under
`~/PythonProjects/OptivEdgeAssessments/.venv`, which is to say it has to be an OEA command.

    DJANGO_SETTINGS_MODULE=assessments.settings.default \
    PYTHONPATH=~/PythonProjects/OptivEdgeAssessments/src \
    ~/PythonProjects/OptivEdgeAssessments/.venv/bin/python -m django print_findings_table \
        --stage6 ~/PythonProjects/OptivEdgeProbe/pipeline/artifacts/stage6-url-filtering.json \
        --stage8 ~/PythonProjects/OptivEdgeProbe/pipeline/artifacts/stage8-url-filtering.json

PATHS ARE ARGUMENTS, NOT A SIBLING-REPO LAYOUT. The artifacts live in OptivEdgeProbe, which
this repository does not depend on, must not import and cannot assume the location of - they are
gitignored, so they exist only on a machine that ran the pipeline. A hardcoded
`../OptivEdgeProbe/pipeline/artifacts` would make an OEA command fail differently depending on
where OEA was cloned, and would silently read a DIFFERENT artifact than the one a run means if
two checkouts exist. `--stage6` and `--stage8` are therefore required, and `<domain-slug>` is
accepted as a convenience that resolves against `--artifacts-dir`.

RECONCILIATION IS NOT A FLAG. It runs always and the exit status reflects it: non-zero on any
mismatch. The `ipsec-crypto` run reconciled 108 verdicts at zero mismatches and said in its own
report that doing so is what let it trust a single row. Without it a run reads its own seeding
mistakes and cannot tell them from presentation defects, which is the failure this command
exists to make impossible rather than merely discouraged.

WHAT IT COVERS, AND WHAT IT DOES NOT. The estate is derived from the artifact - every subject's
own `identity.xpath` and `verified.read_back` - so no PAN-OS entry is transcribed by hand. That
is what makes it domain-independent. The limits are real and named in
`assessments/tests/_estate.py`:

  * A DOMAIN MUST HAVE stage 6 subjects carrying `identity.xpath`, `identity.device` and
    `verified.read_back`, and a stage 8 `controls.<id>.diff.subjects` list. Both proving domains
    and `ipsec-crypto` do. A domain whose stage 6 records subjects any other way is not covered
    and this command will say so rather than seed a partial estate.
  * CONFIGURATION THE DEVICE HOLDS BUT STAGE 6 DID NOT RECORD AS A SUBJECT is not built. Where a
    verdict depends on it - the url category catalog is the known case - it is declared in
    `_estate.AUX_URL_CATEGORIES` and is a RECONSTRUCTION, not a measurement.
  * CHOICE NODES spelled as a text value need one line per domain in `_estate.CHOICE_NODES`,
    because stage 6 artifacts disagree about how to spell them and nothing pins it down.
  * TWO OF ITS OUTPUTS ARE `DOMAINS`-DERIVED, so RUN IT TWICE AND READ A DIFFERENT HALF EACH
    TIME. A shape-B stage 9 run has not written its `FindingsDomain` yet, and both the subject
    census and `reconcile`'s pass-1 matching consult it. Before the sheets exist the census
    answers from stage 8's `catalog.target_model` and SAYS SO, and pass-1 cannot match at all -
    so every verdict falls to pass 2, whose order is arbitrary and whose attribution a reader
    then has to check subject by subject. `globalprotect-portal` separated five such artifacts
    from one real disagreement by hand. So: run it to CHECK THE ESTATE, write the rail, the
    domains and the sheets, then run it again and read the RECONCILIATION.

The three traps that cost those five runs the most are all handled in
`_estate.build_base_estate`, each marked with its number at the line that handles it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.db import connection
from django.test.utils import setup_test_environment


def _load(path: Path, label: str) -> dict:
    if not path.is_file():
        raise CommandError(f"no {label} artifact at {path}")
    try:
        return json.loads(path.read_text())
    except ValueError as exc:
        raise CommandError(f"{label} artifact at {path} is not JSON: {exc}") from exc


class Command(BaseCommand):
    help = (
        "Build a pipeline domain's estate from its stage 6 artifact in a throwaway migrated "
        "database, reconcile the findings against stage 8's diff, and print the findings table. "
        "Exits non-zero on any reconciliation mismatch.")

    def add_arguments(self, parser):
        parser.add_argument(
            "domain", nargs="?",
            help="Domain slug, resolved against --artifacts-dir as stage6-<slug>.json and "
                 "stage8-<slug>.json. Optional if --stage6 and --stage8 are both given.")
        parser.add_argument("--stage6", help="Path to the stage 6 artifact.")
        parser.add_argument("--stage8", help="Path to the stage 8 artifact.")
        parser.add_argument(
            "--artifacts-dir",
            help="Directory holding stage6-<slug>.json / stage8-<slug>.json. Defaults to "
                 "$OEP_ARTIFACTS_DIR. There is no built-in default: these artifacts live in "
                 "another repository and are gitignored, so this command cannot know where "
                 "they are and will not guess.")
        parser.add_argument(
            "--tab", action="append", dest="tabs", default=[],
            help="Findings tab slug to print. Repeatable. Defaults to every tab whose spec "
                 "covers a control type under test.")
        parser.add_argument(
            "--workbook-columns", action="store_true",
            help="Print the tab as the WORKBOOK builds it rather than as the live page does. "
                 "The two surfaces show different columns; the live page is the default "
                 "because it is the one that shows every tested column.")
        parser.add_argument(
            "--rows", type=int, default=0,
            help="Also dump this many table rows cell by cell, marked cells in [brackets].")
        parser.add_argument(
            "--local-station", action="store_true",
            help="Build the station as a locally-managed firewall rather than Panorama-managed. "
                 "Changes whether the pushed-policy reads are required or absent.")

    # ------------------------------------------------------------------ paths

    def _artifact_paths(self, options) -> tuple[Path, Path]:
        stage6, stage8 = options.get("stage6"), options.get("stage8")
        if stage6 and stage8:
            return Path(stage6).expanduser(), Path(stage8).expanduser()
        domain = options.get("domain")
        if not domain:
            raise CommandError(
                "give a domain slug, or both --stage6 and --stage8")
        directory = options.get("artifacts_dir") or os.environ.get("OEP_ARTIFACTS_DIR")
        if not directory:
            raise CommandError(
                "no --artifacts-dir and no $OEP_ARTIFACTS_DIR, so the stage 6 and stage 8 "
                "artifacts for %r cannot be located. They live in OptivEdgeProbe at "
                "pipeline/artifacts/ and are gitignored; pass --stage6 and --stage8 instead "
                "if they are elsewhere." % domain)
        base = Path(directory).expanduser()
        return (Path(stage6).expanduser() if stage6 else base / f"stage6-{domain}.json",
                Path(stage8).expanduser() if stage8 else base / f"stage8-{domain}.json")

    # ------------------------------------------------------------------ main

    def handle(self, *args, **options):
        stage6_path, stage8_path = self._artifact_paths(options)
        stage6 = _load(stage6_path, "stage 6")
        stage8 = _load(stage8_path, "stage 8")

        domain = stage6.get("domain") or options.get("domain") or "?"
        if stage8.get("domain") and stage8["domain"] != stage6.get("domain"):
            raise CommandError(
                f"artifact mismatch: stage 6 is {stage6.get('domain')!r} but stage 8 is "
                f"{stage8['domain']!r}")
        self._check_shape(stage6, stage8)

        control_ids = sorted((stage8.get("controls") or {}))
        if not control_ids:
            raise CommandError(f"stage 8 artifact for {domain!r} declares no controls")

        self.stdout.write(f"\n### DOMAIN {domain}")
        self.stdout.write(f"  stage 6: {stage6_path}")
        self.stdout.write(f"  stage 8: {stage8_path}")
        self.stdout.write(f"  controls: {', '.join(control_ids)}")

        # A THROWAWAY, MIGRATED DATABASE. The dev database is behind its migrations, so a report
        # tab measured against it reports a false clean - which is the reason no stage 9 run can
        # simply read what is already there. `autoclobber` so a leftover test database from an
        # interrupted run does not stop this one and prompt on a non-interactive terminal.
        setup_test_environment()
        old_config = connection.creation.create_test_db(verbosity=0, autoclobber=True)
        try:
            mismatches = self._run(stage6, stage8, control_ids, options)
        finally:
            connection.creation.destroy_test_db(old_config, verbosity=0)

        if mismatches:
            # The exit status reflects reconciliation. A run that reads this command's table
            # without noticing a mismatch would be reading its own seeding mistakes, which is
            # exactly the failure reconciling exists to prevent.
            raise CommandError(
                f"{mismatches} reconciliation mismatch(es) against stage 8's diff - the built "
                f"estate does not reproduce what stage 8 measured, so nothing above should be "
                f"read as a presentation result")
        self.stdout.write(self.style.SUCCESS("\nRECONCILED CLEAN: 0 mismatches.\n"))

    def _check_shape(self, stage6, stage8) -> None:
        """Refuse a domain this cannot build, by name, rather than seeding a partial estate.

        A command that silently handles four of eleven remaining domains is worse than one that
        says which four, because the fifth run will trust it.
        """
        subjects = stage6.get("subjects") or {}
        if not subjects:
            raise CommandError(
                "stage 6 artifact records no `subjects`, so there is no estate to build from it")
        missing = sorted(
            name for name, subject in subjects.items()
            if not ((subject.get("identity") or {}).get("xpath")
                    and (subject.get("identity") or {}).get("device")))
        if missing:
            raise CommandError(
                "NOT COVERED. These stage 6 subjects carry no `identity.xpath` or no "
                "`identity.device`, and this command derives the estate from exactly those two "
                "fields, so it cannot place them: %s. Covering this domain means either stage 6 "
                "recording them or a per-domain placement rule in _estate.py."
                % ", ".join(missing))
        unpaired = sorted(
            control_id for control_id, control in (stage8.get("controls") or {}).items()
            if not (control.get("diff") or {}).get("subjects"))
        if unpaired:
            self.stdout.write(self.style.WARNING(
                "  stage 8 declares no diff subjects for %s, so those controls contribute no "
                "verdict to reconcile" % ", ".join(unpaired)))

    def _run(self, stage6, stage8, control_ids, options) -> int:
        from assessments.tests._estate import build_base_estate, reconcile
        from assessments.tests._seed import seed_controls

        # The Controls and ControlQueries half, through the ONE seeder that takes its field list
        # from the same place the importer does. Not reimplemented here: `_seed.py`'s own
        # docstring records what hand-rolling it cost twice.
        controls = seed_controls(control_ids)
        self.stdout.write(f"\n### CONTROLS SEEDED: {len(controls)}")

        station, appliances, points = build_base_estate(
            stage6, panorama_managed=not options["local_station"])
        self.stdout.write(
            f"### ESTATE BUILT: {len(appliances)} appliance(s), {len(points)} enforcement "
            f"point(s)")
        for serial, appliance in sorted(appliances.items()):
            self.stdout.write(f"    {serial}  {appliance.hostname}  "
                              f"{appliance.software_version or '(no version)'}")

        self._normalize(station)
        counts = self._subject_rows(controls, stage8)
        self._findings(stage6, stage8)
        verdicts = reconcile(stage6, stage8)
        mismatches = self._report_reconciliation(verdicts)
        self._tables(controls, options, counts)
        return mismatches

    def _normalize(self, station) -> None:
        """Through the COMMITTED normalizers, in the committed order, with no device involved.

        `renormalize_in_scope_configuration` is the one entry point that re-runs every
        normalizer against already-collected snapshots "without contacting the device at all",
        as its own docstring puts it. Calling it rather than a per-domain list of normalizers is
        what stops this command needing a per-domain list AND what keeps the ordering
        obligations - which that function documents at length and which matter, several
        normalizers reading rows a previous one wrote - out of this file entirely.
        """
        from optivedge_integrations.integrations.platforms.pan_os.flows import (
            renormalize_in_scope_configuration)

        from assessments.tests._estate import (
            SUPPLEMENTAL_NORMALIZERS, run_supplemental_normalizers)

        result = renormalize_in_scope_configuration(station)
        failures = []
        for attribute in dir(result):
            if not attribute.endswith("_failures"):
                continue
            for failure in getattr(result, attribute) or []:
                failures.append((attribute, getattr(failure, "kind", ""),
                                 getattr(failure, "error_text", "")))
        # ANY NORMALISER THE FLOW LEAVES OUT, after it rather than inside it - see
        # `_estate.SUPPLEMENTAL_NORMALIZERS`, which is EMPTY since 2026-11-04: the seven passes it
        # held, the zone-protection and IKE/IPSec ones, are called from the flow now. The call
        # stays because the list is the place the next omission gets recorded.
        for name, error in run_supplemental_normalizers(station):
            failures.append(("supplemental", name, error))
        self.stdout.write("### NORMALIZED through the committed pipeline (no device contacted)")
        if SUPPLEMENTAL_NORMALIZERS:
            self.stdout.write(
                f"    plus {len(SUPPLEMENTAL_NORMALIZERS)} normalizer(s) the flow omits: "
                f"{', '.join(name for _grain, name in SUPPLEMENTAL_NORMALIZERS)}")
        if failures:
            # Each normaliser has its own try/except upstream, so one failing does not stop the
            # rest - which means a failure here is silent unless it is printed. A domain whose
            # own normaliser is in this list cannot be trusted above, and reconciliation is what
            # turns that into a non-zero exit.
            self.stdout.write(self.style.WARNING(
                f"    {len(failures)} normalizer(s) reported a failure:"))
            for attribute, kind, error in failures:
                self.stdout.write(f"      {attribute} {kind}: {error}")
        else:
            self.stdout.write("    every normalizer completed")

    def _subject_rows(self, controls, stage8=None) -> dict[str, int]:
        """A census of the subject rows the normalizers actually wrote, per model.

        Printed because a row count is the first thing that tells a reader whether the estate
        came out at all - and because a silently empty one is precisely what trap 1 produces.

        IT ASKED `DOMAINS` ALONE UNTIL 2026-11-02, AND THAT MADE IT SILENT ON EXACTLY THE RUN
        THAT NEEDS IT. A domain reaches stage 9 with no `FindingsDomain` entry - writing one is
        the stage's own job - so for a shape-B run this loop matched nothing and the section
        printed an EMPTY LIST, which reads as "no models to count" and not as "I cannot tell
        you". `globalprotect-portal` met it with all three of its subject models at zero rows,
        and the heading above those zeros said nothing at all. The three domains this command
        was proven on were FINISHED domains whose entries already existed, which is why it
        survived.

        So `DOMAINS` is consulted first - it is the authority on what a tab presents - and stage
        8's own `catalog.target_model` fills in any control type it does not cover yet. That
        declaration exists for every control before stage 9 starts, which is the property that
        makes the census available to the run that has not written a sheet.
        """
        from django.apps import apps

        from assessments.artifacts.domains import DOMAINS

        wanted = {control.control_type for control in controls}
        counts: dict[str, int] = {}
        covered: set[str] = set()
        for domain in DOMAINS:
            spec = domain.spec
            for control_type in spec.control_types:
                if control_type not in wanted:
                    continue
                model = spec.subject_model(spec.kind_for(control_type))
                covered.add(control_type)
                counts.setdefault(model._meta.label, model.objects.count())
        awaiting = sorted(wanted - covered)
        for control_id, control in sorted((stage8 or {}).get("controls", {}).items()):
            catalog = control.get("catalog") or {}
            if catalog.get("control_type") not in awaiting:
                continue
            label = catalog.get("target_model")
            if not label or label in counts:
                continue
            try:
                model = apps.get_model(label)
            except (LookupError, ValueError):
                self.stdout.write(self.style.WARNING(
                    f"    stage 8 names {label!r} for {control_id} and this installation has "
                    f"no such model, so its rows cannot be counted"))
                continue
            counts[model._meta.label] = model.objects.count()
        self.stdout.write("### SUBJECT ROWS WRITTEN")
        if not counts:
            self.stdout.write(self.style.WARNING(
                "    NOTHING TO COUNT. No `FindingsDomain` covers these control types and stage "
                "8 names no target model either, so this says nothing about whether the estate "
                "came out."))
        for label, count in sorted(counts.items()):
            flag = "   <-- EMPTY" if count == 0 else ""
            via = "" if label in {
                d.spec.subject_model(d.spec.kind_for(t))._meta.label
                for d in DOMAINS for t in d.spec.control_types if t in covered} else \
                "   (from stage 8's target_model: no findings tab for it yet)"
            self.stdout.write(f"    {label:<56} {count}{flag}{via}")
        return counts

    def _findings(self, stage6, stage8) -> None:
        from assessments.finding_run import regenerate_findings
        from assessments.tests._estate import findings_by_control

        result = regenerate_findings()
        self.stdout.write(
            f"\n### FINDINGS GENERATED: {result.findings_created} "
            f"({result.controls_evaluated} controls evaluated, "
            f"{result.skipped_queries} queries skipped)")
        if result.skipped_queries:
            # A query that no longer compiles makes its control contribute nothing, which reads
            # exactly like a clean result - `finding_run.summarise_run` makes the same point.
            self.stdout.write(self.style.WARNING(
                "    SKIPPED QUERIES ABOVE ZERO: a query that will not compile contributes no "
                "finding and reads exactly like a clean control."))
        produced = findings_by_control()
        for control_id in sorted(stage8.get("controls") or {}):
            self.stdout.write(f"    {control_id:<14} {len(produced.get(control_id) or [])} "
                              f"finding(s)")

    def _report_reconciliation(self, verdicts) -> int:
        self.stdout.write("\n### RECONCILIATION AGAINST STAGE 8'S DIFF")
        mismatches = 0
        for verdict in verdicts:
            if not verdict.ok:
                mismatches += 1
            note = "" if verdict.agrees else "   (stage 8 itself DISAGREED with stage 6 here)"
            self.stdout.write(
                "  %-14s %-24s stage8=%-20s %-9s | built=%-20s %-9s %s%s" % (
                    verdict.control_id, verdict.subject,
                    verdict.expected_produces, verdict.expected_severity or "-",
                    verdict.got_produces, verdict.got_severity or "-",
                    "OK" if verdict.ok else "*** MISMATCH", note))
        line = f"\n  verdicts reconciled: {len(verdicts)} | MISMATCHES: {mismatches}"
        self.stdout.write(self.style.ERROR(line) if mismatches
                          else self.style.SUCCESS(line))
        return mismatches

    def _tables(self, controls, options, counts) -> None:
        from assessments.artifacts.domains import DOMAINS, DOMAIN_BY_SLUG
        from assessments.artifacts.sheets.findings import (
            ALL_TESTED_COLUMNS, build_findings_table)

        wanted = {control.control_type for control in controls}
        if options["tabs"]:
            slugs = list(options["tabs"])
            unknown = [slug for slug in slugs if slug not in DOMAIN_BY_SLUG]
            if unknown:
                raise CommandError(f"no findings tab with slug(s): {', '.join(unknown)}")
        else:
            # Every tab whose spec covers a control type under test. Derived rather than
            # declared per domain: a pipeline domain's controls can land on tabs in three
            # different categories, and `artifacts/domains.py` is the only thing that knows
            # which - `ipsec-crypto`'s own run found one of its verdicts had no tab at all.
            slugs = [domain.slug for domain in DOMAINS
                     if wanted & set(domain.spec.control_types)]

        for slug in slugs:
            table = build_findings_table(
                DOMAIN_BY_SLUG[slug].spec,
                tested=None if options["workbook_columns"] else ALL_TESTED_COLUMNS)
            surface = "WORKBOOK" if options["workbook_columns"] else "LIVE PAGE"
            self.stdout.write("\n" + "=" * 94)
            self.stdout.write(
                f"### TAB {slug!r}  title={table.title!r}  category={table.category!r}  "
                f"surface={surface}")
            self.stdout.write(f"  {len(table.headers)} headings, {len(table.rows)} rows")
            raw = [header for header in table.headers if "_" in header]
            self.stdout.write("\n  HEADINGS, in order (>>> reads as a raw Django field name):")
            for index, header in enumerate(table.headers):
                self.stdout.write("    %2d %s %s" % (
                    index, ">>>" if "_" in header else "   ", header))
            self.stdout.write(f"\n  RAW HEADINGS: {len(raw)} of {len(table.headers)}")
            self._fires_when(table)
            if options["rows"]:
                self._dump_rows(table, options["rows"])

    def _fires_when(self, table) -> None:
        """`Fires when (failing condition)` is built from the clause's own FIELD NAME and
        consults `setting_labels` nowhere, so grepping headings for an underscore is blind to
        it. Printed for that reason: the worst raw-name case does not appear in a heading."""
        column = "Fires when (failing condition)"
        self.stdout.write(f"\n  {column!r} CELLS - the heading check above cannot see these:")
        if column not in table.headers:
            self.stdout.write("     (column absent from this tab)")
            return
        index = table.headers.index(column)
        seen: dict[str, int] = {}
        for row in table.rows:
            seen[str(row[index])] = seen.get(str(row[index]), 0) + 1
        for text, count in sorted(seen.items()):
            self.stdout.write("     %s x%-3d %s" % (
                ">>>" if "_" in text else "   ", count, text))
        self.stdout.write("     %d of %d distinct conditions carry a raw field name" % (
            sum(1 for text in seen if "_" in text), len(seen)))

    def _dump_rows(self, table, limit) -> None:
        marks: dict[int, set[int]] = {}
        for row_index, column_index in table.implicated:
            marks.setdefault(row_index, set()).add(column_index)
        self.stdout.write("\n  ROWS (every cell), value-at-fault cells in [brackets]:")
        for row_index, row in enumerate(table.rows):
            if row_index >= limit:
                self.stdout.write(f"     ... {len(table.rows) - limit} more")
                break
            meta = table.row_meta[row_index] if table.row_meta else None
            self.stdout.write(f"   --- row {row_index}  meta={meta}")
            for column_index, cell in enumerate(row):
                marked = column_index in marks.get(row_index, set())
                self.stdout.write("        %-46s %s%s%s" % (
                    table.headers[column_index], "[" if marked else "",
                    str(cell).replace("\n", " / "), "]" if marked else ""))
