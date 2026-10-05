"""The engineer-detail workbook, once it stopped being a script.

The layout was proven by building it against the lab over and over; what was never proven is
the part that only matters inside a long-running process. Two globals and a `SystemExit` were
harmless while the prototype built one workbook and exited, and are not harmless here:

* the anchor map was a module dict, so a second workbook inherited the first one's row
  numbers and linked to the WRONG ROW - silently
* the format caches were keyed by `id(workbook)`, and CPython reuses an address once an
  object is freed
* `SystemExit` derives from `BaseException`, so a guard would take a worker down rather than
  return an error

So these tests are mostly about isolation and refusal, not about layout.
"""

from __future__ import annotations

import contextlib
import datetime
import io
import re
import zipfile
from pathlib import Path

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from assessments.artifacts import ArtifactBuildError, build_workbook
from assessments.artifacts import layout, workbook as workbook_module
from assessments.artifacts.context import WorkbookBuild
from assessments.finding_run import regenerate_findings
from assessments.models import LoginBannerFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    LoginBanner,
    ManagementStation,
    Snapshot,
)

ARTIFACTS = Path(layout.__file__).resolve().parent


def sheet_names(content: bytes) -> list[str]:
    """The tab names, read from the file itself rather than from what built it."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        book = archive.read("xl/workbook.xml").decode("utf-8")
    return re.findall(r'<sheet name="([^"]+)"', book)


def shared_strings(content: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        return archive.read("xl/sharedStrings.xml").decode("utf-8")


class WorkbookBuildTests(TestCase):
    def test_it_builds_on_an_estate_with_nothing_in_it(self):
        """A fresh deployment, or one whose collection has not run. Every tab still draws."""
        content, reports = build_workbook()

        self.assertTrue(content.startswith(b"PK"))
        self.assertIn("Summary: 28 tabs linked, 0 findings in total", reports[0])

    def test_the_summary_is_the_first_tab(self):
        names = sheet_names(build_workbook()[0])

        self.assertEqual(names[0], "Summary")
        # 28 findings tabs plus the Summary. Coverage joined them on 2026-10-02.
        self.assertEqual(len(names), 29)

    def test_a_control_type_with_no_active_control_still_draws_its_tab(self):
        """It used to raise IndexError: the category came from the controls that LOADED, and
        deactivating the one control of a type left none to read it from."""
        seed_controls(["PAN-MGT-007"])
        from assessments.models import Control

        Control.objects.update(is_active=False)

        self.assertIn("Login Banner", sheet_names(build_workbook()[0]))


class WorkbookContentTests(TestCase):
    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.artifact")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-artifact",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-artifact", hostname="fw-artifact")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        self.run = regenerate_findings().assessment_run

    def test_a_finding_reaches_its_tab_by_its_reference(self):
        finding = LoginBannerFinding.objects.get()
        content, _reports = build_workbook()

        self.assertIn(finding.reference, shared_strings(content))

    def test_the_appliance_it_is_about_is_named(self):
        content, _reports = build_workbook()

        self.assertIn("fw-artifact", shared_strings(content))


class WorkbookIsolationTests(TestCase):
    """Two workbooks in one process must not share anything. This is the whole reason the
    move was not a copy."""

    def test_anchors_do_not_survive_between_builds(self):
        first = WorkbookBuild(workbook=object())
        layout.register_row_anchor(first, "control", 7, "Controls", 5, 9)
        second = WorkbookBuild(workbook=object())

        self.assertIn(("control", 7), first.anchors)
        self.assertEqual(second.anchors, {})

    def test_a_format_belongs_to_one_workbook(self):
        class FakeWorkbook:
            def add_format(self, properties):
                return ("format", id(self), tuple(sorted(properties.items())))

        first = WorkbookBuild(workbook=FakeWorkbook())
        second = WorkbookBuild(workbook=FakeWorkbook())

        self.assertNotEqual(first.format("link", {"bold": True}),
                            second.format("link", {"bold": True}))
        self.assertEqual(first.format("link", {"bold": True}),
                         first.format("link", {"bold": True}))

    def test_the_module_holds_no_build_state(self):
        """The bug was invisible for as long as the process exited after one workbook."""
        source = (ARTIFACTS / "layout.py").read_text(encoding="utf-8")

        self.assertNotIn("ANCHORS", source)
        self.assertNotIn("id(workbook)", source)

    def test_building_twice_gives_two_good_workbooks(self):
        first, _ = build_workbook()
        second, _ = build_workbook()

        self.assertEqual(sheet_names(first), sheet_names(second))
        self.assertTrue(second.startswith(b"PK"))


class WorkbookGuardTests(TestCase):
    def test_a_finding_on_no_tab_refuses_the_build(self):
        """The guard that matters most: a workbook silently missing a finding is worse than
        no workbook, because it is the reference document."""
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.guard")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-guard",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-guard", hostname="fw-guard")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

        with self.assertRaises(ArtifactBuildError) as raised:
            workbook_module.check_every_finding_reached_a_tab([])

        self.assertIn("is on no tab", str(raised.exception))

    def test_tabs_out_of_the_summary_order_refuse_the_build(self):
        from assessments.artifacts.layout import SheetInfo

        out_of_order = [
            SheetInfo(title="a", description="", count="", category="Device",
                      by_severity={"high": 1}, report=""),
            SheetInfo(title="b", description="", count="", category="Policies",
                      by_severity={"high": 1}, report=""),
        ]

        with self.assertRaises(ArtifactBuildError):
            workbook_module.check_tabs_follow_the_summary(out_of_order)

    def test_no_guard_reaches_for_SystemExit(self):
        """It derives from BaseException: under a web server it takes the worker down, and a
        caller's `except Exception` never sees it."""
        offenders = [
            path.relative_to(ARTIFACTS)
            for path in sorted(ARTIFACTS.rglob("*.py"))
            # `raise SystemExit`, not the word - errors.py explains why it is gone.
            if "raise SystemExit" in path.read_text(encoding="utf-8")
        ]

        self.assertEqual(offenders, [])


class TimestampTests(TestCase):
    """Every timestamp column in the workbook is headed "(UTC)"."""

    def test_an_aware_timestamp_is_converted_rather_than_printed_as_it_stands(self):
        somewhere_else = datetime.timezone(datetime.timedelta(hours=-4))
        moment = datetime.datetime(2026, 9, 24, 8, 30, 0, tzinfo=somewhere_else)

        self.assertEqual(layout.utc(moment), "2026-09-24 12:30:00")

    def test_a_naive_timestamp_is_read_as_utc(self):
        """Which is where they come from - a `collected_at` Django stored in UTC - and not
        machine-local, which is what `astimezone` would have assumed."""
        moment = datetime.datetime(2026, 9, 24, 8, 30, 0)

        self.assertEqual(layout.utc(moment), "2026-09-24 08:30:00")

    def test_nothing_is_an_em_dash(self):
        self.assertEqual(layout.utc(None), layout.NONE)


class FindingsTableTests(TestCase):
    """The table both surfaces render.

    The workbook and the live findings pages are meant to match. The only way they stay
    matched is by being one table: everything that decides WHAT a row says lives in
    `build_findings_table`, and each surface only decides how to draw it.
    """

    def _table(self, spec=None, **kwargs):
        from assessments.artifacts import build_findings_table
        from assessments.artifacts.sheets import objects
        from assessments.models import Control

        return build_findings_table(
            spec or objects.SPEC_BY_TYPE[Control.ControlType.LOGIN_BANNER], **kwargs)

    def test_every_row_is_as_wide_as_the_columns(self):
        table = self._table()

        for row in table.rows:
            self.assertEqual(len(row), len(table.columns))

    def test_it_opens_with_the_finding_and_the_control(self):
        """One layout for every domain: which finding, which control, how bad, and why."""
        table = self._table()

        self.assertEqual(table.headers[:6], [
            "Finding #", "Control ID", "Control", "Severity", "Severity basis", "Status"])

    def test_a_surface_can_ask_for_provenance_the_workbook_tab_omits(self):
        """Jason, 2026-09-25: "can we add the provenance data, even if both presentation
        surfaces don't use it?"

        The policy tab passes `tested_columns=()` because its own columns already show every
        field its controls test. That is a decision about one TAB, not about the data, so a
        surface can ask for the provenance and the firing condition anyway.
        """
        from assessments.artifacts import ALL_TESTED_COLUMNS
        from assessments.artifacts.sheets import security_rules

        default = self._table(security_rules.SPEC)
        asked = self._table(security_rules.SPEC, tested=ALL_TESTED_COLUMNS)

        self.assertNotIn("Provenance", default.headers)
        self.assertIn("Provenance", asked.headers)
        self.assertIn("Fires when (failing condition)", asked.headers)

    def test_it_reports_the_domain_its_category_and_its_severities(self):
        table = self._table()

        self.assertEqual(table.title, "Login Banner")
        self.assertEqual(table.category, "Device")
        self.assertTrue(table.description)
        self.assertEqual(table.by_severity, {})

    def test_a_finding_becomes_exactly_one_row(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.table")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-table",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-table", hostname="fw-table")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

        table = self._table()
        finding = LoginBannerFinding.objects.get()

        self.assertEqual(len(table.rows), 1)
        self.assertEqual(table.rows[0][0], finding.reference)
        self.assertEqual(table.by_severity, {finding.severity: 1})


class FiringConditionTests(TestCase):
    """"Fires when" is prose over a control's baseline query, and it is read by a client.

    It used to RAISE on an operator it had no phrasing for, which nothing noticed because the
    only tabs carrying that column used five of the twelve operators. Asking for it on every
    findings page surfaced two - `exactly` and `contains` - as 500s.
    """

    def test_every_operator_a_control_can_use_has_a_phrasing(self):
        """A test rather than a runtime check: this fires when an operator is ADDED, not when
        someone opens the page that happens to use it."""
        from assessments.artifacts.sheets.findings import (
            NEGATED_OPERATORS, OPERATORS, UNARY_OPERATORS)
        from assessments.search.registry import MODEL_REGISTRY

        available = {op
                     for entry in MODEL_REGISTRY.values()
                     for operators in entry["field_operators"].values()
                     for op in operators}
        phrased = set(OPERATORS) | set(UNARY_OPERATORS)

        self.assertEqual(sorted(available - phrased), [])
        # Negation is offered on every comparison, so a phrasing missing there reads as the
        # opposite of what the control asserts.
        self.assertEqual(sorted(set(OPERATORS) - set(NEGATED_OPERATORS)), [])

    def test_the_address_set_operators_say_what_the_spec_locked(self):
        """`equals` is whole-set equality and `exactly` is exact membership - different
        questions, and the names do not say which is which. The phrasings come from the locked
        meanings in docs/security-rule-search-spec.md."""
        from assessments.artifacts.sheets.findings import OPERATORS

        self.assertEqual(OPERATORS["equals"], "is exactly")
        self.assertEqual(OPERATORS["exactly"], "includes exactly")
        self.assertEqual(OPERATORS["intersects"], "overlaps")

    def test_an_unphrased_operator_prints_rather_than_raising(self):
        """A findings page must not vanish because one condition reads awkwardly."""
        from assessments.artifacts.sheets.findings import render_node
        from assessments.models import Control

        control = Control(control_id="PAN-TEST-009")
        rendered = render_node(
            control, {"field": "name", "op": "sounds_like", "value": "x"})

        self.assertEqual(rendered, "name sounds_like x")


class EveryDomainDrawsWithTheWholeCatalogTests(TestCase):
    """Every findings domain, with every control the catalog ships, on an empty estate.

    Two bugs got through the suite and onto the running app on 2026-10-05, both because no test
    combined those three things:

    * PAN-POL-002 tests `source_breadth_known`, a SEARCH field with no column behind it, and
      `build_findings_table` refuses a tested field the subject model can neither store nor
      compute - "A value held on related rows needs a value_reader on the sheet". 588 tests
      passed because each control test seeds only its own control, so nothing ever built the
      security-rules table with PAN-POL-002 present.
    * The Coverage tab inherited the appliance-scoped `subject_select_related` default, and its
      subject is an address object, which has no `appliance`. `test_coverage_controls` proved
      the findings GENERATE; nothing drew them.

    Neither needs a finding, an appliance or a snapshot - the field check iterates controls, and
    `select_related` is validated when the SQL is compiled, so an empty database raises both.
    That is what makes this test cheap enough to cover all of it.
    """

    def setUp(self):
        from assessments.tests._seed import seed_control, seed_specs
        self.seeded = [seed_control(spec) for spec in seed_specs().values()]
        self._build_subjects()

    def _build_subjects(self):
        """One subject for each of the two domains whose presentation was broken, because an
        EMPTY estate does not exercise the same code.

        Django skips `prefetch_related` entirely when a queryset returns no rows, so the
        Coverage tab's prefetch named two relations that do not exist on AddressObject - a
        rule has `source_address_refs`, an address object has
        `securityrulesourceaddressref_set` - and an empty-database test passed anyway. It was
        caught by rendering against the lab. These subjects put the rows back.
        """
        from optivedge_integrations.integrations.models import (
            AddressObject,
            EnforcementNode,
            EnforcementPoint,
            SecurityRule,
            SecurityRuleSourceAddressRef,
        )
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.domains")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-domains",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-domains", hostname="fw-domains")
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        # Every enforcement point is shown on the Enforcement Points tab THROUGH a node, and
        # that tab refuses to build if one would vanish. A fixture without this is incomplete
        # rather than minimal.
        EnforcementNode.objects.create(
            management_station=station, appliance=appliance, enforcement_point=point)

        # PAN-POL-002: an allow rule broad enough to land in the critical band.
        rule = SecurityRule.objects.create(
            management_station=station, enforcement_point=point, source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL, effective_order=1, rule_position=1,
            name="rule-domains", action="allow", rule_type="universal",
            source_num_hosts=4_294_967_296, destination_num_hosts=None)
        # PAN-COV-001: an EDL a rule references and nothing ever collected.
        edl = AddressObject.objects.create(
            management_station=station, enforcement_point=point, source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL, name="edl-domains",
            namespace_type="local_vsys", namespace_value="vsys1", precedence_rank=10,
            address_type=AddressObject.TYPE_EDL, is_edl=True, edl_list_type="ip",
            value="ip", normalized_value="ip")
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule, raw_value=edl.name, position=0,
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT, address_object=edl)
        regenerate_findings()

    def test_the_two_domains_this_exists_for_actually_have_rows(self):
        """Guards the sweep below: without rows it degrades to the empty-estate check that
        already let a prefetch bug through."""
        from assessments.artifacts import ALL_TESTED_COLUMNS, build_findings_table
        from assessments.artifacts.domains import DOMAINS

        by_slug = {domain.slug: domain for domain in DOMAINS}
        for slug in ("security-rules", "coverage"):
            with self.subTest(domain=slug):
                table = build_findings_table(by_slug[slug].spec, tested=ALL_TESTED_COLUMNS)
                self.assertTrue(table.rows, f"{slug} rendered no rows")

    def test_the_controls_that_broke_it_are_actually_seeded(self):
        """Guards the tests below rather than the product. A seeder that produced nothing, or
        skipped a control type, would make them pass over an empty loop - so this names the
        three controls whose presence is the whole point rather than asserting a row count.
        """
        seeded = {control.control_id for control in self.seeded}
        for control_id in ("PAN-POL-002", "PAN-COV-001", "PAN-COV-002"):
            self.assertIn(control_id, seeded)
        self.assertGreater(len(seeded), 60, "the shipped catalog should hold dozens of controls")

    def test_every_domain_builds_its_findings_table(self):
        from assessments.artifacts import ALL_TESTED_COLUMNS, build_findings_table
        from assessments.artifacts.domains import DOMAINS

        self.assertTrue(DOMAINS)
        for domain in DOMAINS:
            with self.subTest(domain=domain.slug):
                build_findings_table(domain.spec, tested=ALL_TESTED_COLUMNS)

    def test_every_domain_builds_the_way_the_workbook_asks_for_it(self):
        """The pages pass `tested=ALL_TESTED_COLUMNS` and the workbook takes the spec's own
        columns, so the two surfaces do not exercise the same code."""
        from assessments.artifacts import build_findings_table
        from assessments.artifacts.domains import DOMAINS

        for domain in DOMAINS:
            with self.subTest(domain=domain.slug):
                build_findings_table(domain.spec)

    def test_the_whole_workbook_builds_with_every_control_active(self):
        content, _reports = build_workbook()
        self.assertTrue(content)


class DeferredPayloadTests(TestCase):
    """What the findings tabs decline to fetch.

    A joined row arrives whole, so a wide column on a joined model is paid for per ROW whether
    or not anything reads it. `Snapshot.payload` cost 1.75 GB on one tab that way before the
    snapshot left the join entirely; the `raw_*` payloads on the subjects are the same habit,
    smaller.

    The care here is in what is NOT deferred. Most JSONFields on these models are read - the
    SSH algorithm lists, bound interface names, exposed SNMP surfaces - and deferring one of
    those turns it into a query per row: slower than the problem it set out to fix, and silent.
    """

    def test_only_verbatim_vendor_payloads_are_deferred(self):
        """`raw_*`, which the query service boundary already forbids reading. A JSONField the
        tabs DO read must never appear here."""
        from assessments.artifacts import domains as artifact_domains
        from assessments.artifacts.sheets.findings import verbatim_payload_paths

        for domain in artifact_domains.DOMAINS:
            spec = domain.spec
            for control_type in spec.control_types:
                kind = spec.kind_for(control_type)
                with self.subTest(f"{domain.slug}/{kind.model.__name__}"):
                    for path in verbatim_payload_paths(kind, spec):
                        self.assertRegex(path.rsplit("__", 1)[-1], r"^raw_",
                                         f"{path} is deferred but is not a raw_* payload")

    def test_a_json_field_is_identified_by_the_model_and_not_by_its_name(self):
        """Both conditions are required. `raw_*` alone would defer a CharField called
        `raw_text`; JSONField alone would defer `ciphers` and cost a query per row."""
        import inspect

        from assessments.artifacts.sheets import findings as findings_module

        source = inspect.getsource(findings_module.verbatim_payload_paths)
        self.assertIn("JSONField", source)
        self.assertIn('startswith("raw_")', source)

    def test_deferring_adds_no_queries(self):
        """The failure this guards against. If a deferred field turns out to be read, Django
        fetches it lazily - correct output, one extra query per row, nothing raised. So each
        domain is built both ways and the counts must match.

        BOTH PATHS ARE WARMED FIRST. `ContentType.objects.get_for_model` caches per process, so
        whichever build runs first pays for it and looks one query worse. Measured without the
        warm-up this reported a +1 on all 23 domains - a constant offset, which is the shape of
        a cache miss and not of an N+1, since a lazy field would cost one query per ROW.

        Only the domains with findings in this fixture exercise it; the full check is run
        against lab data, where all 23 have rows and the counts are identical.
        """
        from unittest import mock

        from assessments.artifacts import ALL_TESTED_COLUMNS, build_findings_table
        from assessments.artifacts import domains as artifact_domains

        def count(spec, *, defer):
            whole = mock.patch(
                "assessments.artifacts.sheets.findings.verbatim_payload_paths",
                return_value=())
            with contextlib.nullcontext() if defer else whole:
                with CaptureQueriesContext(connection) as queries:
                    build_findings_table(spec, tested=ALL_TESTED_COLUMNS)
            return len(queries)

        for domain in artifact_domains.DOMAINS:
            with self.subTest(domain.slug):
                count(domain.spec, defer=True)
                count(domain.spec, defer=False)
                self.assertEqual(
                    count(domain.spec, defer=True), count(domain.spec, defer=False),
                    f"{domain.slug}: deferring changed the query count, so something reads a "
                    f"field it declines to fetch")
