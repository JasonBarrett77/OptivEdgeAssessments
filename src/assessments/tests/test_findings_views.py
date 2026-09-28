"""The findings pages: the workbook's tables, on screen.

Jason, 2026-09-25: "The live findings views and page should closely match the xlsx artifact."
They match by being the same table - `artifacts.build_findings_table` - rather than by two
layouts being kept in step, so most of what is worth testing here is that the page really is
that table and that the order really is the workbook's.
"""

from __future__ import annotations

from datetime import date
from unittest import mock

from django.test import TestCase
from django.urls import resolve, reverse
from django.utils import timezone

from assessments import views
from assessments.artifacts import ArtifactBuildError, workbook_filename
from assessments.artifacts import domains as artifact_domains
from assessments.finding_run import regenerate_findings
from assessments.models import LoginBannerFinding
from assessments.tests._seed import seed_controls
from optivedge.models import ApplicationEnvironment
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, LoginBanner, ManagementStation, Snapshot)


def build_estate(hostname="fw-findings", banner=""):
    station = ManagementStation.objects.create(
        station_type=ManagementStation.StationType.PAN_PANORAMA, hostname=f"pano.{hostname}")
    group = ApplianceGroup.objects.create(
        management_station=station, name=f"g-{hostname}",
        group_type=ApplianceGroup.TYPE_STANDALONE)
    appliance = Appliance.objects.create(
        management_station=station, appliance_group=group,
        serial_number=f"S-{hostname}", hostname=hostname)
    snapshot = Snapshot.objects.create(
        management_station=station, appliance=appliance,
        source_type="show_merged_config", collected_at=timezone.now(), payload={})
    LoginBanner.objects.create(
        management_station=station, appliance=appliance, source_snapshot=snapshot,
        text=banner, acknowledgement_required=False)
    return appliance


class FindingsDomainPageTests(TestCase):
    def setUp(self):
        self.appliance = build_estate()
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()
        self.url = reverse("assessment_findings_domain", kwargs={"slug": "login-banner"})

    def test_the_page_is_the_workbook_table(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["table"].title, "Login Banner")
        self.assertEqual(len(response.context["rows"]), LoginBannerFinding.objects.count())

    def test_a_finding_is_named_by_its_reference(self):
        """F-0001 and nothing else: the same name this finding carries in the workbook and in
        every other artifact."""
        finding = LoginBannerFinding.objects.get()

        response = self.client.get(self.url)

        self.assertEqual(response.context["rows"][0][0]["value"], finding.reference)
        self.assertContains(response, finding.reference)

    def test_it_carries_provenance_and_the_firing_condition(self):
        """Asked for on every page, whatever the workbook tab carries."""
        headers = self.client.get(self.url).context["table"].headers

        self.assertIn("Provenance", headers)
        self.assertIn("Fires when (failing condition)", headers)

    def test_the_control_cell_opens_the_control(self):
        response = self.client.get(self.url)
        control_column = response.context["table"].headers.index("Control ID")
        cell = response.context["rows"][0][control_column]

        self.assertTrue(cell["control_url"])
        self.assertEqual(self.client.get(cell["control_url"]).status_code, 200)

    def test_the_value_at_fault_is_marked(self):
        """The workbook bolds it on amber; the page marks the same cell."""
        response = self.client.get(self.url)

        self.assertTrue(any(cell["implicated"] for cell in response.context["rows"][0]))

    def test_an_unknown_domain_is_a_404(self):
        response = self.client.get(
            reverse("assessment_findings_domain", kwargs={"slug": "nonsense"}))

        self.assertEqual(response.status_code, 404)

    def test_every_domain_renders(self):
        """Twenty-two pages from one view: a spec that the view cannot draw is a 500 nobody
        sees until they open that page."""
        for domain in artifact_domains.DOMAINS:
            with self.subTest(domain.slug):
                response = self.client.get(
                    reverse("assessment_findings_domain", kwargs={"slug": domain.slug}))
                self.assertEqual(response.status_code, 200)


class FindingsSummaryPageTests(TestCase):
    def setUp(self):
        build_estate()
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()
        self.url = reverse("assessment_findings_summary")

    def test_it_totals_every_finding(self):
        response = self.client.get(self.url)

        self.assertEqual(response.context["total"], LoginBannerFinding.objects.count())

    def test_it_groups_by_the_products_own_categories(self):
        response = self.client.get(self.url)

        self.assertEqual([c["label"] for c in response.context["categories"]],
                         ["Policies", "Objects", "Network", "Device"])

    def test_it_links_to_every_domain(self):
        response = self.client.get(self.url)
        linked = {d["slug"] for c in response.context["categories"] for d in c["domains"]}

        self.assertEqual(linked, {domain.slug for domain in artifact_domains.DOMAINS})

    def test_a_domain_with_nothing_wrong_says_so(self):
        """"No findings" rather than 0: this is the reference surface, and a bare zero reads as
        a column nobody filled in."""
        response = self.client.get(self.url)

        self.assertContains(response, "No findings")


class DomainOrderTests(TestCase):
    """The tab strip and these pages are one order, because they are one list."""

    def test_the_workbook_builds_its_findings_tabs_from_the_domains(self):
        from assessments.artifacts import workbook

        self.assertEqual(len(workbook.findings_sheets()), len(artifact_domains.DOMAINS) + 1)

    def test_the_domains_run_in_the_products_category_order(self):
        from assessments.configuration_navigation import CATEGORIES
        from assessments.views import findings_domain_category

        ranks = [CATEGORIES.index(findings_domain_category(domain))
                 for domain in artifact_domains.DOMAINS]

        self.assertEqual(ranks, sorted(ranks))

    def test_every_slug_is_unique_and_url_shaped(self):
        slugs = [domain.slug for domain in artifact_domains.DOMAINS]

        self.assertEqual(len(slugs), len(set(slugs)))
        for slug in slugs:
            self.assertRegex(slug, r"^[a-z0-9-]+$")


class ImplicatedValueTests(TestCase):
    """The marked cell follows the FINDING, never a rule re-derived at render time.

    Ported from the password-complexity device tab, which this surface replaced. PAN-AUTH-010
    is the case that would break a "higher is worse" shortcut: never-expires and
    expires-too-rarely are both findings, and sixty days is not, so a page that marked cells by
    comparing values would get one of the three wrong.
    """

    FIELD = "expiration_period"

    def setUp(self):
        from assessments.models import AssessmentRun, Control, ControlQuery
        from optivedge_integrations.integrations.models import PasswordComplexityPolicy

        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.mark")
        self.run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(), completed_at=timezone.now())
        self.control = Control.objects.create(
            control_id="PAN-AUTH-010", name="Password expiry",
            control_type=Control.ControlType.PASSWORD_COMPLEXITY,
            description="x", default_severity=Control.Severity.MEDIUM,
            target_model="integrations.PasswordComplexityPolicy")
        ControlQuery.objects.create(
            control=self.control, name="Baseline", is_baseline=True, is_active=True,
            canonical_query={
                "model": "integrations.PasswordComplexityPolicy", "operator": "or",
                "clauses": [{"field": self.FIELD, "op": "eq", "value": 0}]})
        self.policy_model = PasswordComplexityPolicy

    def _policy(self, hostname, period):
        appliance = Appliance.objects.create(
            management_station=self.station, serial_number=f"S-{hostname}", hostname=hostname)
        snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return self.policy_model.objects.create(
            management_station=self.station, appliance=appliance, source_snapshot=snapshot,
            expiration_period=period)

    def _fire(self, policy):
        from assessments.models import PasswordComplexityFinding

        return PasswordComplexityFinding.objects.create(
            assessment_run=self.run, control=self.control, password_complexity_policy=policy,
            severity=self.control.default_severity, title="x", subject_name=policy.appliance.hostname)

    def test_only_the_row_whose_control_fired_is_marked(self):
        never = self._policy("fw-never", 0)
        self._policy("fw-fine", 60)
        self._fire(never)

        url = reverse("assessment_findings_domain", kwargs={"slug": "password-complexity"})
        response = self.client.get(url)
        headers = response.context["table"].headers

        # One row: the clean appliance is not a finding, so this surface never shows it.
        self.assertEqual(len(response.context["rows"]), 1)
        marked = {headers[i] for i, cell in enumerate(response.context["rows"][0])
                  if cell["implicated"]}
        self.assertIn(self.FIELD, {h.lower().replace(" ", "_") for h in marked})


class WorkbookDownloadTests(TestCase):
    """The workbook, from the page that is its Summary tab.

    Synchronous on purpose for now - Jason, 2026-09-28: "synchronously is fine for now" - so
    there is no job, no stored artifact and nothing to poll. What IS worth pinning is the
    guard path: `ArtifactBuildError` is catchable precisely so a refused build reaches the
    reader as a sentence instead of a 500 or, worse, a wrong file.
    """

    def setUp(self):
        build_estate()
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()
        self.url = reverse("assessment_findings_workbook")

    def test_it_returns_a_workbook(self):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], views.XLSX_CONTENT_TYPE)
        self.assertTrue(response["Content-Disposition"].startswith("attachment;"))
        # An .xlsx is a zip. Checking the magic beats checking the length, which a stub would
        # also satisfy.
        self.assertEqual(bytes(response.content[:2]), b"PK")

    def test_the_summary_page_offers_it(self):
        response = self.client.get(reverse("assessment_findings_summary"))

        self.assertContains(response, self.url)
        self.assertContains(response, "Download Workbook")

    def test_a_refused_build_says_which_guard_and_why(self):
        """The whole reason `ArtifactBuildError` stopped being a `SystemExit`. A worker that
        dies on a guard, or a page that swallows it, both end with somebody shipping a
        workbook nobody checked."""
        with mock.patch("assessments.views.build_workbook",
                        side_effect=ArtifactBuildError("PAN-MGT-007 reached no tab")):
            response = self.client.get(self.url, follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "PAN-MGT-007 reached no tab")
        self.assertEqual(response.request["PATH_INFO"], reverse("assessment_findings_summary"))

    def test_the_url_is_not_read_as_a_domain_slug(self):
        """`findings/<slug>/` would happily match "workbook" and 404, which is the kind of
        routing bug that only shows up once somebody clicks the button."""
        self.assertNotIn("workbook", {domain.slug for domain in artifact_domains.DOMAINS})
        self.assertEqual(resolve(self.url).func.view_class, views.FindingsWorkbookView)


class WorkbookFilenameTests(TestCase):
    """What the browser is told to call it. Three parts in the order a consultant sorting a
    directory wants: who, which engagement, when."""

    def test_it_names_the_client_the_opportunity_and_the_build_date(self):
        environment = ApplicationEnvironment.objects.create(
            client_name="Acme Corporation", client_short_name="Acme",
            opportunity_number="OP-1234567")

        self.assertEqual(
            workbook_filename(environment, today=date(2026, 9, 28)),
            "acme-op-1234567-assessment-2026-09-28.xlsx")

    def test_an_unconfigured_deployment_still_gets_a_file(self):
        """A deployment with no `ApplicationEnvironment` is a real state - the lab spends its
        first minutes in it - and not worth refusing a download over."""
        self.assertEqual(workbook_filename(None, today=date(2026, 9, 28)),
                         "assessment-2026-09-28.xlsx")

    def test_a_client_name_cannot_break_out_of_the_header(self):
        """Client names are free text on their way into a `Content-Disposition` header, where
        a quote or a newline would be a header-splitting bug rather than a cosmetic one."""
        environment = ApplicationEnvironment(
            client_name='Acme" ; drop\nthings', client_short_name="",
            opportunity_number="OP-7654321")

        filename = workbook_filename(environment, today=date(2026, 9, 28))

        self.assertNotIn('"', filename)
        self.assertNotIn("\n", filename)
        self.assertNotIn(";", filename)
        self.assertTrue(filename.endswith("-assessment-2026-09-28.xlsx"))

    def test_the_download_uses_it(self):
        ApplicationEnvironment.objects.create(
            client_name="Acme Corporation", client_short_name="Acme",
            opportunity_number="OP-1234567")
        build_estate()
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

        response = self.client.get(reverse("assessment_findings_workbook"))

        self.assertIn("acme-op-1234567-assessment-", response["Content-Disposition"])
