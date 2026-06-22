from django.test import TestCase
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.utils import timezone

from assessments.models import (
    AssessmentRun,
    Control,
    ControlQuery,
    RuleFinding,
    RuleFindingControlQuery,
)
from optivedge.integrations.models import (
    ApplicationEnvironment,
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    ManagementPlaneProfile,
    ManagementStation,
    SecurityRule,
    SecurityRuleFromZone,
    Snapshot,
)


class ControlViewTests(TestCase):
    def setUp(self):
        ApplicationEnvironment.objects.create(
            client_name="Example Corp",
            client_short_name="EXAMPLE",
            opportunity_number="OP-1234567",
        )
        self.control = Control.objects.create(
            control_id="FW-RULE-PERMISSIVENESS-001",
            name="Ensure firewall rules are not overly permissive",
            control_type=Control.ControlType.SECURITY_RULE,
            description="Prototype control",
            rationale="Reduce attack surface.",
            audit="Review broad rules.",
            remediation="Restrict broad rules.",
            default_severity=Control.Severity.MEDIUM,
        )
        ControlQuery.objects.create(
            control=self.control,
            name="Baseline permissiveness",
            short_description="Matches permissive rules.",
            canonical_query={
                "model": "integrations.SecurityRule",
                "operator": "or",
                "clauses": [],
            },
            is_baseline=True,
            adjusted_severity=None,
        )

    def create_security_rule(self, *, name="rule-one", from_zone="trust"):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname=f"{name}.panorama.local",
        )
        group = ApplianceGroup.objects.create(
            management_station=station,
            name=f"{name}-group",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance_group=group,
            vsys_name=f"{name}-vsys",
            vsys_display_name=name,
        )
        snapshot = Snapshot.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_type="test",
            collected_at=timezone.now(),
        )
        security_rule = SecurityRule.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=1,
            rule_position=1,
            name=name,
            provenance="test",
            action="allow",
            disabled=False,
            rule_type="universal",
            description="Generated for control finding tests",
            log_start=False,
            log_end=True,
            log_setting="default",
        )
        SecurityRuleFromZone.objects.create(
            security_rule=security_rule,
            value=from_zone,
            prov="test",
            position=1,
        )
        return security_rule

    def test_control_list_view_renders(self):
        response = self.client.get(reverse("assessment_control_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.control.control_id)
        self.assertContains(response, "Run Security Rule Findings")
        self.assertContains(response, "Run Management Plane Findings")
        self.assertContains(response, "/assessments/findings/")

    def test_rule_finding_list_view_renders_empty_state(self):
        response = self.client.get(reverse("assessment_rule_finding_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Security Rule Findings")
        self.assertContains(response, "No rule findings available.")
        self.assertContains(response, reverse("assessment_rule_finding_docx_download"))
        self.assertContains(response, reverse("assessment_rule_finding_xlsx_download"))

    def test_control_detail_view_renders(self):
        response = self.client.get(
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.control.name)
        self.assertContains(response, "Security Rule")
        self.assertContains(response, "Baseline permissiveness")
        self.assertContains(
            response,
            f"/assessments/security-rules/?control={self.control.pk}",
        )
        self.assertContains(
            response,
            reverse(
                "assessment_control_query_update",
                kwargs={"pk": self.control.pk, "query_pk": self.control.queries.first().pk},
            ),
        )
        self.assertContains(
            response,
            f"/assessments/security-rules/?control_query={self.control.queries.first().pk}",
        )
        self.assertContains(
            response,
            reverse(
                "assessment_control_query_delete",
                kwargs={"pk": self.control.pk, "query_pk": self.control.queries.first().pk},
            ),
        )

    def test_control_create_view_creates_control(self):
        response = self.client.post(
            reverse("assessment_control_create"),
            {
                "control_id": "FW-RULE-PERMISSIVENESS-002",
                "name": "Ensure firewall rules are reviewed",
                "control_type": Control.ControlType.SECURITY_RULE,
                "description": "Review rule scope.",
                "rationale": "Reduce exposure.",
                "audit": "Review broad matches.",
                "remediation": "Tighten access.",
                "default_severity": Control.Severity.LOW,
                "implementation_version": "v1",
                "is_active": "on",
            },
        )

        created = Control.objects.get(control_id="FW-RULE-PERMISSIVENESS-002")
        self.assertRedirects(
            response,
            reverse("assessment_control_detail", kwargs={"pk": created.pk}),
        )

    def test_control_update_view_updates_control(self):
        response = self.client.post(
            reverse("assessment_control_update", kwargs={"pk": self.control.pk}),
            {
                "control_id": self.control.control_id,
                "name": "Updated name",
                "control_type": Control.ControlType.CONFIG,
                "description": self.control.description,
                "rationale": self.control.rationale,
                "audit": self.control.audit,
                "remediation": self.control.remediation,
                "default_severity": Control.Severity.HIGH,
                "implementation_version": "v2",
            },
        )

        self.control.refresh_from_db()
        self.assertRedirects(
            response,
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk}),
        )
        self.assertEqual(self.control.name, "Updated name")
        self.assertEqual(self.control.control_type, Control.ControlType.CONFIG)
        self.assertEqual(self.control.default_severity, Control.Severity.HIGH)
        self.assertFalse(self.control.is_active)

    def test_control_detail_hides_security_rule_action_for_non_rule_control(self):
        self.control.control_type = Control.ControlType.CONFIG
        self.control.save()

        response = self.client.get(
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk})
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(
            response,
            f"/assessments/security-rules/?control={self.control.pk}",
        )

    def test_control_delete_view_deletes_control(self):
        response = self.client.post(
            reverse("assessment_control_delete", kwargs={"pk": self.control.pk})
        )

        self.assertRedirects(response, reverse("assessment_control_list"))
        self.assertFalse(Control.objects.filter(pk=self.control.pk).exists())

    def test_control_query_create_view_renders(self):
        response = self.client.get(
            reverse("assessment_control_query_create"),
            {"control": self.control.pk},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create Query")
        self.assertContains(response, "Save Query")
        self.assertContains(response, "Baseline:")

    def test_control_query_create_view_loads_search_json_from_security_rule_builder(self):
        payload = """
        {
          "model": "integrations.SecurityRule",
          "operator": "and",
          "clauses": [
            {
              "field": "from_zone",
              "op": "eq",
              "value": "trust"
            }
          ]
        }
        """
        response = self.client.post(
            reverse("assessment_control_query_create"),
            {
                "search": payload,
                "load_from_search": "1",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "from_zone")
        self.assertContains(response, "trust")

    def test_control_query_create_view_saves_query(self):
        response = self.client.post(
            reverse("assessment_control_query_create"),
            {
                "control": self.control.pk,
                "name": "Sensitive segment calibration",
                "short_description": "Raise severity for sensitive segments.",
                "is_baseline": "",
                "adjusted_severity": Control.Severity.HIGH,
                "is_active": "on",
                "canonical_query": """
                {
                  "model": "integrations.SecurityRule",
                  "operator": "and",
                  "clauses": [
                    {
                      "field": "from_zone",
                      "op": "eq",
                      "value": "trust"
                    }
                  ]
                }
                """,
            },
        )

        self.assertRedirects(
            response,
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk}),
        )
        self.assertTrue(
            ControlQuery.objects.filter(
                control=self.control,
                name="Sensitive segment calibration",
            ).exists()
        )

    def test_control_query_update_view_updates_query(self):
        control_query = self.control.queries.first()
        response = self.client.post(
            reverse(
                "assessment_control_query_update",
                kwargs={"pk": self.control.pk, "query_pk": control_query.pk},
            ),
            {
                "control": self.control.pk,
                "name": "Updated baseline query",
                "short_description": "Updated description.",
                "is_baseline": "on",
                "adjusted_severity": "",
                "is_active": "on",
                "canonical_query": """
                {
                  "model": "integrations.SecurityRule",
                  "operator": "and",
                  "clauses": [
                    {
                      "field": "from_zone",
                      "op": "eq",
                      "value": "trust"
                    }
                  ]
                }
                """,
            },
        )

        self.assertRedirects(
            response,
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk}),
        )
        control_query.refresh_from_db()
        self.assertEqual(control_query.name, "Updated baseline query")

    def test_control_query_delete_view_deletes_query(self):
        control_query = self.control.queries.first()
        response = self.client.post(
            reverse(
                "assessment_control_query_delete",
                kwargs={"pk": self.control.pk, "query_pk": control_query.pk},
            )
        )

        self.assertRedirects(
            response,
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk}),
        )
        self.assertFalse(ControlQuery.objects.filter(pk=control_query.pk).exists())

    def test_control_query_create_view_allows_second_baseline_query(self):
        response = self.client.post(
            reverse("assessment_control_query_create"),
            {
                "control": self.control.pk,
                "name": "Second baseline",
                "short_description": "Another baseline query.",
                "is_baseline": "on",
                "adjusted_severity": "",
                "is_active": "on",
                "canonical_query": """
                {
                  "model": "integrations.SecurityRule",
                  "operator": "and",
                  "clauses": [
                    {
                      "field": "to_zone",
                      "op": "eq",
                      "value": "untrust"
                    }
                  ]
                }
                """,
            },
        )

        self.assertRedirects(
            response,
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk}),
        )
        self.assertEqual(
            ControlQuery.objects.filter(control=self.control, is_baseline=True).count(),
            2,
        )
        second_baseline = ControlQuery.objects.get(
            control=self.control,
            name="Second baseline",
        )
        self.assertIsNone(second_baseline.adjusted_severity)

    def test_control_query_create_view_allows_blank_baseline_severity(self):
        response = self.client.post(
            reverse("assessment_control_query_create"),
            {
                "control": self.control.pk,
                "name": "Blank severity baseline",
                "short_description": "Baseline without explicit severity.",
                "is_baseline": "on",
                "adjusted_severity": "",
                "is_active": "on",
                "canonical_query": """
                {
                  "model": "integrations.SecurityRule",
                  "operator": "and",
                  "clauses": [
                    {
                      "field": "application",
                      "op": "eq",
                      "value": "any"
                    }
                  ]
                }
                """,
            },
        )

        self.assertRedirects(
            response,
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk}),
        )
        query = ControlQuery.objects.get(
            control=self.control,
            name="Blank severity baseline",
        )
        self.assertIsNone(query.adjusted_severity)

    def test_control_query_create_view_ignores_posted_baseline_severity(self):
        response = self.client.post(
            reverse("assessment_control_query_create"),
            {
                "control": self.control.pk,
                "name": "Posted baseline severity",
                "short_description": "Severity should be cleared.",
                "is_baseline": "on",
                "adjusted_severity": Control.Severity.HIGH,
                "is_active": "on",
                "canonical_query": """
                {
                  "model": "integrations.SecurityRule",
                  "operator": "and",
                  "clauses": [
                    {
                      "field": "service",
                      "op": "eq",
                      "value": "any"
                    }
                  ]
                }
                """,
            },
        )

        self.assertRedirects(
            response,
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk}),
        )
        query = ControlQuery.objects.get(
            control=self.control,
            name="Posted baseline severity",
        )
        self.assertIsNone(query.adjusted_severity)

    def test_control_query_model_rejects_baseline_with_adjusted_severity(self):
        query = ControlQuery(
            control=self.control,
            name="Invalid baseline",
            short_description="Should fail model validation.",
            canonical_query={
                "model": "integrations.SecurityRule",
                "operator": "and",
                "clauses": [
                    {
                        "field": "service",
                        "op": "eq",
                        "value": "any",
                    }
                ],
            },
            is_baseline=True,
            adjusted_severity=Control.Severity.MEDIUM,
            is_active=True,
        )

        with self.assertRaises(ValidationError):
            query.full_clean()

    def test_control_run_findings_view_recreates_rule_findings(self):
        self.control.queries.all().delete()
        baseline_query = ControlQuery.objects.create(
            control=self.control,
            name="Trust baseline",
            short_description="Matches trust zone rules.",
            canonical_query={
                "model": "integrations.SecurityRule",
                "operator": "and",
                "clauses": [
                    {
                        "field": "from_zone",
                        "op": "eq",
                        "value": "trust",
                    }
                ],
            },
            is_baseline=True,
        )
        security_rule = self.create_security_rule()
        stale_run = AssessmentRun.objects.create(
            name="Previous run",
            status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(),
            completed_at=timezone.now(),
        )
        stale_finding = RuleFinding.objects.create(
            assessment_run=stale_run,
            control=self.control,
            security_rule=security_rule,
            status=RuleFinding.Status.OPEN,
            severity=Control.Severity.LOW,
            title="Stale finding",
            summary="Should be replaced.",
        )
        RuleFindingControlQuery.objects.create(
            rule_finding=stale_finding,
            control_query=baseline_query,
        )

        response = self.client.post(reverse("assessment_control_run_findings"), follow=True)

        self.assertRedirects(response, reverse("assessment_control_list"))
        self.assertFalse(RuleFinding.objects.filter(pk=stale_finding.pk).exists())
        self.assertEqual(RuleFinding.objects.count(), 1)

        finding = RuleFinding.objects.select_related("assessment_run", "control", "security_rule").get()
        self.assertEqual(finding.control, self.control)
        self.assertEqual(finding.security_rule, security_rule)
        self.assertEqual(finding.severity, Control.Severity.MEDIUM)
        self.assertEqual(finding.title, self.control.name)
        self.assertEqual(finding.assessment_run.status, AssessmentRun.Status.COMPLETED)
        self.assertEqual(finding.control_queries.count(), 1)
        self.assertEqual(finding.control_queries.first(), baseline_query)
        self.assertContains(response, "Rule findings regenerated.")

    def test_rule_finding_list_view_renders_persisted_findings(self):
        security_rule = self.create_security_rule()
        assessment_run = AssessmentRun.objects.create(
            name="Rule Findings Run",
            status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(),
            completed_at=timezone.now(),
        )
        finding = RuleFinding.objects.create(
            assessment_run=assessment_run,
            control=self.control,
            security_rule=security_rule,
            status=RuleFinding.Status.OPEN,
            severity=Control.Severity.HIGH,
            title=self.control.name,
            summary="Matched control query: Baseline permissiveness.",
        )
        RuleFindingControlQuery.objects.create(
            rule_finding=finding,
            control_query=self.control.queries.first(),
        )

        response = self.client.get(reverse("assessment_rule_finding_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.control.control_id)
        self.assertContains(response, security_rule.name)
        self.assertContains(response, "High")
        self.assertContains(response, "Open")
        self.assertContains(response, ">1<", html=False)

    def test_rule_finding_docx_download_returns_attachment(self):
        security_rule = self.create_security_rule()
        assessment_run = AssessmentRun.objects.create(
            name="Rule Findings Run",
            status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(),
            completed_at=timezone.now(),
        )
        finding = RuleFinding.objects.create(
            assessment_run=assessment_run,
            control=self.control,
            security_rule=security_rule,
            status=RuleFinding.Status.OPEN,
            severity=Control.Severity.HIGH,
            title=self.control.name,
            summary="Matched control query: Baseline permissiveness.",
        )
        RuleFindingControlQuery.objects.create(
            rule_finding=finding,
            control_query=self.control.queries.first(),
        )

        response = self.client.get(reverse("assessment_rule_finding_docx_download"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response["Content-Type"],
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertTrue(response.content.startswith(b"PK"))

    def test_rule_finding_xlsx_download_returns_attachment(self):
        security_rule = self.create_security_rule()
        assessment_run = AssessmentRun.objects.create(
            name="Rule Findings Run",
            status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(),
            completed_at=timezone.now(),
        )
        finding = RuleFinding.objects.create(
            assessment_run=assessment_run,
            control=self.control,
            security_rule=security_rule,
            status=RuleFinding.Status.OPEN,
            severity=Control.Severity.HIGH,
            title=self.control.name,
            summary="Matched control query: Baseline permissiveness.",
        )
        RuleFindingControlQuery.objects.create(
            rule_finding=finding,
            control_query=self.control.queries.first(),
        )

        response = self.client.get(reverse("assessment_rule_finding_xlsx_download"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response["Content-Type"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.assertIn("attachment;", response["Content-Disposition"])
        self.assertTrue(response.content.startswith(b"PK"))


class ManagementPlaneProfileListViewTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.test.local",
        )
        self.appliance = Appliance.objects.create(
            management_station=self.station,
            hostname="fw-test-01",
            serial_number="SN-TEST-001",
        )
        self.snapshot = Snapshot.objects.create(
            management_station=self.station,
            appliance=self.appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
        )
        self.profile = ManagementPlaneProfile.objects.create(
            management_station=self.station,
            appliance=self.appliance,
            source_snapshot=self.snapshot,
            config_source="local",
            ha_required=True,
            ha_enabled=False,
            http_disabled=False,
            telnet_disabled=False,
        )
        self.mgmt_control = Control.objects.create(
            control_id="MGMT-TEST-001",
            name="Test management control",
            control_type=Control.ControlType.MANAGEMENT_PLANE,
            description="Test",
            default_severity=Control.Severity.HIGH,
        )
        self.mgmt_query = ControlQuery.objects.create(
            control=self.mgmt_control,
            name="Baseline",
            canonical_query={
                "model": "integrations.ManagementPlaneProfile",
                "operator": "and",
                "clauses": [{"field": "ha_required", "op": "eq", "value": True}],
            },
            is_baseline=True,
        )
        self.sr_control = Control.objects.create(
            control_id="FW-TEST-001",
            name="Test security rule control",
            control_type=Control.ControlType.SECURITY_RULE,
            description="Test",
            default_severity=Control.Severity.MEDIUM,
        )
        self.sr_query = ControlQuery.objects.create(
            control=self.sr_control,
            name="Baseline",
            canonical_query={
                "model": "integrations.SecurityRule",
                "operator": "and",
                "clauses": [],
            },
            is_baseline=True,
        )

    def test_profile_list_returns_200(self):
        response = self.client.get(reverse("assessment_management_plane_profile_list"))
        self.assertEqual(response.status_code, 200)

    def test_url_name_reverses(self):
        url = reverse("assessment_management_plane_profile_list")
        self.assertEqual(url, "/assessments/management-plane-profiles/")

    def test_sidebar_includes_new_route(self):
        from optivedge.app_registry import sidebar_sections
        sections = sidebar_sections()
        assessments = next(s for s in sections if s["label"] == "Assessments")
        active_names = assessments["active_names"]
        self.assertIn("assessment_management_plane_profile_list", active_names)
        item_hrefs = [item["href"] for item in assessments["items"]]
        self.assertIn("/assessments/management-plane-profiles/", item_hrefs)

    def test_control_filter_returns_matching_profiles(self):
        response = self.client.get(
            reverse("assessment_management_plane_profile_list"),
            {"control": self.mgmt_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertTrue(ctx["show_control_severity"])
        self.assertEqual(ctx["total_row_count"], 1)
        self.assertEqual(ctx["selected_control"], self.mgmt_control)

    def test_security_rule_control_is_rejected(self):
        response = self.client.get(
            reverse("assessment_management_plane_profile_list"),
            {"control": self.sr_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertIsNone(ctx["selected_control"])
        self.assertIn("cannot be applied to management plane profiles", ctx["search_error"])
        self.assertFalse(ctx["show_control_severity"])

    def test_control_query_filter_returns_matching_profiles(self):
        response = self.client.get(
            reverse("assessment_management_plane_profile_list"),
            {"control_query": self.mgmt_query.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertEqual(ctx["total_row_count"], 1)
        self.assertFalse(ctx["search_error"])

    def test_security_rule_query_is_rejected(self):
        response = self.client.get(
            reverse("assessment_management_plane_profile_list"),
            {"control_query": self.sr_query.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertIsNone(ctx["selected_control_query"])
        self.assertIn("does not target management plane profiles", ctx["search_error"])

    def test_malformed_control_param_does_not_500(self):
        response = self.client.get(
            reverse("assessment_management_plane_profile_list"),
            {"control": "abc"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("could not be found", response.context["search_error"])

    def test_malformed_control_query_param_does_not_500(self):
        response = self.client.get(
            reverse("assessment_management_plane_profile_list"),
            {"control_query": "abc"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("could not be found", response.context["search_error"])

    def test_control_query_create_seeds_management_plane_default(self):
        response = self.client.get(
            reverse("assessment_control_query_create"),
            {"control": self.mgmt_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        initial_query = response.context["form"].initial["canonical_query"]
        self.assertEqual(initial_query["model"], "integrations.ManagementPlaneProfile")

    def test_control_query_create_seeds_security_rule_default(self):
        response = self.client.get(
            reverse("assessment_control_query_create"),
            {"control": self.sr_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        initial_query = response.context["form"].initial["canonical_query"]
        self.assertEqual(initial_query["model"], "integrations.SecurityRule")

    def test_load_from_search_with_mismatched_model_shows_error_and_restores_default(self):
        import json
        sr_payload = json.dumps({
            "model": "integrations.SecurityRule",
            "operator": "and",
            "clauses": [{"field": "from_zone", "op": "eq", "value": "trust"}],
        })
        response = self.client.post(
            f"{reverse('assessment_control_query_create')}?control={self.mgmt_control.pk}",
            {
                "search": sr_payload,
                "load_from_search": "1",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.context["load_search_error"])
        self.assertIn("integrations.SecurityRule", response.context["load_search_error"])
        initial_query = response.context["form"].initial["canonical_query"]
        self.assertEqual(initial_query["model"], "integrations.ManagementPlaneProfile")


class ControlQueryFormModelValidationTests(TestCase):
    def setUp(self):
        self.mgmt_control = Control.objects.create(
            control_id="MGMT-FORM-001",
            name="Form validation mgmt control",
            control_type=Control.ControlType.MANAGEMENT_PLANE,
            description="Test",
            default_severity=Control.Severity.MEDIUM,
        )
        self.sr_control = Control.objects.create(
            control_id="FW-FORM-001",
            name="Form validation security rule control",
            control_type=Control.ControlType.SECURITY_RULE,
            description="Test",
            default_severity=Control.Severity.MEDIUM,
        )

    def _post_query(self, control, model_label):
        from assessments.forms import ControlQueryForm
        form = ControlQueryForm({
            "control": control.pk,
            "name": "Test query",
            "short_description": "",
            "is_baseline": "on",
            "adjusted_severity": "",
            "is_active": "on",
            "canonical_query": __import__("json").dumps({
                "model": model_label,
                "operator": "and",
                "clauses": [],
            }),
        })
        return form

    def test_matching_model_is_valid(self):
        form = self._post_query(self.mgmt_control, "integrations.ManagementPlaneProfile")
        self.assertTrue(form.is_valid(), form.errors)

    def test_mismatched_model_is_invalid_for_mgmt_control(self):
        form = self._post_query(self.mgmt_control, "integrations.SecurityRule")
        self.assertFalse(form.is_valid())
        self.assertIn("canonical_query", form.errors)

    def test_mismatched_model_is_invalid_for_sr_control(self):
        form = self._post_query(self.sr_control, "integrations.ManagementPlaneProfile")
        self.assertFalse(form.is_valid())
        self.assertIn("canonical_query", form.errors)


class ControlTargetModelTests(TestCase):
    def test_security_rule_control_sets_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-001", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.SecurityRule")

    def test_management_plane_control_sets_target_model(self):
        c = Control.objects.create(
            control_id="MP-TM-001", name="MP", control_type=Control.ControlType.MANAGEMENT_PLANE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.ManagementPlaneProfile")

    def test_config_control_has_empty_target_model(self):
        c = Control.objects.create(
            control_id="CFG-TM-001", name="CFG", control_type=Control.ControlType.CONFIG,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "")

    def test_changing_to_config_clears_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-002", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.SecurityRule")
        c.control_type = Control.ControlType.CONFIG
        c.save()
        self.assertEqual(c.target_model, "")

    def test_changing_to_management_plane_updates_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-003", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.SecurityRule")
        c.control_type = Control.ControlType.MANAGEMENT_PLANE
        c.save()
        self.assertEqual(c.target_model, "integrations.ManagementPlaneProfile")

    def test_supports_security_rule_ui_uses_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-004", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertTrue(c.supports_security_rule_ui)
        self.assertFalse(c.supports_management_plane_ui)

    def test_supports_management_plane_ui_uses_target_model(self):
        c = Control.objects.create(
            control_id="MP-TM-002", name="MP", control_type=Control.ControlType.MANAGEMENT_PLANE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertFalse(c.supports_security_rule_ui)
        self.assertTrue(c.supports_management_plane_ui)


class ControlQueryTargetModelValidationTests(TestCase):
    def setUp(self):
        self.sr_control = Control.objects.create(
            control_id="SR-QVAL-001", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.mp_control = Control.objects.create(
            control_id="MP-QVAL-001", name="MP", control_type=Control.ControlType.MANAGEMENT_PLANE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )

    def _make_query(self, control, model_label):
        return ControlQuery(
            control=control,
            name="Test",
            canonical_query={"model": model_label, "operator": "and", "clauses": []},
            is_baseline=True,
        )

    def test_matching_model_passes_clean(self):
        q = self._make_query(self.sr_control, "integrations.SecurityRule")
        q.full_clean()  # should not raise

    def test_mismatched_model_fails_clean(self):
        from django.core.exceptions import ValidationError
        q = self._make_query(self.sr_control, "integrations.ManagementPlaneProfile")
        with self.assertRaises(ValidationError) as ctx:
            q.full_clean()
        self.assertIn("canonical_query", ctx.exception.message_dict)

    def test_mp_mismatched_model_fails_clean(self):
        from django.core.exceptions import ValidationError
        q = self._make_query(self.mp_control, "integrations.SecurityRule")
        with self.assertRaises(ValidationError) as ctx:
            q.full_clean()
        self.assertIn("canonical_query", ctx.exception.message_dict)

    def test_missing_model_key_fails_clean_when_target_model_set(self):
        from django.core.exceptions import ValidationError
        q = ControlQuery(
            control=self.sr_control,
            name="No model",
            canonical_query={"operator": "and", "clauses": []},
            is_baseline=True,
        )
        with self.assertRaises(ValidationError) as ctx:
            q.full_clean()
        self.assertIn("canonical_query", ctx.exception.message_dict)


class SecurityRuleListViewGuardTests(TestCase):
    def setUp(self):
        self.sr_control = Control.objects.create(
            control_id="SR-GUARD-001", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.mp_control = Control.objects.create(
            control_id="MP-GUARD-001", name="MP", control_type=Control.ControlType.MANAGEMENT_PLANE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.mp_query = ControlQuery.objects.create(
            control=self.mp_control,
            name="Baseline",
            canonical_query={"model": "integrations.ManagementPlaneProfile", "operator": "and", "clauses": [{"field": "ha_required", "op": "eq", "value": True}]},
            is_baseline=True,
        )

    def test_management_plane_control_rejected(self):
        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {"control": self.mp_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertIsNone(ctx["selected_control"])
        self.assertTrue(ctx["search_error"])
        self.assertIn("integrations.ManagementPlaneProfile", ctx["search_error"])

    def test_management_plane_query_rejected(self):
        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {"control_query": self.mp_query.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertIsNone(ctx["selected_control_query"])
        self.assertTrue(ctx["search_error"])

    def test_malformed_control_param_does_not_500(self):
        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {"control": "abc"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["search_error"])

    def test_malformed_control_query_param_does_not_500(self):
        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {"control_query": "abc"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["search_error"])


class ControlListViewNoEnvironmentTests(TestCase):
    def test_renders_without_application_environment(self):
        response = self.client.get(reverse("assessment_control_list"))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["current_catalog_state"])
        self.assertFalse(response.context["catalog_drifted"])
