from django.contrib.contenttypes.models import ContentType
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
from optivedge.models import ApplicationEnvironment
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    DeviceConfigurationProfile,
    FieldProvenance,
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
        self.assertContains(response, "Run Device Configuration Findings")
        self.assertContains(response, "View Findings")

    def test_finding_list_view_renders_empty_state(self):
        response = self.client.get(reverse("assessment_finding_list"))

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

    def test_finding_list_view_renders_persisted_findings(self):
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

        response = self.client.get(reverse("assessment_finding_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.control.control_id)
        self.assertContains(response, security_rule.name)
        self.assertContains(response, "High")
        self.assertContains(response, "Open")
        # Rows render as a Security-Rules-style rulebase table.
        self.assertContains(response, "Src Address")
        self.assertContains(response, "Dst Address")

    def _seed_findings_for_grouping(self):
        """Two rules and two controls with a spread of severities, for the grouped
        findings views. Returns (run, control_b, rule_a, rule_b, findings-by-key)."""
        run = AssessmentRun.objects.create(
            name="Grouping Run", status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(), completed_at=timezone.now(),
        )
        control_b = Control.objects.create(
            control_id="FW-RULE-LOGGING-002",
            name="Ensure logging at session end",
            control_type=Control.ControlType.SECURITY_RULE,
            description="Prototype logging control",
            default_severity=Control.Severity.LOW,
        )
        rule_a = self.create_security_rule(name="rule-a")
        rule_b = self.create_security_rule(name="rule-b")
        f = {}
        f["a_high"] = RuleFinding.objects.create(
            assessment_run=run, control=self.control, security_rule=rule_a,
            status=RuleFinding.Status.OPEN, severity=Control.Severity.HIGH, title=self.control.name,
        )
        f["a_low"] = RuleFinding.objects.create(
            assessment_run=run, control=control_b, security_rule=rule_a,
            status=RuleFinding.Status.OPEN, severity=Control.Severity.LOW, title=control_b.name,
        )
        f["b_med"] = RuleFinding.objects.create(
            assessment_run=run, control=self.control, security_rule=rule_b,
            status=RuleFinding.Status.SUPPRESSED, severity=Control.Severity.MEDIUM, title=self.control.name,
        )
        return run, control_b, rule_a, rule_b, f

    def test_finding_list_groups_by_control_by_default(self):
        self._seed_findings_for_grouping()

        response = self.client.get(reverse("assessment_finding_list"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["security_group_by"], "control")
        groups = response.context["finding_groups"]
        # self.control has HIGH and MEDIUM findings -> two separate control+severity
        # sections; control_b contributes one LOW section. Sorted worst-first.
        self.assertEqual(len(groups), 3)
        self.assertEqual(groups[0]["header"]["primary"], self.control.control_id)
        self.assertEqual(groups[0]["worst_label"], "High")
        self.assertEqual(groups[0]["count"], 1)
        sections = [(g["header"]["primary"], g["worst_label"]) for g in groups]
        self.assertEqual(
            sections,
            [
                (self.control.control_id, "High"),
                (self.control.control_id, "Medium"),
                ("FW-RULE-LOGGING-002", "Low"),
            ],
        )

    def test_finding_list_group_by_rule(self):
        _, _, rule_a, rule_b, _ = self._seed_findings_for_grouping()

        response = self.client.get(reverse("assessment_finding_list") + "?group=rule")

        self.assertEqual(response.context["security_group_by"], "rule")
        primaries = {g["header"]["primary"] for g in response.context["finding_groups"]}
        self.assertEqual(primaries, {rule_a.name, rule_b.name})

    def test_finding_list_filters_by_severity(self):
        self._seed_findings_for_grouping()

        response = self.client.get(reverse("assessment_finding_list") + "?severity=low")

        groups = response.context["finding_groups"]
        self.assertEqual([g["header"]["primary"] for g in groups], ["FW-RULE-LOGGING-002"])
        self.assertEqual(response.context["total_findings"], 1)

    def test_finding_list_hides_suppressed(self):
        self._seed_findings_for_grouping()

        response = self.client.get(reverse("assessment_finding_list") + "?hide_suppressed=1")

        # The only suppressed finding (b_med) is excluded; 2 open findings remain.
        self.assertEqual(response.context["total_findings"], 2)
        self.assertTrue(response.context["hide_suppressed"])

    def test_finding_list_detail_overlay_shows_control_and_rule(self):
        _, _, rule_a, _, f = self._seed_findings_for_grouping()

        response = self.client.get(
            reverse("assessment_finding_list") + f"?finding={f['a_high'].pk}"
        )

        self.assertTrue(response.context["overlay_is_open"])
        selected = response.context["selected_finding"]
        self.assertEqual(selected["control_id"], self.control.control_id)
        self.assertEqual(selected["rule_row"]["security_rule"], rule_a)
        self.assertContains(response, "Remediation")
        self.assertContains(response, self.control.remediation)

    def test_finding_list_rows_include_rule_config(self):
        self._seed_findings_for_grouping()

        # Grouped by control, each row is an affected rule carrying its full
        # build_security_rule_rows() row, rendered as a rulebase-style table.
        response = self.client.get(reverse("assessment_finding_list"))
        item = response.context["finding_groups"][0]["findings"][0]
        self.assertIsNotNone(item["rule_row"])
        self.assertIn("source_addresses", item["rule_row"])
        self.assertContains(response, "Src Address")

        # Grouped by rule, the group itself carries the single rule's config strip.
        response = self.client.get(reverse("assessment_finding_list") + "?group=rule")
        group = response.context["finding_groups"][0]
        self.assertIsNotNone(group["rule_config"])
        self.assertIn("source_addresses", group["rule_config"])

    def test_finding_list_sections_collapse_by_default_and_open_selected(self):
        _, _, rule_a, _, f = self._seed_findings_for_grouping()

        # Default load: every section is collapsed.
        response = self.client.get(reverse("assessment_finding_list"))
        self.assertFalse(any(g["has_selected"] for g in response.context["finding_groups"]))
        self.assertNotContains(response, "<details open")

        # With a selected finding, exactly its section renders expanded.
        response = self.client.get(
            reverse("assessment_finding_list") + f"?finding={f['a_high'].pk}"
        )
        opened = [g for g in response.context["finding_groups"] if g["has_selected"]]
        self.assertEqual(len(opened), 1)
        self.assertIn(f["a_high"].pk, [item["id"] for item in opened[0]["findings"]])
        self.assertContains(response, "<details open")

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


class DeviceConfigurationProfileListViewTests(TestCase):
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
        self.profile = DeviceConfigurationProfile.objects.create(
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
            control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="Test",
            default_severity=Control.Severity.HIGH,
        )
        self.mgmt_query = ControlQuery.objects.create(
            control=self.mgmt_control,
            name="Baseline",
            canonical_query={
                "model": "integrations.DeviceConfigurationProfile",
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
        response = self.client.get(reverse("assessment_device_configuration_profile_list"))
        self.assertEqual(response.status_code, 200)

    def test_url_name_reverses(self):
        url = reverse("assessment_device_configuration_profile_list")
        self.assertEqual(url, "/assessments/device-configuration/")

    def test_sidebar_includes_new_route(self):
        from optivedge.app_registry import sidebar_sections
        sections = sidebar_sections()
        assessments = next(s for s in sections if s["label"] == "Assessments")
        active_names = assessments["active_names"]
        self.assertIn("assessment_device_configuration_profile_list", active_names)
        item_hrefs = [item["href"] for item in assessments["items"]]
        self.assertIn("/assessments/device-configuration/", item_hrefs)

    def test_control_filter_returns_matching_profiles(self):
        response = self.client.get(
            reverse("assessment_device_configuration_profile_list"),
            {"control": self.mgmt_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertTrue(ctx["show_control_severity"])
        self.assertEqual(ctx["total_row_count"], 1)
        self.assertEqual(ctx["selected_control"], self.mgmt_control)

    def test_security_rule_control_is_rejected(self):
        response = self.client.get(
            reverse("assessment_device_configuration_profile_list"),
            {"control": self.sr_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertIsNone(ctx["selected_control"])
        self.assertIn("cannot be applied to device configuration profiles", ctx["search_error"])
        self.assertFalse(ctx["show_control_severity"])

    def test_control_query_filter_returns_matching_profiles(self):
        response = self.client.get(
            reverse("assessment_device_configuration_profile_list"),
            {"control_query": self.mgmt_query.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertEqual(ctx["total_row_count"], 1)
        self.assertFalse(ctx["search_error"])

    def test_security_rule_query_is_rejected(self):
        response = self.client.get(
            reverse("assessment_device_configuration_profile_list"),
            {"control_query": self.sr_query.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertIsNone(ctx["selected_control_query"])
        self.assertIn("does not target device configuration profiles", ctx["search_error"])

    def test_malformed_control_param_does_not_500(self):
        response = self.client.get(
            reverse("assessment_device_configuration_profile_list"),
            {"control": "abc"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("could not be found", response.context["search_error"])

    def test_malformed_control_query_param_does_not_500(self):
        response = self.client.get(
            reverse("assessment_device_configuration_profile_list"),
            {"control_query": "abc"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("could not be found", response.context["search_error"])

    def test_control_query_create_seeds_device_configuration_default(self):
        response = self.client.get(
            reverse("assessment_control_query_create"),
            {"control": self.mgmt_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        initial_query = response.context["form"].initial["canonical_query"]
        self.assertEqual(initial_query["model"], "integrations.DeviceConfigurationProfile")

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
        self.assertEqual(initial_query["model"], "integrations.DeviceConfigurationProfile")


class ControlQueryFormModelValidationTests(TestCase):
    def setUp(self):
        self.mgmt_control = Control.objects.create(
            control_id="MGMT-FORM-001",
            name="Form validation mgmt control",
            control_type=Control.ControlType.DEVICE_CONFIGURATION,
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
        form = self._post_query(self.mgmt_control, "integrations.DeviceConfigurationProfile")
        self.assertTrue(form.is_valid(), form.errors)

    def test_mismatched_model_is_invalid_for_mgmt_control(self):
        form = self._post_query(self.mgmt_control, "integrations.SecurityRule")
        self.assertFalse(form.is_valid())
        self.assertIn("canonical_query", form.errors)

    def test_mismatched_model_is_invalid_for_sr_control(self):
        form = self._post_query(self.sr_control, "integrations.DeviceConfigurationProfile")
        self.assertFalse(form.is_valid())
        self.assertIn("canonical_query", form.errors)


class ControlTargetModelTests(TestCase):
    def test_security_rule_control_sets_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-001", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.SecurityRule")

    def test_device_configuration_control_sets_target_model(self):
        c = Control.objects.create(
            control_id="MP-TM-001", name="MP", control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.DeviceConfigurationProfile")

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

    def test_changing_to_device_configuration_updates_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-003", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.SecurityRule")
        c.control_type = Control.ControlType.DEVICE_CONFIGURATION
        c.save()
        self.assertEqual(c.target_model, "integrations.DeviceConfigurationProfile")

    def test_supports_security_rule_ui_uses_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-004", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertTrue(c.supports_security_rule_ui)
        self.assertFalse(c.supports_device_configuration_ui)

    def test_supports_device_configuration_ui_uses_target_model(self):
        c = Control.objects.create(
            control_id="MP-TM-002", name="MP", control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertFalse(c.supports_security_rule_ui)
        self.assertTrue(c.supports_device_configuration_ui)


class ControlQueryTargetModelValidationTests(TestCase):
    def setUp(self):
        self.sr_control = Control.objects.create(
            control_id="SR-QVAL-001", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.mp_control = Control.objects.create(
            control_id="MP-QVAL-001", name="MP", control_type=Control.ControlType.DEVICE_CONFIGURATION,
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
        q = self._make_query(self.sr_control, "integrations.DeviceConfigurationProfile")
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
            control_id="MP-GUARD-001", name="MP", control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.mp_query = ControlQuery.objects.create(
            control=self.mp_control,
            name="Baseline",
            canonical_query={"model": "integrations.DeviceConfigurationProfile", "operator": "and", "clauses": [{"field": "ha_required", "op": "eq", "value": True}]},
            is_baseline=True,
        )

    def test_device_configuration_control_rejected(self):
        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {"control": self.mp_control.pk},
        )
        self.assertEqual(response.status_code, 200)
        ctx = response.context
        self.assertIsNone(ctx["selected_control"])
        self.assertTrue(ctx["search_error"])
        self.assertIn("integrations.DeviceConfigurationProfile", ctx["search_error"])

    def test_device_configuration_query_rejected(self):
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


class SecurityRuleListDeviceGroupTests(TestCase):
    """Covers the "Device Group" column on the Security Rules list page - previously always
    rendered "-" because the template read a nonexistent `security_rule.provenance` attribute."""

    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance = Appliance.objects.create(
            management_station=station,
            serial_number="SR-DG-001",
            hostname="fw-01",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance=appliance,
            vsys_name="vsys1",
        )
        snapshot = Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="test",
            collected_at=timezone.now(),
        )
        self.rule_with_device_group = SecurityRule.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
            effective_order=1,
            rule_position=1,
            name="rule-branch-dg",
            action="allow",
        )
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(SecurityRule),
            object_id=self.rule_with_device_group.pk,
            field_name="__entry__",
            provenance_type=FieldProvenance.ProvenanceType.DEVICE_GROUP,
            raw_key="@loc",
            raw_value="branch-office-dg",
        )
        self.rule_local = SecurityRule.objects.create(
            management_station=station,
            enforcement_point=enforcement_point,
            source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=2,
            rule_position=2,
            name="rule-local",
            action="allow",
        )
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(SecurityRule),
            object_id=self.rule_local.pk,
            field_name="__entry__",
            provenance_type=FieldProvenance.ProvenanceType.LOCAL,
        )

    def test_security_rule_list_shows_device_group_name(self):
        response = self.client.get(reverse("assessment_security_rule_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "branch-office-dg")

    def test_security_rule_list_shows_dash_for_local_rule(self):
        response = self.client.get(reverse("assessment_security_rule_list"))

        rows = {row["security_rule"].pk: row for row in response.context["security_rule_rows"]}
        self.assertEqual(rows[self.rule_with_device_group.pk]["device_group_name"], "branch-office-dg")
        self.assertEqual(rows[self.rule_local.pk]["device_group_name"], "")


class ControlListViewNoEnvironmentTests(TestCase):
    def test_renders_without_application_environment(self):
        response = self.client.get(reverse("assessment_control_list"))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["current_catalog_state"])
        self.assertFalse(response.context["catalog_drifted"])
