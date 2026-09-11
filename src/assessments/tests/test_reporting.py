from django.test import TestCase
from django.utils import timezone

from assessments.models import AssessmentRun, Control, RuleFinding
from assessments.reporting.context import (
    RISK_RATING_BY_SEVERITY,
    build_firewall_detail_rows,
    build_report_context,
    build_summary_rows,
)
from django.contrib.contenttypes.models import ContentType

from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    EnforcementPoint,
    FieldProvenance,
    ManagementStation,
    SecurityRule,
    Snapshot,
)


class ReportingContextTests(TestCase):
    def setUp(self):
        self.control = Control.objects.create(
            control_id="FW-RULE-PERMISSIVENESS-001",
            name="Ensure firewall rules are not overly permissive",
            control_type=Control.ControlType.SECURITY_RULE,
            description="Prototype control description.",
            remediation="Restrict broad rules.",
            default_severity=Control.Severity.MEDIUM,
        )
        self.run = AssessmentRun.objects.create(
            name="Rule Findings 2026-05-01 09:00:00",
            status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(),
            completed_at=timezone.now(),
        )
        self.management_run = AssessmentRun.objects.create(
            name="Device Configuration Findings 2026-05-01 10:00:00",
            status=AssessmentRun.Status.COMPLETED,
            started_at=timezone.now(),
            completed_at=timezone.now(),
        )

    def test_summary_rows_roll_up_by_control(self):
        self._create_finding(rule_name="rule-one", rule_position=10, severity=Control.Severity.MEDIUM)
        self._create_finding(rule_name="rule-two", rule_position=20, severity=Control.Severity.CRITICAL)

        findings = RuleFinding.objects.filter(assessment_run=self.run).select_related("control", "security_rule__enforcement_point")
        rows = build_summary_rows(findings)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0].sequence, 1)
        self.assertEqual(rows[0].importance, "Critical")
        self.assertEqual(rows[0].recommendation, "Restrict broad rules.")
        self.assertIn("1 matching finding", rows[0].observation)
        self.assertEqual(rows[1].importance, "Medium")

    def test_firewall_detail_rows_include_rule_context(self):
        self._create_finding(rule_name="rule-one", rule_position=42, severity=Control.Severity.MEDIUM)

        findings = RuleFinding.objects.filter(assessment_run=self.run).select_related("control", "security_rule__enforcement_point")
        rows = build_firewall_detail_rows(findings)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].line_reference, "42")
        self.assertEqual(rows[0].risk_rating, RISK_RATING_BY_SEVERITY[Control.Severity.MEDIUM])
        self.assertIn("Matched control query", rows[0].description)

    def test_build_report_context_uses_latest_rule_run(self):
        self._create_finding(rule_name="rule-one", rule_position=1, severity=Control.Severity.MEDIUM)

        context = build_report_context()

        self.assertEqual(context.assessment_run, self.run)
        self.assertEqual(len(context.summary_rows), 1)
        self.assertEqual(len(context.firewall_detail_rows), 1)

    def test_summary_rows_format_local_firewall_provenance_for_report(self):
        self._create_finding(
            rule_name="rule-local",
            rule_position=10,
            severity=Control.Severity.MEDIUM,
            config_source=SecurityRule.SOURCE_LOCAL,
        )

        findings = RuleFinding.objects.filter(assessment_run=self.run).select_related("control", "security_rule__enforcement_point")
        rows = build_summary_rows(findings)

        self.assertEqual(rows[0].detail_table.detail_rows[0].secondary, "Local firewall")

    def test_summary_rows_format_device_group_provenance_for_report(self):
        self._create_finding(
            rule_name="rule-pushed",
            rule_position=10,
            severity=Control.Severity.MEDIUM,
            provenance="branch-dg",
            config_source=SecurityRule.SOURCE_PUSHED_PRE,
        )

        findings = RuleFinding.objects.filter(assessment_run=self.run).select_related("control", "security_rule__enforcement_point")
        rows = build_summary_rows(findings)

        self.assertEqual(rows[0].detail_table.detail_rows[0].secondary, "Device group: branch-dg")

    def _create_finding(
        self,
        *,
        rule_name: str,
        rule_position: int,
        severity: str,
        provenance: str = "",
        config_source: str = SecurityRule.SOURCE_LOCAL,
    ) -> RuleFinding:
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname=f"{rule_name}.panorama.local",
        )
        group = ApplianceGroup.objects.create(
            management_station=station,
            name=f"{rule_name}-group",
        )
        enforcement_point = EnforcementPoint.objects.create(
            management_station=station,
            appliance_group=group,
            vsys_name=f"{rule_name}-vsys",
            vsys_display_name=f"{rule_name}-display",
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
            config_source=config_source,
            effective_order=rule_position,
            rule_position=rule_position,
            name=rule_name,
            action="allow",
            disabled=False,
            rule_type="universal",
            description="Generated for reporting tests",
            log_start=False,
            log_end=True,
            log_setting="default",
        )
        if provenance and provenance not in ("local", "test"):
            ct = ContentType.objects.get_for_model(SecurityRule)
            FieldProvenance.objects.create(
                content_type=ct,
                object_id=security_rule.pk,
                field_name="__entry__",
                provenance_type="device_group",
                raw_key="@loc",
                raw_value=provenance,
            )
        return RuleFinding.objects.create(
            assessment_run=self.run,
            control=self.control,
            security_rule=security_rule,
            severity=severity,
            title=self.control.name,
            summary="Matched control query: Source is 'any'.",
        )

