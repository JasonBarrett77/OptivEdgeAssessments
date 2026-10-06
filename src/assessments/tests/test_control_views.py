from django.contrib.contenttypes.models import ContentType
from unittest import mock
from datetime import timedelta

from django.test import TestCase
from django.contrib import messages
from django.contrib.messages import get_messages
from django.urls import reverse
from django.core.exceptions import ValidationError
from django.utils import timezone

from assessments.finding_run import FINDINGS_LOCK_MAX_AGE, regenerate_findings
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
        # One run for every finding kind: the policy/device split is gone (2026-09-16).
        self.assertContains(response, "Run Findings")
        self.assertNotContains(response, "Run Policy Findings")
        self.assertNotContains(response, "Run Configuration Findings")
        self.assertContains(response, "View Findings")

    def test_control_detail_view_renders(self):
        response = self.client.get(
            reverse("assessment_control_detail", kwargs={"pk": self.control.pk})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.control.name)
        self.assertContains(response, "Security Rule")
        self.assertContains(response, "Baseline permissiveness")
        # Policies > Security, 2026-09-18. Security rules are an object in the explorer like
        # every other, so the control's results open there rather than on the standalone page.
        self.assertContains(
            response,
            f"/assessments/configuration/policies/security/?control={self.control.pk}",
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
            f"/assessments/configuration/policies/security/?control_query={self.control.queries.first().pk}",
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

    def test_control_run_findings_warns_when_a_query_could_not_be_compiled(self):
        """A skipped query means the control contributed nothing, which reads like a clean
        result. `ControlQuery.clean()` validates only the model label, so a query naming a
        field that has since been removed stores fine and fails at compile time - exactly
        what happens to a stored catalog after a field is renamed."""
        self.control.queries.all().delete()
        ControlQuery.objects.create(
            control=self.control,
            name="Names a field that no longer exists",
            canonical_query={
                "model": "integrations.SecurityRule",
                "operator": "and",
                "clauses": [{"field": "field_removed_in_a_later_release", "op": "eq", "value": "x"}],
            },
            is_baseline=True,
        )
        self.create_security_rule()

        result = regenerate_findings()

        self.assertEqual(RuleFinding.objects.count(), 0)
        self.assertEqual(result.skipped_queries, 1)
        # The signal moved from a WARNING-level message to the run itself when the view stopped
        # waiting for the run: a background thread has no request to write a message from. On
        # the run it also survives navigation, and the sentence leads with the thing most
        # easily missed rather than burying it behind three counts.
        notes = AssessmentRun.objects.latest("started_at").notes
        self.assertIn("could not be compiled", notes)
        self.assertIn("Skipped queries: 1.", notes)

    def test_control_run_findings_reports_success_when_nothing_was_skipped(self):
        self.control.queries.all().delete()
        ControlQuery.objects.create(
            control=self.control,
            name="Trust baseline",
            canonical_query={
                "model": "integrations.SecurityRule",
                "operator": "and",
                "clauses": [{"field": "from_zone", "op": "eq", "value": "trust"}],
            },
            is_baseline=True,
        )
        self.create_security_rule()

        regenerate_findings()

        notes = AssessmentRun.objects.latest("started_at").notes
        self.assertIn("Skipped queries: 0.", notes)
        self.assertNotIn("could not be compiled", notes)

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

        # Called directly, which is what the view's background thread does. The POST is
        # covered by `BackgroundFindingsRunTests`, where the thread is not actually started -
        # a real one would use its own connection and never see this test's transaction.
        regenerate_findings()

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

        # The matched query names are snapshotted onto the finding at generation time and
        # stay frozen even if the control query is renamed afterwards.
        self.assertEqual(finding.matched_query_names, ["Trust baseline"])
        baseline_query.name = "Renamed after the run"
        baseline_query.save(update_fields=["name"])
        finding.refresh_from_db()
        self.assertEqual(finding.matched_query_names, ["Trust baseline"])

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

class ControlQueryFormModelValidationTests(TestCase):
    def setUp(self):
        self.mgmt_control = Control.objects.create(
            control_id="MGMT-FORM-001",
            name="Form validation mgmt control",
            control_type=Control.ControlType.LOGIN_BANNER,
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
        form = self._post_query(self.mgmt_control, "integrations.LoginBanner")
        self.assertTrue(form.is_valid(), form.errors)

    def test_mismatched_model_is_invalid_for_mgmt_control(self):
        form = self._post_query(self.mgmt_control, "integrations.SecurityRule")
        self.assertFalse(form.is_valid())
        self.assertIn("canonical_query", form.errors)

    def test_mismatched_model_is_invalid_for_sr_control(self):
        form = self._post_query(self.sr_control, "integrations.LoginBanner")
        self.assertFalse(form.is_valid())
        self.assertIn("canonical_query", form.errors)


class ControlTargetModelTests(TestCase):
    def test_security_rule_control_sets_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-001", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.SecurityRule")

    def test_login_banner_control_sets_target_model(self):
        c = Control.objects.create(
            control_id="MP-TM-001", name="MP", control_type=Control.ControlType.LOGIN_BANNER,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.LoginBanner")

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

    def test_changing_to_login_banner_updates_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-003", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertEqual(c.target_model, "integrations.SecurityRule")
        c.control_type = Control.ControlType.LOGIN_BANNER
        c.save()
        self.assertEqual(c.target_model, "integrations.LoginBanner")

    def test_supports_security_rule_ui_uses_target_model(self):
        c = Control.objects.create(
            control_id="SR-TM-004", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.assertTrue(c.supports_security_rule_ui)


class ControlQueryTargetModelValidationTests(TestCase):
    def setUp(self):
        self.sr_control = Control.objects.create(
            control_id="SR-QVAL-001", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.mp_control = Control.objects.create(
            control_id="MP-QVAL-001", name="MP", control_type=Control.ControlType.LOGIN_BANNER,
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
        q = self._make_query(self.sr_control, "integrations.LoginBanner")
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


#: The retired `/assessments/security-rules/` page moved here on 2026-09-25.
SECURITY_PAGE = "/assessments/configuration/policies/security/"


class SecurityRuleQueryPageGuardTests(TestCase):
    """A parameter aimed at the wrong model, or malformed, must say so rather than 500 or
    quietly answer a question it was not asked. Written against the security rules page; kept
    against the explorer page that replaced it."""

    def setUp(self):
        self.sr_control = Control.objects.create(
            control_id="SR-GUARD-001", name="SR", control_type=Control.ControlType.SECURITY_RULE,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.mp_control = Control.objects.create(
            control_id="MP-GUARD-001", name="MP", control_type=Control.ControlType.LOGIN_BANNER,
            description="test", default_severity=Control.Severity.MEDIUM,
        )
        self.mp_query = ControlQuery.objects.create(
            control=self.mp_control,
            name="Baseline",
            canonical_query={"model": "integrations.LoginBanner", "operator": "and", "clauses": [{"field": "acknowledgement_required", "op": "eq", "value": True}]},
            is_baseline=True,
        )

    def test_another_models_control_rejected(self):
        response = self.client.get(SECURITY_PAGE, {"control": self.mp_control.pk})

        self.assertEqual(response.status_code, 200)
        # No preview context at all: the page refused the control rather than previewing it
        # against rows it does not describe.
        self.assertNotIn("control_preview", response.context)
        self.assertIn("integrations.LoginBanner", response.context["search_error"])

    def test_another_models_query_rejected(self):
        response = self.client.get(SECURITY_PAGE, {"control_query": self.mp_query.pk})

        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["search_query"])
        self.assertTrue(response.context["search_error"])

    def test_malformed_control_param_does_not_500(self):
        response = self.client.get(SECURITY_PAGE, {"control": "abc"})

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["search_error"])

    def test_malformed_control_query_param_does_not_500(self):
        response = self.client.get(SECURITY_PAGE, {"control_query": "abc"})

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

    def _rows_by_rule(self, response):
        columns = list(response.context["columns"])
        return {row[columns.index("Rule")]: dict(zip(columns, row))
                for row in response.context["rows"]}

    def test_security_rule_page_shows_device_group_name(self):
        response = self.client.get(SECURITY_PAGE)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "branch-office-dg")

    def test_a_local_rule_names_no_device_group(self):
        """A pushed rule names the group that pushed it; a local one has none to name and
        renders the empty marker the page uses everywhere a multi-value cell holds nothing."""
        rows = self._rows_by_rule(self.client.get(SECURITY_PAGE))

        self.assertEqual(rows[self.rule_with_device_group.name]["Device Group"],
                         "branch-office-dg")
        self.assertEqual(rows[self.rule_local.name]["Device Group"], "-")


class ControlListViewNoEnvironmentTests(TestCase):
    def test_renders_without_application_environment(self):
        response = self.client.get(reverse("assessment_control_list"))
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.context["current_catalog_state"])
        self.assertFalse(response.context["catalog_drifted"])


class BackgroundFindingsRunTests(TestCase):
    """Run Findings starts a thread and returns.

    A run is 24 generators, each deleting and recreating every finding of its model, so holding
    it in the request made the browser wait for all of it - into any proxy or server timeout,
    and on SQLite it was the longest window for a concurrent reader to collide with the writer
    and raise "database is locked". Jason, 2026-10-06: "make Run Findings run in the background
    ... so that browsing away from the page doesn't interrupt Run Findings."

    The thread is never actually started here. A real one opens its own database connection and
    would not see this test's transaction, so what is asserted is the DISPATCH - a run opened,
    a thread asked for, a redirect - and the work itself is covered by the tests that call
    `regenerate_findings` directly.
    """

    def setUp(self):
        self.url = reverse("assessment_control_run_findings")
        self.list_url = reverse("assessment_control_list")

    def post(self):
        with mock.patch("assessments.views.threading.Thread") as thread:
            response = self.client.post(self.url, follow=True)
        return response, thread

    def test_the_run_is_opened_in_the_request_not_on_the_thread(self):
        """Opened on the thread, the page this redirects to could render before the row
        existed - showing nothing in progress, and never refreshing."""
        response, thread = self.post()

        self.assertRedirects(response, self.list_url)
        run = AssessmentRun.objects.get()
        self.assertEqual(run.status, AssessmentRun.Status.RUNNING)
        thread.assert_called_once()
        self.assertEqual(thread.call_args.kwargs["args"], (run.pk,))
        self.assertTrue(thread.call_args.kwargs["daemon"])
        thread.return_value.start.assert_called_once()

    def test_a_second_run_is_refused_while_one_is_in_progress(self):
        """Two runs would interleave their delete-and-recreate writes on the same tables, and
        the reference allocator assumes one run fills at a time."""
        self.post()

        response, thread = self.post()

        thread.assert_not_called()
        self.assertEqual(AssessmentRun.objects.count(), 1)
        self.assertIn("already in progress",
                      str(list(get_messages(response.wsgi_request))[-1]))

    def test_an_orphaned_run_does_not_disable_the_button_for_ever(self):
        """The worker is a daemon, so a server restart mid-run kills it and leaves the row
        RUNNING. Without an age limit that would refuse every later run."""
        self.post()
        AssessmentRun.objects.update(
            started_at=timezone.now() - FINDINGS_LOCK_MAX_AGE - timedelta(minutes=1))

        _response, thread = self.post()

        thread.assert_called_once()
        self.assertEqual(AssessmentRun.objects.count(), 2)

    def test_the_page_reports_the_run_and_refreshes_itself(self):
        self.post()

        response = self.client.get(self.list_url)

        self.assertContains(response, "data-findings-run-in-progress")
        self.assertContains(response, "window.location.reload()")
        self.assertContains(response, "you can browse away without")

    def test_an_idle_page_does_not_refresh_itself(self):
        """A page that reloads under a reader who is halfway through something is worse than
        one that needs a manual refresh."""
        response = self.client.get(self.list_url)

        self.assertNotContains(response, "window.location.reload()")
        self.assertNotContains(response, "data-findings-run-in-progress")

    def test_a_finished_run_reports_what_it_did(self):
        """The counts were a Django message from the view, and the view no longer waits for the
        run. They live on the run now, which also means they are still there tomorrow."""
        regenerate_findings()

        response = self.client.get(self.list_url)

        self.assertContains(response, "data-findings-run-outcome")
        self.assertContains(response, "Skipped queries: 0.")
        self.assertNotContains(response, "data-findings-run-in-progress")
