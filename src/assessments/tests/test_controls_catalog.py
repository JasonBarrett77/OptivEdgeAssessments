import json
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from assessments.controls_catalog.drift import catalog_has_drifted
from assessments.controls_catalog.io.importers import (
    apply_catalog,
    create_catalog_from_current_controls,
    refresh_seeded_catalogs,
    seed_catalogs_if_empty,
)
from assessments.controls_catalog.schemas import validate_catalog_payload
from assessments.models import (
    ApplicationEnvironmentCatalogState,
    AssessmentRun,
    Catalog,
    Control,
    ControlQuery,
)
from optivedge.models import ApplicationEnvironment


def build_security_rule_query(value: str) -> dict:
    return {
        "model": "integrations.SecurityRule",
        "operator": "and",
        "clauses": [
            {
                "field": "from_zone",
                "op": "eq",
                "value": value,
                "negated": False,
                "case_sensitive": False,
                "include_any": False,
            }
        ],
    }


class ControlsCatalogTests(TestCase):
    def setUp(self):
        self.application_environment = ApplicationEnvironment.objects.create(
            client_name="Example Corp",
            client_short_name="EXAMPLE",
            opportunity_number="OP-1234567",
        )

    def create_live_control(self, *, control_id: str, name: str, from_zone: str) -> Control:
        control = Control.objects.create(
            control_id=control_id,
            name=name,
            control_type=Control.ControlType.SECURITY_RULE,
            description=f"{name} description",
            remediation=f"{name} remediation",
            default_severity=Control.Severity.MEDIUM,
        )
        ControlQuery.objects.create(
            control=control,
            name="Baseline",
            short_description="Query description",
            canonical_query=build_security_rule_query(from_zone),
            is_baseline=True,
            is_active=True,
        )
        return control

    def test_create_catalog_from_current_controls_persists_payload(self):
        self.create_live_control(
            control_id="FW-RULE-001",
            name="Trust Rules",
            from_zone="trust",
        )

        catalog = create_catalog_from_current_controls(
            label="Base Controls",
            version="1.0.0",
            description="Reusable baseline controls.",
        )

        self.assertEqual(catalog.key, "base-controls")
        self.assertEqual(catalog.payload["catalog"]["key"], catalog.key)
        self.assertEqual(catalog.payload["catalog"]["label"], "Base Controls")
        self.assertEqual(catalog.payload["controls"][0]["control_id"], "FW-RULE-001")
        self.assertEqual(
            catalog.payload["controls"][0]["queries"][0]["canonical_query"]["model"],
            "integrations.SecurityRule",
        )

    def test_apply_catalog_replaces_live_controls_and_creates_snapshot(self):
        self.create_live_control(
            control_id="FW-RULE-OLD-001",
            name="Old Control",
            from_zone="trust",
        )
        AssessmentRun.objects.create(name="Old Run", status=AssessmentRun.Status.COMPLETED)
        catalog = Catalog.objects.create(
            key="base-controls",
            label="Base Controls",
            version="1.0.0",
            description="Reusable baseline controls.",
            payload={
                "type": "optivedge.assessments.catalog",
                "schema_version": "1.0",
                "catalog": {
                    "key": "base-controls",
                    "label": "Base Controls",
                    "version": "1.0.0",
                    "description": "Reusable baseline controls.",
                },
                "controls": [
                    {
                        "control_id": "FW-RULE-NEW-001",
                        "name": "New Control",
                        "control_type": "security_rule",
                        "description": "New control description",
                        "rationale": "",
                        "audit": "",
                        "remediation": "Tighten rule scope.",
                        "default_severity": "high",
                        "implementation_version": "v1",
                        "target_model": "integrations.SecurityRule",
                        "is_active": True,
                        "queries": [
                            {
                                "name": "Baseline",
                                "short_description": "Trust zone query.",
                                "canonical_query": build_security_rule_query("dmz"),
                                "is_baseline": True,
                                "adjusted_severity": None,
                                "is_active": True,
                            }
                        ],
                    }
                ],
            },
        )

        result = apply_catalog(
            catalog=catalog,
            application_environment=self.application_environment,
        )

        self.assertIsNotNone(result.snapshot_catalog)
        self.assertTrue(result.snapshot_catalog.is_snapshot)
        self.assertEqual(result.controls_created, 1)
        self.assertEqual(result.queries_created, 1)
        self.assertEqual(result.assessment_runs_deleted, 1)
        self.assertFalse(Control.objects.filter(control_id="FW-RULE-OLD-001").exists())
        self.assertTrue(Control.objects.filter(control_id="FW-RULE-NEW-001").exists())
        state = ApplicationEnvironmentCatalogState.objects.get(
            application_environment=self.application_environment,
        )
        self.assertEqual(state.current_catalog, catalog)

    @patch("assessments.controls_catalog.io.importers.load_seed_payload")
    def test_seed_catalogs_if_empty_loads_seeded_catalogs(self, mock_load_seed_payload):
        mock_load_seed_payload.return_value = {
            "type": "optivedge.assessments.catalog_seed",
            "schema_version": "1.0",
            "catalogs": [
                {
                    "type": "optivedge.assessments.catalog",
                    "schema_version": "1.0",
                    "catalog": {
                        "key": "base-controls",
                        "label": "Base Controls",
                        "version": "1.0.0",
                        "description": "Reusable baseline controls.",
                    },
                    "controls": [],
                }
            ],
        }

        result = seed_catalogs_if_empty()

        self.assertEqual(result.catalogs_created, 1)
        self.assertEqual(Catalog.objects.count(), 1)
        self.assertTrue(Catalog.objects.get().is_seeded)

    @patch("assessments.controls_catalog.io.importers.load_seed_payload")
    def test_refresh_seeded_catalogs_updates_existing_catalog_in_place(self, mock_load_seed_payload):
        stale_catalog = Catalog.objects.create(
            key="base-controls",
            label="Base Controls",
            version="1.0.0",
            description="stale description",
            payload={
                "type": "optivedge.assessments.catalog",
                "schema_version": "1.0",
                "catalog": {
                    "key": "base-controls",
                    "label": "Base Controls",
                    "version": "1.0.0",
                    "description": "stale description",
                },
                "controls": [],
            },
            is_seeded=True,
        )
        original_pk = stale_catalog.pk
        mock_load_seed_payload.return_value = {
            "type": "optivedge.assessments.catalog_seed",
            "schema_version": "1.0",
            "catalogs": [
                {
                    "type": "optivedge.assessments.catalog",
                    "schema_version": "1.0",
                    "catalog": {
                        "key": "base-controls",
                        "label": "Base Controls",
                        "version": "1.0.1",
                        "description": "refreshed description",
                    },
                    "controls": [
                        {
                            "control_id": "FW-RULE-NEW-001",
                            "name": "New Control",
                            "control_type": "security_rule",
                            "description": "New control description",
                            "rationale": "",
                            "audit": "",
                            "remediation": "Tighten rule scope.",
                            "default_severity": "high",
                            "implementation_version": "v1",
                            "target_model": "integrations.SecurityRule",
                            "is_active": True,
                            "queries": [
                                {
                                    "name": "Baseline",
                                    "short_description": "Trust zone query.",
                                    "canonical_query": build_security_rule_query("dmz"),
                                    "is_baseline": True,
                                    "adjusted_severity": None,
                                    "is_active": True,
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        result = refresh_seeded_catalogs()

        self.assertEqual(result.catalogs_created, 0)
        self.assertEqual(result.catalogs_updated, 1)
        refreshed = Catalog.objects.get(key="base-controls")
        self.assertEqual(refreshed.pk, original_pk)
        self.assertEqual(refreshed.version, "1.0.1")
        self.assertEqual(refreshed.description, "refreshed description")
        self.assertEqual(refreshed.payload["controls"][0]["control_id"], "FW-RULE-NEW-001")
        # Live controls are untouched - refresh only updates the Catalog row.
        self.assertFalse(Control.objects.exists())

    @patch("assessments.controls_catalog.io.importers.load_seed_payload")
    def test_refresh_seeded_catalogs_creates_catalog_if_missing(self, mock_load_seed_payload):
        mock_load_seed_payload.return_value = {
            "type": "optivedge.assessments.catalog_seed",
            "schema_version": "1.0",
            "catalogs": [
                {
                    "type": "optivedge.assessments.catalog",
                    "schema_version": "1.0",
                    "catalog": {
                        "key": "base-controls",
                        "label": "Base Controls",
                        "version": "1.0.0",
                        "description": "Reusable baseline controls.",
                    },
                    "controls": [],
                }
            ],
        }

        result = refresh_seeded_catalogs()

        self.assertEqual(result.catalogs_created, 1)
        self.assertEqual(result.catalogs_updated, 0)
        self.assertTrue(Catalog.objects.get(key="base-controls").is_seeded)

    def test_refresh_catalog_seed_view_updates_catalog_and_redirects(self):
        Catalog.objects.create(
            key="base",
            label="Base",
            version="v1",
            description="stale",
            payload={
                "type": "optivedge.assessments.catalog",
                "schema_version": "1.0",
                "catalog": {"key": "base", "label": "Base", "version": "v1", "description": "stale"},
                "controls": [],
            },
            is_seeded=True,
        )

        response = self.client.post(reverse("assessment_catalog_refresh_seed"))

        self.assertRedirects(response, reverse("assessment_system"))
        refreshed = Catalog.objects.get(key="base")
        self.assertNotEqual(refreshed.description, "stale")

    def test_catalog_pages_render_home_and_management_views(self):
        catalog = Catalog.objects.create(
            key="base-controls",
            label="Base Controls",
            version="1.0.0",
            description="Reusable baseline controls.",
            payload={
                "type": "optivedge.assessments.catalog",
                "schema_version": "1.0",
                "catalog": {
                    "key": "base-controls",
                    "label": "Base Controls",
                    "version": "1.0.0",
                    "description": "Reusable baseline controls.",
                },
                "controls": [],
            },
            is_seeded=True,
        )
        ApplicationEnvironmentCatalogState.objects.create(
            application_environment=self.application_environment,
            current_catalog=catalog,
        )

        home_response = self.client.get(reverse("home"))
        catalog_response = self.client.get(reverse("assessment_catalog_list"))

        self.assertEqual(home_response.status_code, 200)
        self.assertContains(home_response, "Client Settings")
        self.assertEqual(catalog_response.status_code, 200)
        self.assertContains(catalog_response, "Catalogs")
        self.assertContains(catalog_response, "Snapshot Current")


class CatalogDriftTargetModelTests(TestCase):
    """Verify that target_model is included in the drift fingerprint."""

    def _make_payload(self, target_model):
        # Minimal payload with no queries so the only variable is target_model.
        return {
            "type": "optivedge.assessments.catalog",
            "schema_version": "1.0",
            "catalog": {"key": "test", "label": "Test", "version": "v1", "description": ""},
            "controls": [{
                "control_id": "TM-DRIFT-001",
                "name": "Test",
                "control_type": "security_rule",
                "description": "test",
                "rationale": "", "audit": "", "remediation": "",
                "default_severity": "medium",
                "implementation_version": "v1",
                "target_model": target_model,
                "is_active": True,
                "queries": [],
            }],
        }

    def setUp(self):
        # Live control with no queries — matches the minimal payload structure.
        Control.objects.create(
            control_id="TM-DRIFT-001",
            name="Test",
            control_type=Control.ControlType.SECURITY_RULE,
            description="test",
            default_severity=Control.Severity.MEDIUM,
        )
        # target_model auto-set to "integrations.SecurityRule" by save()

    def test_matching_target_model_no_drift(self):
        payload = self._make_payload("integrations.SecurityRule")
        self.assertFalse(catalog_has_drifted(payload))

    def test_different_target_model_reports_drift(self):
        payload = self._make_payload("integrations.OtherModel")
        self.assertTrue(catalog_has_drifted(payload))


class CatalogSchemaTargetModelValidationTests(TestCase):
    def _base_payload(self, target_model, query_model):
        return {
            "type": "optivedge.assessments.catalog",
            "schema_version": "1.0",
            "catalog": {"key": "test", "label": "Test", "version": "v1", "description": ""},
            "controls": [{
                "control_id": "SCHEMA-TM-001",
                "name": "Test",
                "control_type": "security_rule",
                "description": "test",
                "rationale": "", "audit": "", "remediation": "",
                "default_severity": "medium",
                "implementation_version": "v1",
                "target_model": target_model,
                "is_active": True,
                "queries": [{
                    "name": "Baseline",
                    "short_description": "",
                    "canonical_query": {"model": query_model, "operator": "and", "clauses": [{"field": "from_zone", "op": "eq", "value": "trust"}]},
                    "is_baseline": True,
                    "adjusted_severity": None,
                    "is_active": True,
                }],
            }],
        }

    def test_matching_target_and_query_model_valid(self):
        payload = self._base_payload("integrations.SecurityRule", "integrations.SecurityRule")
        result = validate_catalog_payload(payload)
        self.assertEqual(result["controls"][0]["target_model"], "integrations.SecurityRule")

    def test_mismatched_target_and_query_model_invalid(self):
        from django.core.exceptions import ValidationError
        payload = self._base_payload("integrations.LoginBanner", "integrations.SecurityRule")
        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload)

    def test_security_rule_with_another_models_target_invalid(self):
        from django.core.exceptions import ValidationError
        payload = self._base_payload("integrations.LoginBanner", "integrations.LoginBanner")
        # control_type=security_rule but target_model=LoginBanner — contradicts save() derivation
        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload)

    def test_config_control_with_nonempty_target_model_invalid(self):
        from django.core.exceptions import ValidationError
        payload = self._base_payload("integrations.SecurityRule", "integrations.SecurityRule")
        payload["controls"][0]["control_type"] = "config"
        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload)


def build_minimal_catalog_payload(*, key: str, label: str) -> dict:
    return {
        "type": "optivedge.assessments.catalog",
        "schema_version": "1.0",
        "catalog": {"key": key, "label": label, "version": "1.0.0", "description": ""},
        "controls": [],
    }


class CatalogViewTests(TestCase):
    def setUp(self):
        self.application_environment = ApplicationEnvironment.objects.create(
            client_name="Example Corp",
            client_short_name="EXAMPLE",
            opportunity_number="OP-1234567",
        )

    def test_create_from_current_view_creates_catalog_and_redirects(self):
        Control.objects.create(
            control_id="FW-RULE-VIEW-001",
            name="View Control",
            control_type=Control.ControlType.SECURITY_RULE,
            description="desc",
            remediation="remediate",
            default_severity=Control.Severity.MEDIUM,
        )

        response = self.client.post(
            reverse("assessment_catalog_create_from_current"),
            {"label": "View Snapshot", "version": "v1", "description": "created via view"},
        )

        self.assertRedirects(response, reverse("assessment_catalog_list"))
        self.assertTrue(Catalog.objects.filter(label="View Snapshot").exists())

    def test_create_from_current_view_errors_when_no_live_controls(self):
        response = self.client.post(
            reverse("assessment_catalog_create_from_current"),
            {"label": "Empty Snapshot", "version": "v1", "description": ""},
        )

        self.assertRedirects(response, reverse("assessment_catalog_list"))
        self.assertFalse(Catalog.objects.filter(label="Empty Snapshot").exists())

    def test_apply_view_applies_catalog_and_redirects(self):
        catalog = Catalog.objects.create(
            key="view-apply",
            label="View Apply",
            version="1.0.0",
            description="",
            payload=build_minimal_catalog_payload(key="view-apply", label="View Apply"),
        )

        response = self.client.post(
            reverse("assessment_catalog_apply", kwargs={"pk": catalog.pk}),
        )

        self.assertRedirects(response, reverse("assessment_catalog_list"))
        state = ApplicationEnvironmentCatalogState.objects.get(
            application_environment=self.application_environment,
        )
        self.assertEqual(state.current_catalog, catalog)

    def test_apply_view_requires_application_environment(self):
        self.application_environment.delete()
        catalog = Catalog.objects.create(
            key="view-apply-2",
            label="View Apply 2",
            version="1.0.0",
            description="",
            payload=build_minimal_catalog_payload(key="view-apply-2", label="View Apply 2"),
        )

        response = self.client.post(
            reverse("assessment_catalog_apply", kwargs={"pk": catalog.pk}),
        )

        self.assertRedirects(response, reverse("home"))
        self.assertFalse(ApplicationEnvironmentCatalogState.objects.exists())

    def test_download_view_returns_catalog_payload_as_json_attachment(self):
        catalog = Catalog.objects.create(
            key="view-download",
            label="View Download",
            version="1.0.0",
            description="",
            payload=build_minimal_catalog_payload(key="view-download", label="View Download"),
        )

        response = self.client.get(reverse("assessment_catalog_download", kwargs={"pk": catalog.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("attachment;", response["Content-Disposition"])
        payload = json.loads(response.content)
        self.assertEqual(payload["catalog"]["key"], "view-download")

    def test_seed_download_view_returns_seed_payload_as_json_attachment(self):
        response = self.client.get(reverse("assessment_catalog_seed_download"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("attachment;", response["Content-Disposition"])
        payload = json.loads(response.content)
        self.assertEqual(payload["type"], "optivedge.assessments.catalog_seed")
