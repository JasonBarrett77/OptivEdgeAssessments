from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from assessments.controls_catalog.io.importers import (
    apply_catalog,
    create_catalog_from_current_controls,
    seed_catalogs_if_empty,
)
from assessments.models import (
    ApplicationEnvironmentCatalogState,
    AssessmentRun,
    Catalog,
    Control,
    ControlQuery,
)
from optivedge.integrations.models import ApplicationEnvironment


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
        self.assertContains(home_response, "Control Catalog")
        self.assertContains(home_response, "Base Controls")
        self.assertEqual(catalog_response.status_code, 200)
        self.assertContains(catalog_response, "Control Catalogs")
        self.assertContains(catalog_response, "Download Seed JSON")
