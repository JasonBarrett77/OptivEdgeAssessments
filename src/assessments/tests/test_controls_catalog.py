import json
import re
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from assessments.controls_catalog.drift import catalog_has_drifted
from assessments.controls_catalog.io.importers import (
    apply_catalog,
    create_catalog_from_current_controls,
    refresh_seeded_catalogs,
    seed_catalogs_if_empty,
)
from assessments.controls_catalog.schemas import (
    SHORT_REMEDIATION_LIMIT, validate_catalog_payload)
from assessments.controls_catalog.registry import load_seed_payload
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


class SeededCatalogTextTests(TestCase):
    """The text a CUSTOMER reads, checked on the shipped payload rather than on a model."""

    def test_no_control_ships_a_literal_backslash_n(self):
        """A paragraph break written `\\n` in the JSON reaches the page as two CHARACTERS.

        FOUND BY A SIDEWAYS GLANCE, NOT BY A READER. The stage 8 anti-spyware run of 2026-10-31
        fixed eight of these in PAN-SPY-001's description and reported it as that control's
        defect; the same grep over the whole payload found 28 controls carrying 132 of them,
        across PAN-AUTH, PAN-CRT, PAN-MGT and PAN-VLN, every one in `description` and every one a
        paragraph break beside REAL newlines in the same string. So the shape is a known one: an
        author escaping a newline twice in a field that already holds them literally.

        Checked here and not in a template filter because the payload is where it is wrong - a
        filter would hide it from the next author, and `description` is the one field with no
        length limit and the most prose in it.
        """
        offenders = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                for field, value in control.items():
                    if isinstance(value, str) and "\\n" in value:
                        offenders.setdefault(control["control_id"], []).append(field)
        self.assertEqual(offenders, {})


    def test_every_active_control_ships_a_short_recommendation(self):
        """The one sentence of a control a CLIENT reads, in the health check's Summary of
        Findings and Recommendations.

        It used to be `remediation`, the engineer's instruction - so the table carried UI paths
        and CLI into a document for whoever decides whether to fund the work. Jason, 2026-11-06:
        *"The 'Recommendation' is too long, and the values themselves aren't appropriate for
        this customer facing artifact."*
        """
        missing = [control["control_id"]
                   for catalog in load_seed_payload()["catalogs"]
                   for control in catalog["controls"]
                   if control["is_active"] and not control.get("short_remediation", "").strip()]

        self.assertEqual(missing, [])

    def test_no_short_recommendation_reads_like_an_instruction_to_an_engineer(self):
        """The rule, over the shipped payload: one sentence, 100 characters or fewer, no
        command, no UI path, no control id. `schemas` refuses a catalogue that breaks it; this
        says so about the one that ships, so a bad line cannot reach a client even if the
        refusal is ever loosened.
        """
        offenders = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                value = (control.get("short_remediation") or "").strip()
                if not value:
                    continue
                why = []
                if len(value) > SHORT_REMEDIATION_LIMIT:
                    why.append(f"{len(value)} characters")
                if "`" in value or ">" in value:
                    why.append("a command or a UI path")
                if re.search(r"[A-Z]{2,4}-[A-Z]{2,5}-\d{3}", value):
                    why.append("a control id")
                if len(re.findall(r"\.(?:\s|$)", value)) != 1 or not value.endswith("."):
                    why.append("more or less than one sentence")
                if why:
                    offenders[control["control_id"]] = why

        self.assertEqual(offenders, {})

    def test_a_control_with_no_short_recommendation_is_refused(self):
        """A guard and not a convention: a control added tomorrow without one would put the full
        remediation back in front of a client, and nothing else in the build would notice."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], short_remediation="")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("short_remediation", str(caught.exception))

    def test_a_short_recommendation_that_carries_a_command_is_refused(self):
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    short_remediation="Run `set deviceconfig system`.")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("remediation", str(caught.exception))

    def test_a_short_recommendation_over_the_limit_is_refused(self):
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    short_remediation="Narrow it. " * 20)]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn(str(SHORT_REMEDIATION_LIMIT), str(caught.exception))

    def test_a_snapshot_of_controls_that_predate_the_field_is_not_refused(self):
        """`apply_catalog` snapshots the live controls before replacing them. On a deployment
        upgraded from a release before this field those rows carry nothing, and refusing the
        snapshot would refuse the upgrade that introduces it."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], short_remediation="")]

        validated = validate_catalog_payload(payload, require_short_remediation=False)

        self.assertEqual(validated["controls"][0]["short_remediation"], "")

    def test_a_snapshot_still_refuses_a_line_that_is_unfit_to_print(self):
        """Only the PRESENCE rule is relaxed for a snapshot. A line that exists has to be one a
        client can read, however the payload was built."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    short_remediation="Run `set deviceconfig system`.")]

        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload, require_short_remediation=False)

    def test_an_inactive_control_needs_no_short_recommendation(self):
        """It is graded by nothing, so it reaches no document."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], short_remediation="",
                                    is_active=False)]

        validated = validate_catalog_payload(payload)

        self.assertEqual(validated["controls"][0]["short_remediation"], "")

    def test_it_survives_a_round_trip_through_the_exporter(self):
        """A catalogue exported from the live controls and validated again must not lose it -
        which is how a reissue is made, and losing it there would put the full remediation back
        in the document with nothing failing."""
        seed_catalogs_if_empty()
        refresh_seeded_catalogs()
        payload = load_seed_payload()["catalogs"][0]
        for row in payload["controls"]:
            Control.objects.create(
                control_id=row["control_id"], name=row["name"],
                control_type=row["control_type"], description=row["description"],
                remediation=row["remediation"],
                short_remediation=row["short_remediation"],
                default_severity=row["default_severity"], is_active=row["is_active"],
                target_model=row.get("target_model", ""))

        exported = create_catalog_from_current_controls(
            label="Round trip", version="1", description="A snapshot of the live controls.")

        validated = validate_catalog_payload(exported.payload)
        shipped = next(row for row in validated["controls"]
                       if row["control_id"] == "PAN-MGT-007")
        self.assertEqual(shipped["short_remediation"],
                         Control.objects.get(control_id="PAN-MGT-007").short_remediation)
        self.assertTrue(shipped["short_remediation"])


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
                        "short_remediation": "Tighten the rule's scope.",
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
                            "short_remediation": "Tighten the rule's scope.",
                        "short_remediation": "Tighten the rule's scope.",
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
                "short_remediation": "Tighten the rule's scope.",
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
                "short_remediation": "Tighten the rule's scope.",
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
