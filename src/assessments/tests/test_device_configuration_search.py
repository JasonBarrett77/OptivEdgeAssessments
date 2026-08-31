from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.device_configuration_findings import regenerate_device_configuration_findings
from assessments.models import (
    AssessmentRun,
    Control,
    ControlQuery,
    DeviceConfigurationFinding,
)
from assessments.search.compiler import apply_search
from django.contrib.contenttypes.models import ContentType
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    DeviceConfigurationProfile,
    FieldProvenance,
    ManagementStation,
    Snapshot,
)


class DeviceConfigurationSearchTests(TestCase):
    model_name = "integrations.DeviceConfigurationProfile"

    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        appliance_group = ApplianceGroup.objects.create(
            management_station=station,
            name="ha-pair-a",
            group_type=ApplianceGroup.TYPE_HA_PAIR,
        )
        appliance = Appliance.objects.create(
            management_station=station,
            appliance_group=appliance_group,
            serial_number="SERIAL-100",
            hostname="fw-100",
        )
        snapshot = Snapshot.objects.create(
            management_station=station,
            appliance=appliance,
            source_type="show_merged_config",
            collected_at=timezone.now(),
            payload={"config": {}},
        )
        self.profile = DeviceConfigurationProfile.objects.create(
            management_station=station,
            appliance=appliance,
            appliance_group=appliance_group,
            source_snapshot=snapshot,
            config_source="local",
            ha_required=True,
            ha_enabled=True,
            ha_state_sync_enabled=False,
            ha_link_monitoring_enabled=False,
            ntp_primary_server="time1.example.com",
            ntp_secondary_server="",
            permitted_ip_values=[],
            permitted_ip_count=0,
            login_banner="",
            idle_timeout_minutes=60,
            raw_profile={},
        )
        ct = ContentType.objects.get_for_model(DeviceConfigurationProfile)
        FieldProvenance.objects.bulk_create([
            FieldProvenance(
                content_type=ct, object_id=self.profile.pk,
                field_name=fn, provenance_type=FieldProvenance.ProvenanceType.LOCAL,
                raw_key="", raw_value="",
            )
            for fn in ("ha_enabled", "ha_state_sync_enabled", "ntp_primary_server")
        ])
        self.control = Control.objects.create(
            control_id="MGMT-TEST-001",
            name="Test management control",
            control_type=Control.ControlType.DEVICE_CONFIGURATION,
            description="Prototype management control",
            default_severity=Control.Severity.MEDIUM,
        )

    def test_apply_search_supports_device_configuration_boolean_and_integer_fields(self):
        queryset, _search_query = apply_search(
            DeviceConfigurationProfile.objects.all(),
            """
            {
              "model": "integrations.DeviceConfigurationProfile",
              "operator": "and",
              "clauses": [
                {"field": "ha_required", "op": "eq", "value": true},
                {"field": "idle_timeout_minutes", "op": "gt", "value": 10}
              ]
            }
            """,
        )

        self.assertEqual(list(queryset), [self.profile])

    def test_apply_search_supports_device_configuration_text_is_empty(self):
        queryset, _search_query = apply_search(
            DeviceConfigurationProfile.objects.all(),
            """
            {
              "model": "integrations.DeviceConfigurationProfile",
              "operator": "and",
              "clauses": [
                {"field": "ntp_secondary_server", "op": "is_empty", "value": ""}
              ]
            }
            """,
        )

        self.assertEqual(list(queryset), [self.profile])

    def test_regenerate_device_configuration_findings_emits_finding(self):
        ControlQuery.objects.create(
            control=self.control,
            name="Baseline",
            short_description="Flags missing secondary NTP.",
            canonical_query={
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "ntp_secondary_server",
                        "op": "is_empty",
                        "value": "",
                    }
                ],
            },
            is_baseline=True,
        )

        result = regenerate_device_configuration_findings()

        self.assertEqual(result.controls_evaluated, 1)
        self.assertEqual(result.findings_created, 1)
        self.assertEqual(result.query_links_created, 1)
        self.assertEqual(AssessmentRun.objects.count(), 1)
        self.assertEqual(DeviceConfigurationFinding.objects.count(), 1)

        finding = DeviceConfigurationFinding.objects.select_related(
            "assessment_run",
            "control",
            "device_configuration_profile",
        ).get()
        self.assertEqual(finding.control, self.control)
        self.assertEqual(finding.device_configuration_profile, self.profile)
        self.assertEqual(finding.severity, Control.Severity.MEDIUM)
        self.assertEqual(finding.assessment_run.status, AssessmentRun.Status.COMPLETED)
        self.assertEqual(finding.control_queries.count(), 1)

    def test_device_configuration_finding_list_view_renders(self):
        ControlQuery.objects.create(
            control=self.control,
            name="Baseline",
            short_description="Flags missing secondary NTP.",
            canonical_query={
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "ntp_secondary_server",
                        "op": "is_empty",
                        "value": "",
                    }
                ],
            },
            is_baseline=True,
        )
        regenerate_device_configuration_findings()

        response = self.client.get(reverse("assessment_finding_list") + "?tab=device-configuration")

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Device Configuration Findings")
        self.assertContains(response, self.control.control_id)
        self.assertContains(response, self.profile.appliance.hostname)

    def test_control_run_configuration_findings_view_regenerates_findings(self):
        ControlQuery.objects.create(
            control=self.control,
            name="Baseline",
            short_description="Flags missing secondary NTP.",
            canonical_query={
                "model": self.model_name,
                "operator": "and",
                "clauses": [
                    {
                        "field": "ntp_secondary_server",
                        "op": "is_empty",
                        "value": "",
                    }
                ],
            },
            is_baseline=True,
        )

        response = self.client.post(
            reverse("assessment_control_run_configuration_findings"),
            follow=True,
        )

        self.assertRedirects(response, reverse("assessment_control_list"))
        self.assertEqual(DeviceConfigurationFinding.objects.count(), 1)
        self.assertContains(response, "Configuration findings regenerated.")
