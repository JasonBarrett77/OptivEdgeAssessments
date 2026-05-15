from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments.management_findings import regenerate_management_plane_findings
from assessments.models import (
    AssessmentRun,
    Control,
    ControlQuery,
    ManagementPlaneFinding,
)
from assessments.search.compiler import apply_search
from optivedge.integrations.models import (
    Appliance,
    ApplianceGroup,
    ManagementPlaneProfile,
    ManagementStation,
    Snapshot,
)


class ManagementPlaneSearchTests(TestCase):
    model_name = "integrations.ManagementPlaneProfile"

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
        self.profile = ManagementPlaneProfile.objects.create(
            management_station=station,
            appliance=appliance,
            appliance_group=appliance_group,
            source_snapshot=snapshot,
            config_source="local",
            provenance="local",
            ha_required=True,
            ha_enabled=True,
            ha_enabled_explicit=True,
            ha_enabled_prov="local",
            ha_state_sync_enabled=False,
            ha_state_sync_explicit=True,
            ha_state_sync_prov="local",
            ha_link_monitoring_enabled=False,
            ha_link_monitoring_explicit=False,
            ha_link_monitoring_prov="",
            ntp_primary_server="time1.example.com",
            ntp_primary_server_prov="local",
            ntp_secondary_server="",
            ntp_secondary_server_prov="",
            http_disabled=True,
            http_disabled_explicit=True,
            http_disabled_prov="local",
            https_disabled=False,
            https_disabled_explicit=False,
            https_disabled_prov="",
            telnet_disabled=True,
            telnet_disabled_explicit=True,
            telnet_disabled_prov="local",
            ssh_disabled=False,
            ssh_disabled_explicit=False,
            ssh_disabled_prov="",
            icmp_disabled=False,
            icmp_disabled_explicit=False,
            icmp_disabled_prov="",
            snmp_disabled=True,
            snmp_disabled_explicit=False,
            snmp_disabled_prov="",
            permitted_ip_values=[],
            permitted_ip_count=0,
            has_permitted_ip_restrictions=False,
            has_unrestricted_permitted_ips=False,
            login_banner="",
            login_banner_prov="",
            idle_timeout_minutes=60,
            idle_timeout_explicit=False,
            idle_timeout_prov="",
            raw_profile={},
        )
        self.control = Control.objects.create(
            control_id="MGMT-TEST-001",
            name="Test management control",
            control_type=Control.ControlType.MANAGEMENT_PLANE,
            description="Prototype management control",
            default_severity=Control.Severity.MEDIUM,
        )

    def test_apply_search_supports_management_plane_boolean_and_integer_fields(self):
        queryset, _search_query = apply_search(
            ManagementPlaneProfile.objects.all(),
            """
            {
              "model": "integrations.ManagementPlaneProfile",
              "operator": "and",
              "clauses": [
                {"field": "ha_required", "op": "eq", "value": true},
                {"field": "idle_timeout_minutes", "op": "gt", "value": 10}
              ]
            }
            """,
        )

        self.assertEqual(list(queryset), [self.profile])

    def test_apply_search_supports_management_plane_text_is_empty(self):
        queryset, _search_query = apply_search(
            ManagementPlaneProfile.objects.all(),
            """
            {
              "model": "integrations.ManagementPlaneProfile",
              "operator": "and",
              "clauses": [
                {"field": "ntp_secondary_server", "op": "is_empty", "value": ""}
              ]
            }
            """,
        )

        self.assertEqual(list(queryset), [self.profile])

    def test_regenerate_management_plane_findings_emits_finding(self):
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

        result = regenerate_management_plane_findings()

        self.assertEqual(result.controls_evaluated, 1)
        self.assertEqual(result.findings_created, 1)
        self.assertEqual(result.query_links_created, 1)
        self.assertEqual(AssessmentRun.objects.count(), 1)
        self.assertEqual(ManagementPlaneFinding.objects.count(), 1)

        finding = ManagementPlaneFinding.objects.select_related(
            "assessment_run",
            "control",
            "management_profile",
        ).get()
        self.assertEqual(finding.control, self.control)
        self.assertEqual(finding.management_profile, self.profile)
        self.assertEqual(finding.severity, Control.Severity.MEDIUM)
        self.assertEqual(finding.assessment_run.status, AssessmentRun.Status.COMPLETED)
        self.assertEqual(finding.control_queries.count(), 1)

    def test_management_plane_finding_list_view_renders(self):
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
        regenerate_management_plane_findings()

        response = self.client.get(reverse("assessment_management_finding_list"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Management Findings")
        self.assertContains(response, self.control.control_id)
        self.assertContains(response, self.profile.appliance.hostname)
