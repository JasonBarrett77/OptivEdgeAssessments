"""Every active control, in one run.

Until 2026-09-16 the UI offered two actions - policy findings and "everything else" - each
creating its own run, on the theory that a user asks "are my rules bad" separately from "is my
device configured badly". Jason, 2026-09-16: "The split between policy and device findings
shouldn't exist." A run is now the whole assessment, which is also what lets a finding's
reference number be unique across every finding model at once (see `FindingBase`).

The per-type generators fill a run they are handed rather than each creating their own. Adding
a control type means adding one line to GENERATORS - and a test fails until you do. It should
not mean adding a button, because the number of buttons is a question about what a user is
asking, not about how many models back the answer.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.utils import timezone

from assessments.admin_user_findings import generate_admin_user_findings
from assessments.authentication_profile_findings import generate_authentication_profile_findings
from assessments.authentication_sequence_findings import generate_authentication_sequence_findings
from assessments.authentication_settings_findings import generate_authentication_settings_findings
from assessments.findings import generate_rule_findings
from assessments.certificate_findings import generate_certificate_findings
from assessments.coverage_findings import generate_coverage_findings
from assessments.device_identification_findings import (
    generate_device_identification_findings,
)
from assessments.zone_findings import generate_zone_findings
from assessments.user_id_collector_findings import (
    generate_user_id_collector_findings,
)
from assessments.user_id_discovery_bound_findings import (
    generate_user_id_discovery_bound_findings,
)
from assessments.rulebase_device_match_findings import (
    generate_rulebase_device_match_findings,
)
from assessments.globalprotect_portal_findings import (
    generate_globalprotect_portal_findings,
)
from assessments.globalprotect_portal_client_auth_findings import (
    generate_globalprotect_portal_client_auth_findings,
)
from assessments.globalprotect_enforcement_point_findings import (
    generate_globalprotect_enforcement_point_findings,
)
from assessments.firewall_content_streams_findings import (
    generate_firewall_content_streams_findings,
)
from assessments.licence_inventory_findings import (
    generate_licence_inventory_findings,
)
from assessments.log_alarm_settings_findings import (
    generate_log_alarm_settings_findings,
)
from assessments.content_update_schedule_findings import (
    generate_content_update_schedule_findings,
)
from assessments.custom_url_category_findings import (
    generate_custom_url_category_findings,
)
from assessments.data_filtering_posture_findings import (
    generate_data_filtering_posture_findings,
)
from assessments.dhcp_interface_config_findings import (
    generate_dhcp_interface_config_findings,
)
from assessments.interface_findings import generate_interface_findings
from assessments.lldp_global_findings import generate_lldp_global_findings
from assessments.routing_adjacency_findings import generate_routing_adjacency_findings
from assessments.session_settings_findings import generate_session_settings_findings
from assessments.tunnel_inspection_findings import generate_tunnel_inspection_findings
from assessments.normalization_findings import generate_normalization_findings
from assessments.certificate_profile_findings import generate_certificate_profile_findings
from assessments.cloud_app_engine_findings import generate_cloud_app_engine_findings
from assessments.ike_crypto_profile_findings import generate_ike_crypto_profile_findings
from assessments.ike_gateway_findings import generate_ike_gateway_findings
from assessments.high_availability_findings import generate_high_availability_findings
from assessments.panorama_registration_findings import (
    generate_panorama_registration_findings,
)
from assessments.saas_application_policy_posture_findings import (
    generate_saas_application_policy_posture_findings,
)
from assessments.saas_url_filtering_posture_findings import (
    generate_saas_url_filtering_posture_findings,
)
from assessments.sanctioned_application_marking_findings import (
    generate_sanctioned_application_marking_findings,
)
from assessments.interface_management_profile_findings import (
    generate_interface_management_profile_findings,
)
from assessments.logging_settings_findings import generate_logging_settings_findings
from assessments.wildfire_settings_findings import generate_wildfire_settings_findings
from assessments.login_banner_findings import generate_login_banner_findings
from assessments.management_interface_findings import generate_management_interface_findings
from assessments.management_tls_findings import generate_management_tls_findings
from assessments.management_ssh_findings import generate_management_ssh_findings
from assessments.master_key_findings import generate_master_key_findings
from assessments.models import AssessmentRun, Control
from assessments.ntp_settings_findings import generate_ntp_settings_findings
from assessments.password_complexity_findings import generate_password_complexity_findings
from assessments.password_profile_findings import generate_password_profile_findings
from assessments.security_profile_findings import generate_security_profile_findings
from assessments.server_profile_findings import generate_server_profile_findings
from assessments.snmp_settings_findings import generate_snmp_settings_findings
from assessments.ssl_tls_service_profile_findings import (
    generate_ssl_tls_service_profile_findings,
)
from assessments.system_identity_findings import generate_system_identity_findings
from assessments.update_server_settings_findings import generate_update_server_settings_findings

T = Control.ControlType

#: (label, the control type whose findings it writes, generator). Ordered so a report reads
#: device-wide settings before per-surface exposure, then the objects.
#:
#: The control type is carried so a test can compare this tuple with `finding_registry`. The
#: tuple fell behind the registry twice without anything failing: the administrator and AAA
#: server generators were never added, and when `DeviceConfigurationProfile` was split into
#: seven models on 2026-09-10, none of the seven was either - so for a day the one button
#: produced no findings at all for 24 controls. `test_finding_run` now checks the two agree -
#: for EVERY registered kind, security rules included.
#:
#: The order is also the order reference numbers are allocated in, so F-0001 is the first
#: password-complexity finding and policy findings come last.
GENERATORS = (
    ("password complexity", T.PASSWORD_COMPLEXITY, generate_password_complexity_findings),
    ("authentication settings", T.AUTHENTICATION_SETTINGS, generate_authentication_settings_findings),
    ("login banner", T.LOGIN_BANNER, generate_login_banner_findings),
    ("management TLS", T.MANAGEMENT_TLS, generate_management_tls_findings),
    ("management SSH", T.MANAGEMENT_SSH, generate_management_ssh_findings),
    ("master key", T.MASTER_KEY, generate_master_key_findings),
    ("update server", T.UPDATE_SERVER, generate_update_server_settings_findings),
    ("logging settings", T.LOGGING_SETTINGS, generate_logging_settings_findings),
    ("wildfire settings", T.WILDFIRE_SETTINGS, generate_wildfire_settings_findings),
    # Device-wide services, so they sit with the settings above rather than with the objects
    # below: one row per appliance, and nothing references them.
    ("NTP", T.NTP_SETTINGS, generate_ntp_settings_findings),
    ("SNMP", T.SNMP_SETTINGS, generate_snmp_settings_findings),
    ("system identity", T.SYSTEM_IDENTITY, generate_system_identity_findings),
    # Device-wide management-plane settings, so they sit with the settings above: one row per
    # appliance. High availability first, because PAN-HAP-005's applicability turns on whether
    # the MANAGEMENT estate is a pair and a reader meets the firewall's own pair first.
    ("high availability", T.HIGH_AVAILABILITY, generate_high_availability_findings),
    ("panorama registration", T.PANORAMA_REGISTRATION,
     generate_panorama_registration_findings),
    ("management interface", T.MANAGEMENT_INTERFACE, generate_management_interface_findings),
    ("interface management profile", T.INTERFACE_MANAGEMENT_PROFILE,
     generate_interface_management_profile_findings),
    ("ssl/tls service profile", T.SSL_TLS_SERVICE_PROFILE, generate_ssl_tls_service_profile_findings),
    ("certificate profile", T.CERTIFICATE_PROFILE, generate_certificate_profile_findings),
    ("certificate", T.CERTIFICATE, generate_certificate_findings),
    # The two IKE objects, gateway after proposal set: a gateway's finding names the profile it
    # points at, so a reader meets the proposal before the binding that chooses it.
    ("ike crypto profile", T.IKE_CRYPTO_PROFILE, generate_ike_crypto_profile_findings),
    ("ike gateway", T.IKE_GATEWAY, generate_ike_gateway_findings),
    # App-ID Cloud Engine before the three SaaS verdicts, because its state is the PREMISE they
    # rest on: rules and filters naming cloud-delivered App-IDs stay visible in the policy while
    # they stop enforcing, so a reader meets "the engine is not working" before any finding that
    # assumes it is.
    ("App-ID Cloud Engine", T.CLOUD_APP_ENGINE_SETTING, generate_cloud_app_engine_findings),
    ("sanctioned application marking", T.SANCTIONED_APPLICATION_MARKING,
     generate_sanctioned_application_marking_findings),
    ("SaaS URL filtering posture", T.SAAS_URL_FILTERING_POSTURE,
     generate_saas_url_filtering_posture_findings),
    ("SaaS application policy posture", T.SAAS_APPLICATION_POLICY_POSTURE,
     generate_saas_application_policy_posture_findings),
    # Last on purpose: it reports what the run could NOT establish, so it reads as the
    # footnote to everything above rather than as another finding family.
    ("coverage", T.COVERAGE, generate_coverage_findings),
    # Beside coverage, for the same reason: it reports what the run could not establish. The
    # two differ only in which gap they can reach - see `normalization_findings`.
    ("normalization", T.NORMALIZATION, generate_normalization_findings),
    ("authentication profile", T.AUTHENTICATION_PROFILE, generate_authentication_profile_findings),
    ("authentication sequence", T.AUTHENTICATION_SEQUENCE, generate_authentication_sequence_findings),
    ("password profile", T.PASSWORD_PROFILE, generate_password_profile_findings),
    ("security profile", T.SECURITY_PROFILE, generate_security_profile_findings),
    ("administrator", T.ADMIN_USER, generate_admin_user_findings),
    ("aaa server profile", T.SERVER_PROFILE, generate_server_profile_findings),
    # Network hardening, device-wide settings first and then the per-surface objects, which is
    # this tuple's own ordering rule. `global LLDP` writes nothing today - no shipped control
    # targets it, because PAN-NET-003 asserts across two models and one control cannot hold
    # both - and it is here so the entry cannot be the thing that is forgotten later.
    ("session settings", T.SESSION_SETTINGS, generate_session_settings_findings),
    ("global LLDP", T.LLDP_GLOBAL, generate_lldp_global_findings),
    ("interface", T.FIREWALL_INTERFACE, generate_interface_findings),
    ("dhcp interface configuration", T.DHCP_INTERFACE_CONFIG,
     generate_dhcp_interface_config_findings),
    ("tunnel inspection coverage", T.TUNNEL_INSPECTION, generate_tunnel_inspection_findings),
    ("routing adjacency", T.ROUTING_ADJACENCY, generate_routing_adjacency_findings),
    # `device-id-iot`, in this tuple's own ordering rule: the device-wide service state first,
    # then the per-zone setting, then the verdict over the policy. The appliance's entitlement and
    # installed classification data are the PREMISE the other two rest on - a zone with
    # identification switched on identifies nothing without the service behind it - so a reader
    # meets "there is no working means of identifying devices" before any finding that assumes
    # there is.
    ("device identification", T.DEVICE_IDENTIFICATION, generate_device_identification_findings),
    ("security zone", T.ZONE, generate_zone_findings),
    ("rulebase device match", T.RULEBASE_DEVICE_MATCH,
     generate_rulebase_device_match_findings),
    # `file-data-filtering`. The posture is a verdict over an enforcement point, so it sits with
    # the other per-point conclusions and before the policy below. Its three sibling controls
    # need no line here: they target `SecurityProfile`, whose generator already exists.
    ("data filtering posture", T.DATA_FILTERING_POSTURE,
     generate_data_filtering_posture_findings),
    # `globalprotect-portal`, in this tuple's own ordering rule: the VSYS-WIDE verdict first, then
    # the portal, then the row beneath it. A reader meets "this virtual system publishes internal
    # web applications for browser access" - or holds the pieces to - before any finding about one
    # portal's settings, and meets the portal before the authentication row inside it, because the
    # row's own severity turns on a leaf of the portal above it.
    ("GlobalProtect enforcement point", T.GLOBALPROTECT_ENFORCEMENT_POINT,
     generate_globalprotect_enforcement_point_findings),
    ("GlobalProtect portal", T.GLOBALPROTECT_PORTAL, generate_globalprotect_portal_findings),
    ("GlobalProtect portal authentication row", T.GLOBALPROTECT_PORTAL_CLIENT_AUTH,
     generate_globalprotect_portal_client_auth_findings),
    # `platform-lifecycle`, in this tuple's own ordering rule: what the appliance is ENTITLED to
    # first, then what it has actually LOADED, then the mechanism that would say a log database
    # filled. A reader meets "this appliance's licence table could not be read" before "its
    # antivirus stream was never installed", because the first is a candidate explanation for the
    # second - and meets both before the alarm node, which is about the device noticing its own
    # storage rather than about protection.
    ("licence inventory", T.LICENCE_INVENTORY, generate_licence_inventory_findings),
    # `updates`, placed BEFORE the content streams it explains and after the licence inventory
    # that entitles them - this tuple's own ordering rule is cause before symptom. The schedule
    # is the CONFIGURED CAUSE of stale content and PAN-PLT-002's streams are the RUNTIME
    # SYMPTOM; stage 3 settled that division in writing, and a reader who meets "this appliance
    # retrieves no antivirus content at all" before "its antivirus stream is a year old" has the
    # explanation in hand when the symptom arrives.
    ("content update schedule", T.CONTENT_UPDATE_SCHEDULE,
     generate_content_update_schedule_findings),
    ("firewall content streams", T.FIREWALL_CONTENT_STREAMS,
     generate_firewall_content_streams_findings),
    ("log database alarm mechanism", T.LOG_ALARM_SETTINGS,
     generate_log_alarm_settings_findings),
    # `url-filtering`. The OBJECT a profile's action list points at, so it sits with the other
    # named objects and before the policy below. ONE line for ONE control - PAN-URL-006's
    # category half - because the domain's other five controls target `SecurityProfile`, whose
    # generator already exists and picks them up by type on the next run.
    ("custom URL category", T.CUSTOM_URL_CATEGORY, generate_custom_url_category_findings),
    # `user-id`. TWO lines for SIX controls: PAN-UID-003, -004 and -006 share the collector
    # generator, PAN-UID-002 has the discovery bound to itself, and the domain's other two need
    # no line here at all - PAN-UID-001 is picked up by `security zone` above and PAN-UID-005 by
    # `management interface`, both by type on the next run, which is the cheap half of reusing a
    # type. (The expensive half is the summary sentence, and `zone_findings` carries a
    # PAN-UID-001 entry for exactly that reason.)
    #
    # The collector runs BEFORE the discovery bound because the collector is the thing that
    # performs discovery: a reader meeting an unbounded discovery scope wants to know first
    # whether the agent probing it is the credentialed kind, which is PAN-UID-003's row.
    ("User-ID collector", T.USER_ID_COLLECTOR, generate_user_id_collector_findings),
    ("User-ID discovery bound", T.USER_ID_DISCOVERY_BOUND,
     generate_user_id_discovery_bound_findings),
    # Policy last: the device's own configuration reads before the rules it enforces.
    ("security rule", T.SECURITY_RULE, generate_rule_findings),
)


@dataclass
class FindingRunResult:
    assessment_run: AssessmentRun
    controls_evaluated: int
    findings_created: int
    query_links_created: int
    skipped_queries: int
    #: Per-generator counts, so a caller can say WHICH kind produced nothing.
    by_kind: dict


def summarise_run(controls, findings, links, skipped) -> str:
    """One sentence, led by the thing most easily missed."""
    summary = (f"Controls: {controls}. Findings: {findings}. Query links: {links}. "
               f"Skipped queries: {skipped}.")
    if skipped:
        summary = (f"Attention: {skipped} quer{'y' if skipped == 1 else 'ies'} could not be "
                   f"compiled, so the control{'' if skipped == 1 else 's'} using "
                   f"{'it' if skipped == 1 else 'them'} contributed nothing. " + summary)
    return summary


def open_findings_run() -> AssessmentRun:
    """The run row, RUNNING, before any generator touches it.

    Separated from `regenerate_findings` so a view can open it inside the REQUEST and hand the
    pk to a background thread. The page the browser lands on then always finds a run in
    progress; opened on the thread, it could render before the row existed and show nothing
    happening.
    """
    return AssessmentRun.objects.create(
        name=f"Findings {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}",
        status=AssessmentRun.Status.RUNNING,
        started_at=timezone.now(),
    )


def findings_run_in_progress() -> AssessmentRun | None:
    """The findings run currently filling, or None.

    A RUNNING run is a live one: a restart that killed its thread closes it - see
    `lifecycle.close_interrupted_work`. There was a two-hour age limit here until 2026-10-15.
    """
    return (AssessmentRun.objects
            .filter(status=AssessmentRun.Status.RUNNING)
            .order_by("-started_at")
            .first())


def regenerate_findings(assessment_run: AssessmentRun | None = None) -> FindingRunResult:
    if assessment_run is None:
        assessment_run = open_findings_run()
    totals = [0, 0, 0, 0]
    by_kind = {}
    try:
        for label, _control_type, generate in GENERATORS:
            counts = generate(assessment_run)
            by_kind[label] = counts
            totals = [a + b for a, b in zip(totals, counts)]
    except Exception as exc:
        # One generator failing fails the run. A partially-filled run reported as complete
        # would understate findings, which is the direction that hides problems.
        assessment_run.mark_failed()
        assessment_run.notes = f"Run failed: {type(exc).__name__}: {exc}"[:2000]
        assessment_run.save(update_fields=["status", "completed_at", "notes"])
        raise

    # The tables the findings pages and the workbook draw, stored while the run still holds
    # off builds and normalization - so the first reader does not wait for them. It cannot fail
    # the run: a table that will not build is logged, and its page reports why.
    from assessments.artifacts.stored import store_run_tables

    store_run_tables(assessment_run)

    assessment_run.mark_completed()
    # THE RUN REPORTS ITSELF. The outcome used to be a Django message written by the view, and
    # the view no longer waits for the run - it starts a thread and returns. A message cannot be
    # written from there, and the one signal that most needed carrying is the skipped-query
    # count: a query that no longer compiles makes its control contribute nothing, which reads
    # exactly like a clean result. So the sentence lives on the run, survives navigation, and is
    # still there when somebody asks later what that run actually did.
    assessment_run.notes = summarise_run(*totals)
    assessment_run.save(update_fields=["status", "completed_at", "notes"])
    return FindingRunResult(
        assessment_run=assessment_run,
        controls_evaluated=totals[0], findings_created=totals[1],
        query_links_created=totals[2], skipped_queries=totals[3], by_kind=by_kind)
