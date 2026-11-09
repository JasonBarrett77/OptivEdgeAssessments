"""Shared control-query evaluation helpers."""

from __future__ import annotations

from assessments.models import Control
from assessments.search.compiler import compile_predicate
from assessments.search.exceptions import SearchSyntaxError


SECURITY_RULE_QUERY_MODEL = "integrations.SecurityRule"
MANAGEMENT_INTERFACE_MODEL = "integrations.ManagementInterface"
INTERFACE_MANAGEMENT_PROFILE_MODEL = "integrations.InterfaceManagementProfile"
SSL_TLS_SERVICE_PROFILE_MODEL = "integrations.SslTlsServiceProfile"
CERTIFICATE_PROFILE_MODEL = "integrations.CertificateProfile"
CERTIFICATE_MODEL = "integrations.Certificate"
AUTHENTICATION_PROFILE_MODEL = "integrations.AuthenticationProfile"
AUTHENTICATION_SEQUENCE_MODEL = "integrations.AuthenticationSequence"
PASSWORD_COMPLEXITY_MODEL = "integrations.PasswordComplexityPolicy"
AUTHENTICATION_SETTINGS_MODEL = "integrations.AuthenticationSettings"
LOGIN_BANNER_MODEL = "integrations.LoginBanner"
MANAGEMENT_TLS_MODEL = "integrations.ManagementTlsBinding"
MANAGEMENT_SSH_MODEL = "integrations.ManagementSshSettings"
MASTER_KEY_MODEL = "integrations.MasterKey"
UPDATE_SERVER_SETTINGS_MODEL = "integrations.UpdateServerSettings"
WILDFIRE_SETTINGS_MODEL = "integrations.WildfireSettings"
LOGGING_SETTINGS_MODEL = "integrations.LoggingSettings"
LOG_SERVER_TARGET_MODEL = "integrations.LogServerTarget"
VSYS_LOG_FORWARDING_MODEL = "integrations.VsysLogForwarding"
# `management-services`, 2026-11-01. Two appliance-grained management-plane facts.
MANAGEMENT_PLANE_ADDRESSING_MODEL = "integrations.ManagementPlaneAddressing"
APPLIANCE_OPERATIONAL_MODE_MODEL = "integrations.ApplianceOperationalMode"
PASSWORD_PROFILE_MODEL = "integrations.PasswordProfile"
SECURITY_PROFILE_MODEL = "integrations.SecurityProfile"
ADMIN_USER_MODEL = "integrations.AdminUser"
SERVER_PROFILE_MODEL = "integrations.ServerProfile"
NTP_SETTINGS_MODEL = "integrations.NtpSettings"
SNMP_SETTINGS_MODEL = "integrations.SnmpSettings"
SYSTEM_IDENTITY_MODEL = "integrations.SystemIdentity"
DNS_SETTINGS_MODEL = "integrations.DnsSettings"
SERVICE_ROUTE_MODEL = "integrations.ServiceRoute"
IKE_CRYPTO_PROFILE_MODEL = "integrations.IkeCryptoProfile"
IKE_GATEWAY_MODEL = "integrations.IkeGateway"
# PHASE 2. Four near-identical names across the two phases; these two are the IPSec ones.
IPSEC_CRYPTO_PROFILE_MODEL = "integrations.IpsecCryptoProfile"
IPSEC_TUNNEL_MODEL = "integrations.IpsecTunnel"
IPSEC_TUNNEL_PATH_MODEL = "integrations.IpsecTunnelPath"
HIGH_AVAILABILITY_CONFIG_MODEL = "integrations.HighAvailabilityConfig"
PANORAMA_REGISTRATION_MODEL = "integrations.PanoramaRegistration"
INTERFACE_MODEL = "integrations.Interface"
SESSION_SETTINGS_MODEL = "integrations.PanOsSessionSettings"
LLDP_GLOBAL_MODEL = "integrations.PanOsLldpGlobalSettings"
DHCP_INTERFACE_CONFIG_MODEL = "integrations.PanOsDhcpInterfaceConfig"
TUNNEL_INSPECTION_MODEL = "integrations.PanOsTunnelInspectionCoverage"
ROUTING_ADJACENCY_MODEL = "integrations.PanOsRoutingAdjacency"
SANCTIONED_APPLICATION_MARKING_MODEL = "integrations.SanctionedApplicationMarking"
SAAS_URL_FILTERING_POSTURE_MODEL = "integrations.SaasUrlFilteringPosture"
SAAS_APPLICATION_POLICY_POSTURE_MODEL = "integrations.SaasApplicationPolicyPosture"
CLOUD_APP_ENGINE_SETTING_MODEL = "integrations.CloudAppEngineSetting"
DEVICE_IDENTIFICATION_MODEL = "integrations.DeviceIdentificationState"
ZONE_MODEL = "integrations.Zone"
RULEBASE_DEVICE_MATCH_MODEL = "integrations.RulebaseDeviceMatchVerdict"
DATA_FILTERING_POSTURE_MODEL = "integrations.DataFilteringPosture"
GLOBALPROTECT_PORTAL_MODEL = "integrations.GlobalProtectPortal"
GLOBALPROTECT_PORTAL_CLIENT_AUTH_MODEL = "integrations.GlobalProtectPortalClientAuthRow"
GLOBALPROTECT_ENFORCEMENT_POINT_MODEL = "integrations.GlobalProtectEnforcementPoint"
GLOBALPROTECT_GATEWAY_MODEL = "integrations.GlobalProtectGateway"
GLOBALPROTECT_GATEWAY_CLIENT_AUTH_MODEL = "integrations.GlobalProtectGatewayClientAuth"
GLOBALPROTECT_GATEWAY_AGENT_CONFIG_MODEL = "integrations.GlobalProtectGatewayAgentConfig"
FIREWALL_CONTENT_STREAMS_MODEL = "integrations.FirewallContentStreams"
LICENCE_INVENTORY_MODEL = "integrations.LicenceInventory"
LOG_ALARM_SETTINGS_MODEL = "integrations.LogAlarmSettings"
CONTENT_UPDATE_SCHEDULE_MODEL = "integrations.ContentUpdateSchedule"
CUSTOM_URL_CATEGORY_MODEL = "integrations.CustomUrlCategory"
USER_ID_COLLECTOR_MODEL = "integrations.UserIdCollectorSettings"
USER_ID_DISCOVERY_BOUND_MODEL = "integrations.UserIdDiscoveryBound"
DECRYPTION_SETTINGS_MODEL = "integrations.DecryptionSettings"
ZONE_PROTECTION_PROFILE_MODEL = "integrations.ZoneProtectionProfile"
DOS_POLICY_RULE_MODEL = "integrations.DosPolicyRule"
# `decryption-policy`. TWO GRAINS OVER ONE PAN-OS OBJECT and two more models beside them. The
# per-entry grain reports a rule that exists and is wrong; the verdict grain reports a rulebase
# that does not exist at all, which is the commonest state stage 4 measured.
DECRYPTION_POLICY_RULE_MODEL = "integrations.DecryptionPolicyRule"
DECRYPTION_RULEBASE_COVERAGE_MODEL = "integrations.DecryptionRulebaseVerdict"
SSL_DECRYPTION_EXCLUSION_MODEL = "integrations.SslDecryptionExclusion"
SSL_DECRYPTION_VENDOR_EXCLUSION_OPTOUT_MODEL = (
    "integrations.SslDecryptionVendorExclusionOptOut")
# `security-policy`, 2026-11-01. Two VERDICT grains, neither of them the rule: one virtual
# system's whole policy taken as a set of absences, and the device-wide pair of policy-rule
# switches at `deviceconfig/setting/management`, which has no vsys axis.
VSYS_RULE_POSTURE_MODEL = "integrations.VsysRulePosture"
POLICY_RULE_SETTINGS_MODEL = "integrations.PolicyRuleSettings"


SEVERITY_LABELS = dict(Control.Severity.choices)
SEVERITY_RANK = {
    Control.Severity.INFORMATIONAL: 0,
    Control.Severity.LOW: 1,
    Control.Severity.MEDIUM: 2,
    Control.Severity.HIGH: 3,
    Control.Severity.CRITICAL: 4,
}


def default_security_rule_search_query():
    return {"model": SECURITY_RULE_QUERY_MODEL, "operator": "and", "clauses": []}


def severity_label(severity_value: str) -> str:
    return SEVERITY_LABELS.get(severity_value, severity_value)


def derive_control_query_severity_value(control, matched_queries):
    calibration_queries = [
        query
        for query in matched_queries
        if not query.is_baseline and query.adjusted_severity
    ]
    if not calibration_queries:
        return control.default_severity
    winning_query = max(
        calibration_queries,
        key=lambda query: SEVERITY_RANK[query.adjusted_severity],
    )
    return winning_query.adjusted_severity


def evaluate_queryset_control_queries(queryset, control, *, model_name):
    """Match `queryset` against every active ControlQuery on `control`.

    Runs one broad union query to find every matching object, then attributes matches
    to individual queries (needed for severity ranking) only against that narrowed
    subset - instead of running each active query as its own full-table query.
    """
    active_queries = list(control.queries.filter(is_active=True).order_by("-is_baseline", "name", "pk"))
    predicates_by_query = []
    combined_predicate = None
    skipped_queries = 0

    for control_query in active_queries:
        canonical_query = control_query.canonical_query
        if not isinstance(canonical_query, dict) or canonical_query.get("model") != model_name:
            skipped_queries += 1
            continue
        try:
            predicate = compile_predicate(queryset.model, canonical_query)
        except SearchSyntaxError:
            skipped_queries += 1
            continue
        predicates_by_query.append((control_query, predicate))
        combined_predicate = predicate if combined_predicate is None else combined_predicate | predicate

    if combined_predicate is None:
        return queryset.none(), active_queries, skipped_queries, {}, {}

    matched_ids = set(queryset.filter(combined_predicate).values_list("pk", flat=True))
    if not matched_ids:
        return queryset.none(), active_queries, skipped_queries, {}, {}

    narrowed_queryset = queryset.filter(pk__in=matched_ids)
    matched_by_object = {}
    for control_query, predicate in predicates_by_query:
        for object_id in narrowed_queryset.filter(predicate).values_list("pk", flat=True):
            matched_by_object.setdefault(object_id, []).append(control_query)

    severity_by_object_id = {
        object_id: derive_control_query_severity_value(control, matched_queries)
        for object_id, matched_queries in matched_by_object.items()
    }
    return (
        queryset.filter(pk__in=matched_by_object.keys()),
        active_queries,
        skipped_queries,
        matched_by_object,
        severity_by_object_id,
    )


def evaluate_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SECURITY_RULE_QUERY_MODEL,
    )


def evaluate_interface_management_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or INTERFACE_MANAGEMENT_PROFILE_MODEL,
    )


def evaluate_ssl_tls_service_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SSL_TLS_SERVICE_PROFILE_MODEL,
    )


def evaluate_master_key_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or MASTER_KEY_MODEL,
    )


def evaluate_update_server_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or UPDATE_SERVER_SETTINGS_MODEL,
    )


def evaluate_wildfire_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or WILDFIRE_SETTINGS_MODEL,
    )


def evaluate_logging_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or LOGGING_SETTINGS_MODEL,
    )


def evaluate_management_plane_addressing_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or MANAGEMENT_PLANE_ADDRESSING_MODEL,
    )


def evaluate_appliance_operational_mode_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or APPLIANCE_OPERATIONAL_MODE_MODEL,
    )


def evaluate_management_tls_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or MANAGEMENT_TLS_MODEL,
    )


def evaluate_login_banner_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or LOGIN_BANNER_MODEL,
    )


def evaluate_authentication_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or AUTHENTICATION_SETTINGS_MODEL,
    )


def evaluate_password_complexity_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or PASSWORD_COMPLEXITY_MODEL,
    )


def evaluate_password_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or PASSWORD_PROFILE_MODEL,
    )


def evaluate_security_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SECURITY_PROFILE_MODEL,
    )


def evaluate_decryption_settings_control_queries(queryset, control):
    """PAN-DCP-006's half, over one appliance's forward-proxy signing designation.

    THE DOMAIN's OTHER SIX CONTROLS DO NOT COME THROUGH HERE. They target the `decryption` kind
    of `integrations.SecurityProfile` and go through
    `evaluate_security_profile_control_queries`, because they reuse the `security_profile` type.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DECRYPTION_SETTINGS_MODEL,
    )


def evaluate_server_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SERVER_PROFILE_MODEL,
    )


def evaluate_admin_user_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or ADMIN_USER_MODEL,
    )


def evaluate_authentication_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or AUTHENTICATION_PROFILE_MODEL,
    )


def evaluate_certificate_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or CERTIFICATE_PROFILE_MODEL,
    )


def evaluate_coverage_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset, control, model_name="integrations.AddressObject")


def evaluate_normalization_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset, control, model_name="integrations.NormalizationIssue")


def evaluate_certificate_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or CERTIFICATE_MODEL,
    )


def evaluate_management_interface_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or MANAGEMENT_INTERFACE_MODEL,
    )


def evaluate_authentication_sequence_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or AUTHENTICATION_SEQUENCE_MODEL,
    )


def evaluate_management_ssh_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or MANAGEMENT_SSH_MODEL,
    )


def evaluate_ntp_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or NTP_SETTINGS_MODEL,
    )


def evaluate_snmp_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SNMP_SETTINGS_MODEL,
    )


def evaluate_system_identity_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SYSTEM_IDENTITY_MODEL,
    )


def evaluate_dns_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DNS_SETTINGS_MODEL,
    )


def evaluate_service_route_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SERVICE_ROUTE_MODEL,
    )


def evaluate_ike_crypto_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or IKE_CRYPTO_PROFILE_MODEL,
    )


def evaluate_ike_gateway_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or IKE_GATEWAY_MODEL,
    )


def evaluate_ipsec_crypto_profile_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or IPSEC_CRYPTO_PROFILE_MODEL,
    )


def evaluate_ipsec_tunnel_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or IPSEC_TUNNEL_MODEL,
    )


def evaluate_ipsec_tunnel_path_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or IPSEC_TUNNEL_PATH_MODEL,
    )


def evaluate_high_availability_config_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or HIGH_AVAILABILITY_CONFIG_MODEL,
    )


def evaluate_panorama_registration_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or PANORAMA_REGISTRATION_MODEL,
    )
# Network hardening. PAN-NET-001 to 007, six models.
#
# TWO CONTROLS SHARE `Interface` AND TWO SHARE `PanOsSessionSettings`, which is safe and worth
# saying out loud because the union in `evaluate_queryset_control_queries` makes sharing look
# dangerous: the union is taken over ONE control's active queries, so two controls on one model
# never widen each other and never calibrate each other's severity. They produce two findings on
# the same row, which is correct - they assert unrelated things.


def evaluate_interface_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or INTERFACE_MODEL,
    )


def evaluate_session_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SESSION_SETTINGS_MODEL,
    )


def evaluate_lldp_global_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or LLDP_GLOBAL_MODEL,
    )


def evaluate_dhcp_interface_config_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DHCP_INTERFACE_CONFIG_MODEL,
    )


def evaluate_tunnel_inspection_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or TUNNEL_INSPECTION_MODEL,
    )


def evaluate_routing_adjacency_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or ROUTING_ADJACENCY_MODEL,
    )
def evaluate_sanctioned_application_marking_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SANCTIONED_APPLICATION_MARKING_MODEL,
    )


def evaluate_saas_url_filtering_posture_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SAAS_URL_FILTERING_POSTURE_MODEL,
    )


def evaluate_saas_application_policy_posture_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SAAS_APPLICATION_POLICY_POSTURE_MODEL,
    )


def evaluate_cloud_app_engine_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or CLOUD_APP_ENGINE_SETTING_MODEL,
    )


def evaluate_device_identification_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DEVICE_IDENTIFICATION_MODEL,
    )


def evaluate_zone_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or ZONE_MODEL,
    )


def evaluate_user_id_collector_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or USER_ID_COLLECTOR_MODEL,
    )


def evaluate_user_id_discovery_bound_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or USER_ID_DISCOVERY_BOUND_MODEL,
    )


def evaluate_rulebase_device_match_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or RULEBASE_DEVICE_MATCH_MODEL,
    )


def evaluate_data_filtering_posture_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DATA_FILTERING_POSTURE_MODEL,
    )


def evaluate_globalprotect_portal_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or GLOBALPROTECT_PORTAL_MODEL,
    )


def evaluate_globalprotect_portal_client_auth_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or GLOBALPROTECT_PORTAL_CLIENT_AUTH_MODEL,
    )


def evaluate_globalprotect_enforcement_point_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or GLOBALPROTECT_ENFORCEMENT_POINT_MODEL,
    )


def evaluate_globalprotect_gateway_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or GLOBALPROTECT_GATEWAY_MODEL,
    )


def evaluate_globalprotect_gateway_client_auth_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or GLOBALPROTECT_GATEWAY_CLIENT_AUTH_MODEL,
    )


def evaluate_globalprotect_gateway_agent_config_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or GLOBALPROTECT_GATEWAY_AGENT_CONFIG_MODEL,
    )


def evaluate_firewall_content_streams_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or FIREWALL_CONTENT_STREAMS_MODEL,
    )


def evaluate_licence_inventory_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or LICENCE_INVENTORY_MODEL,
    )


def evaluate_log_alarm_settings_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or LOG_ALARM_SETTINGS_MODEL,
    )


def evaluate_content_update_schedule_control_queries(queryset, control):
    """One appliance's content update schedule, for all four controls over this model.

    PAN-UPD-001, -002, -004 and -005 share one target model and one evaluate helper. Which
    content type a finding is about is decided by the CONTROL's own queries and not here: each
    control's clauses name only its own content type's columns.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or CONTENT_UPDATE_SCHEDULE_MODEL,
    )


def evaluate_custom_url_category_control_queries(queryset, control):
    """One custom URL category definition, for PAN-URL-006's category half.

    ONE CONTROL AND ONE RECORD REACH THIS HELPER. PAN-URL-006's other two assertion records name
    the URL filtering profile, which is a different model with no relation to this one in either
    direction, so they are silent rather than evaluated here - recorded in the stage 8 artifact's
    `subjects_in_two_models`. The domain's other five controls evaluate through
    `evaluate_security_profile_control_queries`, because they reuse the `security_profile` type.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or CUSTOM_URL_CATEGORY_MODEL,
    )


def evaluate_zone_protection_profile_control_queries(queryset, control):
    """One zone protection profile of one appliance. PAN-ZON-002, -003, -004, -005, -006.

    FIVE CONTROLS REACH THIS HELPER and each asserts on a disjoint column of the same row, which
    is the ordinary many-controls-one-type case. PAN-ZON-008's first record names this model too
    and does NOT reach here: that control's target is `integrations.SecurityProfile`, a control
    has exactly one target model, and `ControlQuery.clean()` refuses a query on any other - so
    the zone-profile half of it is silent and the stage 8 artifact's `subjects_in_two_models`
    says so.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or ZONE_PROTECTION_PROFILE_MODEL,
    )


def evaluate_dos_policy_rule_control_queries(queryset, control):
    """One DoS Protection policy rule of one rulebase of one vsys. PAN-ZON-007.

    ONE CONTROL AND ONE OF ITS TWO RECORDS reach this helper. The other is discharged onto a
    question for a person - which services behind this firewall are business-critical - and owes
    no query at all, so nothing here is silent for want of a model: the half simply has no
    configurational form.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DOS_POLICY_RULE_MODEL,
    )


def evaluate_decryption_policy_rule_control_queries(queryset, control):
    """One ordered entry of one decryption rulebase of one vsys. PAN-DEC-002, -003, -005 to -008
    and -010.

    SEVEN CONTROLS REACH THIS HELPER, which is the ordinary many-controls-one-type case, and each
    asserts on a different column of the same row - the content criterion, the written reason, the
    address criterion, the exempt user population, the inverted match, the attached profile and the
    two log switches.

    PAN-DEC-001 and PAN-DEC-009 do NOT reach here. Their subject is the rulebase as a whole, and
    the state they report is that no rule does something - which has no row at this grain, because
    stage 4 measured the commonest state of this domain as no decryption rulebase at all.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DECRYPTION_POLICY_RULE_MODEL,
    )


def evaluate_decryption_rulebase_coverage_control_queries(queryset, control):
    """One enforcement point's decryption rulebase as a verdict over all of its rules.
    PAN-DEC-001 and PAN-DEC-009.

    PAN-DEC-009's SECOND assertion record names the per-rule model and does NOT reach here, and
    that is not a silence this helper causes: stage 5 discharges that record `not_in_configuration`
    - no configuration node anywhere on the firewall holds whether a published service's own
    certificate was imported with its private key - so it owes no query at either grain.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or DECRYPTION_RULEBASE_COVERAGE_MODEL,
    )


def evaluate_ssl_decryption_exclusion_control_queries(queryset, control):
    """One SSL decryption exclusion the organization added itself. PAN-DEC-004's first record.

    THE SECOND RECORD IS SILENT AND NOT ROUTED ELSEWHERE. It asserts over
    `integrations.SslDecryptionVendorExclusionOptOut`, a control has exactly one `target_model`,
    and `probe.relation_between` finds NO relation between the two models in either direction - so
    there is no walk by which one query could carry both halves. See the stage 8 artifact for
    `decryption-policy`, `subjects_in_two_models`.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SSL_DECRYPTION_EXCLUSION_MODEL,
    )


def evaluate_ssl_decryption_vendor_exclusion_optout_control_queries(queryset, control):
    """One appliance's departures from the vendor's SSL exclusion list.

    NO SHIPPED CONTROL REACHES THIS HELPER, the same recorded state
    `evaluate_lldp_global_control_queries` carries. It is registered so that the half of
    PAN-DEC-004 somebody may decide to split out reports the moment a control exists, rather than
    leaving a model and a normalizer nothing can read. The generator's docstring says why no estate
    can make that half fire today.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or SSL_DECRYPTION_VENDOR_EXCLUSION_OPTOUT_MODEL,
    )


def evaluate_log_server_target_control_queries(queryset, control):
    """One server entry of one log-settings server profile. PAN-LOG-002.

    EVERY QUERY THAT REACHES HERE CLAUSES ON `kind`, and nothing here enforces it. One table
    holds both the syslog and the e-mail kind, `transport` holds its UDP default on the e-mail
    kind too, and no shipped gate compares a query's clause list against the kind it is about.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or LOG_SERVER_TARGET_MODEL,
    )


def evaluate_vsys_log_forwarding_control_queries(queryset, control):
    """One virtual system's Log Forwarding availability, as a verdict. PAN-LOG-005."""
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or VSYS_LOG_FORWARDING_MODEL,
    )


def evaluate_vsys_rule_posture_control_queries(queryset, control):
    """One enforcement point's whole-policy verdicts. PAN-POL-007, -010, -017, -018, -019.

    EVERY QUERY THAT REACHES HERE CLAUSES ON `rules_collected`, and nothing here enforces it.
    False means no rulebase read has answered for the vsys, and without that clause a vsys nobody
    collected answers false to every existence verdict on the model and reports as missing every
    rule it was supposed to have - a full set of findings raised on an empty set of rows.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or VSYS_RULE_POSTURE_MODEL,
    )


def evaluate_policy_rule_settings_control_queries(queryset, control):
    """One appliance's device-wide policy-rule switches. PAN-POL-011, which ships INACTIVE.

    BOTH COLUMNS ARE NULLABLE BOOLEANS WHOSE NULL IS THE FIRING SIDE, so every control on this
    model is written as a NEGATED equality. That reaches a NULL because `compile_search_clause`
    negates a `pk__in` subquery - set complement over primary keys - rather than emitting a SQL
    `!=`, which would not.
    """
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or POLICY_RULE_SETTINGS_MODEL,
    )
