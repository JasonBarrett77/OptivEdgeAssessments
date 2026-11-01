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
PASSWORD_PROFILE_MODEL = "integrations.PasswordProfile"
SECURITY_PROFILE_MODEL = "integrations.SecurityProfile"
ADMIN_USER_MODEL = "integrations.AdminUser"
SERVER_PROFILE_MODEL = "integrations.ServerProfile"
NTP_SETTINGS_MODEL = "integrations.NtpSettings"
SNMP_SETTINGS_MODEL = "integrations.SnmpSettings"
SYSTEM_IDENTITY_MODEL = "integrations.SystemIdentity"
IKE_CRYPTO_PROFILE_MODEL = "integrations.IkeCryptoProfile"
IKE_GATEWAY_MODEL = "integrations.IkeGateway"
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


def evaluate_rulebase_device_match_control_queries(queryset, control):
    return evaluate_queryset_control_queries(
        queryset,
        control,
        model_name=control.target_model or RULEBASE_DEVICE_MATCH_MODEL,
    )
