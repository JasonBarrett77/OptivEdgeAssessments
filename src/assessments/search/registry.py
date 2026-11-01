"""Canonical search model and field registry."""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.security_rules.compiler import (
    FIELD_OPERATOR_REGISTRY as SECURITY_RULE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.security_rules.compiler import (
    SECURITY_RULE_MODEL,
    compile_security_rule_search_node,
)
from assessments.search.management_interface.compiler import (
    FIELD_OPERATOR_REGISTRY as MANAGEMENT_INTERFACE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.management_interface.compiler import (
    MANAGEMENT_INTERFACE_MODEL,
    compile_management_interface_search_node,
)
from assessments.search.interface_management_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as INTERFACE_MANAGEMENT_PROFILE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.interface_management_profile.compiler import (
    INTERFACE_MANAGEMENT_PROFILE_MODEL,
    compile_interface_management_profile_search_node,
)
from assessments.search.ssl_tls_service_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as SSL_TLS_SERVICE_PROFILE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.ssl_tls_service_profile.compiler import (
    SSL_TLS_SERVICE_PROFILE_MODEL,
    compile_ssl_tls_service_profile_search_node,
)
from assessments.search.certificate.compiler import (
    FIELD_OPERATOR_REGISTRY as CERTIFICATE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.certificate.compiler import (
    CERTIFICATE_MODEL,
    compile_certificate_search_node,
)
from assessments.search.authentication_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as AUTHENTICATION_PROFILE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.authentication_profile.compiler import (
    AUTHENTICATION_PROFILE_MODEL,
    compile_authentication_profile_search_node,
)
from assessments.search.server_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as SERVER_PROFILE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.server_profile.compiler import (
    SERVER_PROFILE_MODEL,
    compile_server_profile_search_node,
)
from assessments.search.admin_user.compiler import (
    FIELD_OPERATOR_REGISTRY as ADMIN_USER_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.admin_user.compiler import (
    ADMIN_USER_MODEL,
    compile_admin_user_search_node,
)
from assessments.search.master_key.compiler import (
    FIELD_OPERATOR_REGISTRY as MASTER_KEY_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.master_key.compiler import (
    MASTER_KEY_MODEL,
    compile_master_key_search_node,
)
from assessments.search.wildfire_settings.compiler import (
    FIELD_OPERATOR_REGISTRY as WILDFIRE_SETTINGS_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.wildfire_settings.compiler import (
    WILDFIRE_SETTINGS_MODEL,
    compile_wildfire_settings_search_node,
)
from assessments.search.update_server_settings.compiler import (
    FIELD_OPERATOR_REGISTRY as UPDATE_SERVER_SETTINGS_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.update_server_settings.compiler import (
    UPDATE_SERVER_SETTINGS_MODEL,
    compile_update_server_settings_search_node,
)
from assessments.search.logging_settings.compiler import (
    FIELD_OPERATOR_REGISTRY as LOGGING_SETTINGS_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.logging_settings.compiler import (
    LOGGING_SETTINGS_MODEL,
    compile_logging_settings_search_node,
)
from assessments.search.management_tls.compiler import (
    FIELD_OPERATOR_REGISTRY as MANAGEMENT_TLS_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.management_tls.compiler import (
    MANAGEMENT_TLS_MODEL,
    compile_management_tls_search_node,
)
from assessments.search.management_ssh.compiler import (
    FIELD_OPERATOR_REGISTRY as MANAGEMENT_SSH_FIELD_OPERATOR_REGISTRY,
    MANAGEMENT_SSH_MODEL,
    compile_management_ssh_search_node,
)
from assessments.search.ntp_settings.compiler import (
    FIELD_OPERATOR_REGISTRY as NTP_SETTINGS_FIELD_OPERATOR_REGISTRY,
    NTP_SETTINGS_MODEL,
    compile_ntp_settings_search_node,
)
from assessments.search.snmp_settings.compiler import (
    FIELD_OPERATOR_REGISTRY as SNMP_SETTINGS_FIELD_OPERATOR_REGISTRY,
    SNMP_SETTINGS_MODEL,
    compile_snmp_settings_search_node,
)
from assessments.search.system_identity.compiler import (
    FIELD_OPERATOR_REGISTRY as SYSTEM_IDENTITY_FIELD_OPERATOR_REGISTRY,
    SYSTEM_IDENTITY_MODEL,
    compile_system_identity_search_node,
)
from assessments.search.address_object.compiler import (
    FIELD_OPERATOR_REGISTRY as ADDRESS_OBJECT_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.address_object.compiler import (
    ADDRESS_OBJECT_MODEL,
    compile_address_object_search_node,
)
from assessments.search.login_banner.compiler import (
    FIELD_OPERATOR_REGISTRY as LOGIN_BANNER_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.login_banner.compiler import (
    LOGIN_BANNER_MODEL,
    compile_login_banner_search_node,
)
from assessments.search.authentication_settings.compiler import (
    FIELD_OPERATOR_REGISTRY as AUTHENTICATION_SETTINGS_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.authentication_settings.compiler import (
    AUTHENTICATION_SETTINGS_MODEL,
    compile_authentication_settings_search_node,
)
from assessments.search.password_complexity.compiler import (
    FIELD_OPERATOR_REGISTRY as PASSWORD_COMPLEXITY_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.password_complexity.compiler import (
    PASSWORD_COMPLEXITY_MODEL,
    compile_password_complexity_search_node,
)
from assessments.search.password_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as PASSWORD_PROFILE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.password_profile.compiler import (
    PASSWORD_PROFILE_MODEL,
    compile_password_profile_search_node,
)
from assessments.search.security_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as SECURITY_PROFILE_FIELD_OPERATOR_REGISTRY,
    SECURITY_PROFILE_MODEL,
    compile_security_profile_search_node,
)
from assessments.search.certificate_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as CERTIFICATE_PROFILE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.certificate_profile.compiler import (
    CERTIFICATE_PROFILE_MODEL,
    compile_certificate_profile_search_node,
)
from assessments.search.normalization_issue.compiler import (
    FIELD_OPERATOR_REGISTRY as NORMALIZATION_ISSUE_FIELD_OPERATOR_REGISTRY,
    NORMALIZATION_ISSUE_MODEL,
    compile_normalization_issue_search_node,
)
from assessments.search.ike_crypto_profile.compiler import (
    FIELD_OPERATOR_REGISTRY as IKE_CRYPTO_PROFILE_FIELD_OPERATOR_REGISTRY,
    IKE_CRYPTO_PROFILE_MODEL,
    compile_ike_crypto_profile_search_node,
)
from assessments.search.ike_gateway.compiler import (
    FIELD_OPERATOR_REGISTRY as IKE_GATEWAY_FIELD_OPERATOR_REGISTRY,
    IKE_GATEWAY_MODEL,
    compile_ike_gateway_search_node,
)
from assessments.search.high_availability_config.compiler import (
    FIELD_OPERATOR_REGISTRY as HIGH_AVAILABILITY_CONFIG_FIELD_OPERATOR_REGISTRY,
    HIGH_AVAILABILITY_CONFIG_MODEL,
    compile_high_availability_config_search_node,
)
from assessments.search.panorama_registration.compiler import (
    FIELD_OPERATOR_REGISTRY as PANORAMA_REGISTRATION_FIELD_OPERATOR_REGISTRY,
    PANORAMA_REGISTRATION_MODEL,
    compile_panorama_registration_search_node,
)
from assessments.search.authentication_sequence.compiler import (
    AUTHENTICATION_SEQUENCE_MODEL,
    FIELD_OPERATOR_REGISTRY as AUTHENTICATION_SEQUENCE_FIELD_OPERATOR_REGISTRY,
    compile_authentication_sequence_search_node,
)
# The six network-hardening subjects. PAN-NET-001 to 007.
from assessments.search.interface.compiler import (
    FIELD_OPERATOR_REGISTRY as INTERFACE_FIELD_OPERATOR_REGISTRY,
    INTERFACE_MODEL,
    compile_interface_search_node,
)
from assessments.search.session_settings.compiler import (
    FIELD_OPERATOR_REGISTRY as SESSION_SETTINGS_FIELD_OPERATOR_REGISTRY,
    SESSION_SETTINGS_MODEL,
    compile_session_settings_search_node,
)
from assessments.search.lldp_global.compiler import (
    FIELD_OPERATOR_REGISTRY as LLDP_GLOBAL_FIELD_OPERATOR_REGISTRY,
    LLDP_GLOBAL_MODEL,
    compile_lldp_global_search_node,
)
from assessments.search.dhcp_interface_config.compiler import (
    FIELD_OPERATOR_REGISTRY as DHCP_INTERFACE_CONFIG_FIELD_OPERATOR_REGISTRY,
    DHCP_INTERFACE_CONFIG_MODEL,
    compile_dhcp_interface_config_search_node,
)
from assessments.search.tunnel_inspection.compiler import (
    FIELD_OPERATOR_REGISTRY as TUNNEL_INSPECTION_FIELD_OPERATOR_REGISTRY,
    TUNNEL_INSPECTION_MODEL,
    compile_tunnel_inspection_search_node,
)
from assessments.search.routing_adjacency.compiler import (
    FIELD_OPERATOR_REGISTRY as ROUTING_ADJACENCY_FIELD_OPERATOR_REGISTRY,
    ROUTING_ADJACENCY_MODEL,
    compile_routing_adjacency_search_node,
)
from optivedge_integrations.integrations.models import (
    AddressObject,
    HighAvailabilityConfig,
    PanoramaRegistration,
)
from assessments.search.sanctioned_application_marking.compiler import (
    FIELD_OPERATOR_REGISTRY as SANCTIONED_APPLICATION_MARKING_FIELD_OPERATOR_REGISTRY,
    SANCTIONED_APPLICATION_MARKING_MODEL,
    compile_sanctioned_application_marking_search_node,
)
from assessments.search.saas_url_filtering_posture.compiler import (
    FIELD_OPERATOR_REGISTRY as SAAS_URL_FILTERING_POSTURE_FIELD_OPERATOR_REGISTRY,
    SAAS_URL_FILTERING_POSTURE_MODEL,
    compile_saas_url_filtering_posture_search_node,
)
from assessments.search.saas_application_policy_posture.compiler import (
    FIELD_OPERATOR_REGISTRY as SAAS_APPLICATION_POLICY_POSTURE_FIELD_OPERATOR_REGISTRY,
    SAAS_APPLICATION_POLICY_POSTURE_MODEL,
    compile_saas_application_policy_posture_search_node,
)
from assessments.search.cloud_app_engine_setting.compiler import (
    FIELD_OPERATOR_REGISTRY as CLOUD_APP_ENGINE_SETTING_FIELD_OPERATOR_REGISTRY,
    CLOUD_APP_ENGINE_SETTING_MODEL,
    compile_cloud_app_engine_setting_search_node,
)
from assessments.search.device_identification.compiler import (
    FIELD_OPERATOR_REGISTRY as DEVICE_IDENTIFICATION_FIELD_OPERATOR_REGISTRY,
    DEVICE_IDENTIFICATION_MODEL,
    compile_device_identification_search_node,
)
from assessments.search.zone.compiler import (
    FIELD_OPERATOR_REGISTRY as ZONE_FIELD_OPERATOR_REGISTRY,
    ZONE_MODEL,
    compile_zone_search_node,
)
from assessments.search.rulebase_device_match.compiler import (
    FIELD_OPERATOR_REGISTRY as RULEBASE_DEVICE_MATCH_FIELD_OPERATOR_REGISTRY,
    RULEBASE_DEVICE_MATCH_MODEL,
    compile_rulebase_device_match_search_node,
)
from assessments.search.data_filtering_posture.compiler import (
    FIELD_OPERATOR_REGISTRY as DATA_FILTERING_POSTURE_FIELD_OPERATOR_REGISTRY,
    DATA_FILTERING_POSTURE_MODEL,
    compile_data_filtering_posture_search_node,
)
from assessments.search.globalprotect_portal.compiler import (
    FIELD_OPERATOR_REGISTRY as GLOBALPROTECT_PORTAL_FIELD_OPERATOR_REGISTRY,
    GLOBALPROTECT_PORTAL_MODEL,
    compile_globalprotect_portal_search_node,
)
from assessments.search.globalprotect_portal_client_auth.compiler import (
    FIELD_OPERATOR_REGISTRY as GLOBALPROTECT_PORTAL_CLIENT_AUTH_FIELD_OPERATOR_REGISTRY,
    GLOBALPROTECT_PORTAL_CLIENT_AUTH_MODEL,
    compile_globalprotect_portal_client_auth_search_node,
)
from assessments.search.globalprotect_enforcement_point.compiler import (
    FIELD_OPERATOR_REGISTRY as GLOBALPROTECT_ENFORCEMENT_POINT_FIELD_OPERATOR_REGISTRY,
    GLOBALPROTECT_ENFORCEMENT_POINT_MODEL,
    compile_globalprotect_enforcement_point_search_node,
)
from assessments.search.firewall_content_streams.compiler import (
    FIELD_OPERATOR_REGISTRY as FIREWALL_CONTENT_STREAMS_FIELD_OPERATOR_REGISTRY,
    FIREWALL_CONTENT_STREAMS_MODEL,
    compile_firewall_content_streams_search_node,
)
from assessments.search.content_update_schedule.compiler import (
    FIELD_OPERATOR_REGISTRY as CONTENT_UPDATE_SCHEDULE_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.content_update_schedule.compiler import (
    CONTENT_UPDATE_SCHEDULE_MODEL,
    compile_content_update_schedule_search_node,
)
from assessments.search.custom_url_category.compiler import (
    FIELD_OPERATOR_REGISTRY as CUSTOM_URL_CATEGORY_FIELD_OPERATOR_REGISTRY,
)
from assessments.search.custom_url_category.compiler import (
    CUSTOM_URL_CATEGORY_MODEL,
    compile_custom_url_category_search_node,
)
from assessments.search.licence_inventory.compiler import (
    FIELD_OPERATOR_REGISTRY as LICENCE_INVENTORY_FIELD_OPERATOR_REGISTRY,
    LICENCE_INVENTORY_MODEL,
    compile_licence_inventory_search_node,
)
from assessments.search.log_alarm_settings.compiler import (
    FIELD_OPERATOR_REGISTRY as LOG_ALARM_SETTINGS_FIELD_OPERATOR_REGISTRY,
    LOG_ALARM_SETTINGS_MODEL,
    compile_log_alarm_settings_search_node,
)
from optivedge_integrations.integrations.models import (
    AddressObject,
    CloudAppEngineSetting,
    DeviceIdentificationState,
    RulebaseDeviceMatchVerdict,
    DataFilteringPosture,
    GlobalProtectPortal,
    GlobalProtectPortalClientAuthRow,
    GlobalProtectEnforcementPoint,
    FirewallContentStreams,
    LicenceInventory,
    LogAlarmSettings,
    ContentUpdateSchedule,
    Zone,
    NormalizationIssue,
    SaasApplicationPolicyPosture,
    SaasUrlFilteringPosture,
    SanctionedApplicationMarking,
    AdminUser,
    ServerProfile,
    AuthenticationProfile,
    AuthenticationSequence,
    Certificate,
    AuthenticationSettings,
    LoggingSettings,
    LoginBanner,
    NtpSettings,
    SnmpSettings,
    SystemIdentity,
    ManagementTlsBinding,
    ManagementSshSettings,
    MasterKey,
    UpdateServerSettings,
    WildfireSettings,
    PasswordComplexityPolicy,
    PasswordProfile,
    SecurityProfile,
    CertificateProfile,
    InterfaceManagementProfile,
    IkeCryptoProfile,
    IkeGateway,
    SslTlsServiceProfile,
    ManagementInterface,
    SecurityRule,
    Interface,
    PanOsSessionSettings,
    PanOsLldpGlobalSettings,
    PanOsDhcpInterfaceConfig,
    PanOsTunnelInspectionCoverage,
    PanOsRoutingAdjacency,
    CustomUrlCategory,
)


MODEL_REGISTRY = {
    SECURITY_RULE_MODEL: {
        "model_class": SecurityRule,
        "field_operators": SECURITY_RULE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_security_rule_search_node,
    },
    MANAGEMENT_INTERFACE_MODEL: {
        "model_class": ManagementInterface,
        "field_operators": MANAGEMENT_INTERFACE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_management_interface_search_node,
    },
    INTERFACE_MANAGEMENT_PROFILE_MODEL: {
        "model_class": InterfaceManagementProfile,
        "field_operators": INTERFACE_MANAGEMENT_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_interface_management_profile_search_node,
    },
    SSL_TLS_SERVICE_PROFILE_MODEL: {
        "model_class": SslTlsServiceProfile,
        "field_operators": SSL_TLS_SERVICE_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_ssl_tls_service_profile_search_node,
    },
    CERTIFICATE_PROFILE_MODEL: {
        "model_class": CertificateProfile,
        "field_operators": CERTIFICATE_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_certificate_profile_search_node,
    },
    AUTHENTICATION_PROFILE_MODEL: {
        "model_class": AuthenticationProfile,
        "field_operators": AUTHENTICATION_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_authentication_profile_search_node,
    },
    AUTHENTICATION_SEQUENCE_MODEL: {
        "model_class": AuthenticationSequence,
        "field_operators": AUTHENTICATION_SEQUENCE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_authentication_sequence_search_node,
    },
    SERVER_PROFILE_MODEL: {
        "model_class": ServerProfile,
        "field_operators": SERVER_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_server_profile_search_node,
    },
    ADMIN_USER_MODEL: {
        "model_class": AdminUser,
        "field_operators": ADMIN_USER_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_admin_user_search_node,
    },
    MASTER_KEY_MODEL: {
        "model_class": MasterKey,
        "field_operators": MASTER_KEY_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_master_key_search_node,
    },
    WILDFIRE_SETTINGS_MODEL: {
        "model_class": WildfireSettings,
        "field_operators": WILDFIRE_SETTINGS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_wildfire_settings_search_node,
    },
    UPDATE_SERVER_SETTINGS_MODEL: {
        "model_class": UpdateServerSettings,
        "field_operators": UPDATE_SERVER_SETTINGS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_update_server_settings_search_node,
    },
    LOGGING_SETTINGS_MODEL: {
        "model_class": LoggingSettings,
        "field_operators": LOGGING_SETTINGS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_logging_settings_search_node,
    },
    MANAGEMENT_TLS_MODEL: {
        "model_class": ManagementTlsBinding,
        "field_operators": MANAGEMENT_TLS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_management_tls_search_node,
    },
    MANAGEMENT_SSH_MODEL: {
        "model_class": ManagementSshSettings,
        "field_operators": MANAGEMENT_SSH_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_management_ssh_search_node,
    },
    NTP_SETTINGS_MODEL: {
        "model_class": NtpSettings,
        "field_operators": NTP_SETTINGS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_ntp_settings_search_node,
    },
    SNMP_SETTINGS_MODEL: {
        "model_class": SnmpSettings,
        "field_operators": SNMP_SETTINGS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_snmp_settings_search_node,
    },
    SYSTEM_IDENTITY_MODEL: {
        "model_class": SystemIdentity,
        "field_operators": SYSTEM_IDENTITY_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_system_identity_search_node,
    },
    ADDRESS_OBJECT_MODEL: {
        "model_class": AddressObject,
        "field_operators": ADDRESS_OBJECT_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_address_object_search_node,
    },
    LOGIN_BANNER_MODEL: {
        "model_class": LoginBanner,
        "field_operators": LOGIN_BANNER_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_login_banner_search_node,
    },
    AUTHENTICATION_SETTINGS_MODEL: {
        "model_class": AuthenticationSettings,
        "field_operators": AUTHENTICATION_SETTINGS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_authentication_settings_search_node,
    },
    PASSWORD_COMPLEXITY_MODEL: {
        "model_class": PasswordComplexityPolicy,
        "field_operators": PASSWORD_COMPLEXITY_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_password_complexity_search_node,
    },
    PASSWORD_PROFILE_MODEL: {
        "model_class": PasswordProfile,
        "field_operators": PASSWORD_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_password_profile_search_node,
    },
    SECURITY_PROFILE_MODEL: {
        "model_class": SecurityProfile,
        "field_operators": SECURITY_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_security_profile_search_node,
    },
    CERTIFICATE_MODEL: {
        "model_class": Certificate,
        "field_operators": CERTIFICATE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_certificate_search_node,
    },
    IKE_CRYPTO_PROFILE_MODEL: {
        "model_class": IkeCryptoProfile,
        "field_operators": IKE_CRYPTO_PROFILE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_ike_crypto_profile_search_node,
    },
    IKE_GATEWAY_MODEL: {
        "model_class": IkeGateway,
        "field_operators": IKE_GATEWAY_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_ike_gateway_search_node,
    },
    # Device-wide management-plane settings: one row per appliance, no vsys axis and no entry
    # name. The HA row is NOT expected to agree with its pair member's; the registration row is.
    HIGH_AVAILABILITY_CONFIG_MODEL: {
        "model_class": HighAvailabilityConfig,
        "field_operators": HIGH_AVAILABILITY_CONFIG_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_high_availability_config_search_node,
    },
    PANORAMA_REGISTRATION_MODEL: {
        "model_class": PanoramaRegistration,
        "field_operators": PANORAMA_REGISTRATION_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_panorama_registration_search_node,
    },
    # Network hardening. Six subjects, four grains: a port, a DHCP configuration attached to a
    # port, two device-wide singleton nodes, a verdict over one enforcement point's tunnel
    # rulebase, and one dynamic routing adjacency.
    INTERFACE_MODEL: {
        "model_class": Interface,
        "field_operators": INTERFACE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_interface_search_node,
    },
    SESSION_SETTINGS_MODEL: {
        "model_class": PanOsSessionSettings,
        "field_operators": SESSION_SETTINGS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_session_settings_search_node,
    },
    # Registered with no shipped control over it: PAN-NET-003's assertions name two models and
    # one catalogue control cannot hold both. See that compiler's docstring.
    LLDP_GLOBAL_MODEL: {
        "model_class": PanOsLldpGlobalSettings,
        "field_operators": LLDP_GLOBAL_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_lldp_global_search_node,
    },
    DHCP_INTERFACE_CONFIG_MODEL: {
        "model_class": PanOsDhcpInterfaceConfig,
        "field_operators": DHCP_INTERFACE_CONFIG_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_dhcp_interface_config_search_node,
    },
    TUNNEL_INSPECTION_MODEL: {
        "model_class": PanOsTunnelInspectionCoverage,
        "field_operators": TUNNEL_INSPECTION_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_tunnel_inspection_search_node,
    },
    ROUTING_ADJACENCY_MODEL: {
        "model_class": PanOsRoutingAdjacency,
        "field_operators": ROUTING_ADJACENCY_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_routing_adjacency_search_node,
    },
    # The four `saas-security` subjects. THREE OF THEM ARE VERDICTS OVER A COLLECTION rather than
    # entries of one: the commonest state of this domain is NO ENTRY AT ALL - no application-tag
    # container, no header insertion on any profile at any scope, no application filter, no rule
    # naming a function child application - and a per-entry grain has no row for that, so a
    # predicate could not compare against it. Every column of all three defaults to its FIRING
    # value for the same reason.
    SANCTIONED_APPLICATION_MARKING_MODEL: {
        "model_class": SanctionedApplicationMarking,
        "field_operators": SANCTIONED_APPLICATION_MARKING_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_sanctioned_application_marking_search_node,
    },
    SAAS_URL_FILTERING_POSTURE_MODEL: {
        "model_class": SaasUrlFilteringPosture,
        "field_operators": SAAS_URL_FILTERING_POSTURE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_saas_url_filtering_posture_search_node,
    },
    SAAS_APPLICATION_POLICY_POSTURE_MODEL: {
        "model_class": SaasApplicationPolicyPosture,
        "field_operators": SAAS_APPLICATION_POLICY_POSTURE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_saas_application_policy_posture_search_node,
    },
    # The fourth is a device-wide singleton and takes an appliance directly.
    CLOUD_APP_ENGINE_SETTING_MODEL: {
        "model_class": CloudAppEngineSetting,
        "field_operators": CLOUD_APP_ENGINE_SETTING_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_cloud_app_engine_setting_search_node,
    },
    # `device-id-iot`. Three models and three grains: the appliance's own service state, the
    # zone, and a verdict over an enforcement point's whole rule set. `Zone` had shipped for
    # months with no compiler at all, because no control had ever asserted over a zone.
    DEVICE_IDENTIFICATION_MODEL: {
        "model_class": DeviceIdentificationState,
        "field_operators": DEVICE_IDENTIFICATION_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_device_identification_search_node,
    },
    ZONE_MODEL: {
        "model_class": Zone,
        "field_operators": ZONE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_zone_search_node,
    },
    RULEBASE_DEVICE_MATCH_MODEL: {
        "model_class": RulebaseDeviceMatchVerdict,
        "field_operators": RULEBASE_DEVICE_MATCH_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_rulebase_device_match_search_node,
    },
    # `file-data-filtering`. ONE new model of the domain's two: `SecurityProfile` already had a
    # compiler here - the biggest in the tree - and this domain only added fields to it. The
    # posture is a verdict per enforcement point, like the three SaaS entries above, because the
    # commonest failing state is no data-filtering profile anywhere beneath the point.
    DATA_FILTERING_POSTURE_MODEL: {
        "model_class": DataFilteringPosture,
        "field_operators": DATA_FILTERING_POSTURE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_data_filtering_posture_search_node,
    },
    # `globalprotect-portal`. THREE entries for three models, and none of the three had a type, a
    # compiler or a finding model before this change - so nothing here reuses and nothing here is
    # a second surface over a model that already had one.
    #
    # THE THREE ARE A PARENT, ITS CHILD ROW AND THE VSYS ABOVE BOTH, which is why they are three
    # and not one: `test_every_control_type_targets_a_registered_model` iterates `ControlType`,
    # reads `_CONTROL_TYPE_TARGET_MODEL` and asserts the target is in THIS map, so a type with a
    # map entry and no compiler fails a test whose message names the other map.
    GLOBALPROTECT_PORTAL_MODEL: {
        "model_class": GlobalProtectPortal,
        "field_operators": GLOBALPROTECT_PORTAL_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_globalprotect_portal_search_node,
    },
    # The child row, keyed by the endpoint CLASS it serves. Its own grain and not the portal's:
    # one portal can demand both factors of one class and neither of another, so a portal-grain
    # query cannot say which class is weak - the to-many downward walk standing ruling 6 refuses.
    GLOBALPROTECT_PORTAL_CLIENT_AUTH_MODEL: {
        "model_class": GlobalProtectPortalClientAuthRow,
        "field_operators": GLOBALPROTECT_PORTAL_CLIENT_AUTH_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_globalprotect_portal_client_auth_search_node,
    },
    # The vsys as a verdict over its GlobalProtect objects as a whole, the same shape as the three
    # SaaS postures and `data_filtering_posture` above: the gap it reports is sometimes the ABSENCE
    # of a portal or of a published application, and nothing that does not exist carries a row.
    GLOBALPROTECT_ENFORCEMENT_POINT_MODEL: {
        "model_class": GlobalProtectEnforcementPoint,
        "field_operators": GLOBALPROTECT_ENFORCEMENT_POINT_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_globalprotect_enforcement_point_search_node,
    },
    # `platform-lifecycle`. THREE entries for three models, none of which had a type, a compiler
    # or a finding model before this change - so nothing here reuses and nothing here is a second
    # surface over a model that already had one.
    #
    # ALL THREE ARE DEVICE-WIDE SINGLETONS: one row per appliance, no vsys axis, no entry name.
    # They are three and not one because `_CONTROL_TYPE_TARGET_MODEL` is one-to-one and
    # `test_every_control_type_targets_a_registered_model` iterates `ControlType`, reads that map
    # and asserts the target is in THIS one - so a type with a map entry and no compiler fails a
    # test whose message names the other map.
    FIREWALL_CONTENT_STREAMS_MODEL: {
        "model_class": FirewallContentStreams,
        "field_operators": FIREWALL_CONTENT_STREAMS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_firewall_content_streams_search_node,
    },
    # A CONCLUSION ABOUT the licence table rather than one licence, which is what lets a control
    # report an entitlement that is MISSING. `LicenceEntitlement` holds the per-licence rows and
    # gets no entry here: no assertion record of this domain names that subject.
    LICENCE_INVENTORY_MODEL: {
        "model_class": LicenceInventory,
        "field_operators": LICENCE_INVENTORY_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_licence_inventory_search_node,
    },
    # One singleton configuration node, as one ordered verdict over its six leaves. The ordering
    # is stage 3's and is not expressible as a conjunction of them.
    LOG_ALARM_SETTINGS_MODEL: {
        "model_class": LogAlarmSettings,
        "field_operators": LOG_ALARM_SETTINGS_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_log_alarm_settings_search_node,
    },
    # `updates`. ONE entry for FOUR controls, because all five content types live on one row
    # keyed by the appliance: PAN-UPD-001 grades antivirus, -002 Applications-and-Threats, -004
    # WildFire and -005 the two GlobalProtect content types. `ContentDeploymentSchedule` - the
    # management station's own deployment schedule - gets NO entry: the one record naming it is
    # discharged `not_in_configuration` on a scope ruling, so it owes no query and a surface over
    # it could never be referenced by a finding.
    CONTENT_UPDATE_SCHEDULE_MODEL: {
        "model_class": ContentUpdateSchedule,
        "field_operators": CONTENT_UPDATE_SCHEDULE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_content_update_schedule_search_node,
    },
    # `url-filtering`. ONE entry for ONE control - PAN-URL-006's category half. The domain's
    # other five controls get NO entry here: they query `integrations.SecurityProfile`, whose
    # surface is registered above and which they extend with sixteen new fields rather than a
    # new package.
    CUSTOM_URL_CATEGORY_MODEL: {
        "model_class": CustomUrlCategory,
        "field_operators": CUSTOM_URL_CATEGORY_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_custom_url_category_search_node,
    },
    # Our own record of what could not be normalized. The only entry here whose model is not
    # device configuration - see the compiler's module docstring.
    NORMALIZATION_ISSUE_MODEL: {
        "model_class": NormalizationIssue,
        "field_operators": NORMALIZATION_ISSUE_FIELD_OPERATOR_REGISTRY,
        "compiler": compile_normalization_issue_search_node,
    },
}


def get_model_label(model_class):
    return f"{model_class._meta.app_label}.{model_class.__name__}"


def get_model_entry(model_name):
    entry = MODEL_REGISTRY.get(model_name)
    if entry is None:
        raise SearchSyntaxError(f"Unsupported search model: {model_name}.")
    return entry
