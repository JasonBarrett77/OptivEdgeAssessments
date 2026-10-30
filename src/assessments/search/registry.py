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
    NormalizationIssue,
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
