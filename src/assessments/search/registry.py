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
from assessments.search.authentication_sequence.compiler import (
    AUTHENTICATION_SEQUENCE_MODEL,
    FIELD_OPERATOR_REGISTRY as AUTHENTICATION_SEQUENCE_FIELD_OPERATOR_REGISTRY,
    compile_authentication_sequence_search_node,
)
from optivedge_integrations.integrations.models import (
    AdminUser,
    ServerProfile,
    AuthenticationProfile,
    AuthenticationSequence,
    Certificate,
    AuthenticationSettings,
    LoggingSettings,
    LoginBanner,
    ManagementTlsBinding,
    ManagementSshSettings,
    MasterKey,
    UpdateServerSettings,
    PasswordComplexityPolicy,
    PasswordProfile,
    SecurityProfile,
    CertificateProfile,
    InterfaceManagementProfile,
    SslTlsServiceProfile,
    ManagementInterface,
    SecurityRule,
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
}


def get_model_label(model_class):
    return f"{model_class._meta.app_label}.{model_class.__name__}"


def get_model_entry(model_name):
    entry = MODEL_REGISTRY.get(model_name)
    if entry is None:
        raise SearchSyntaxError(f"Unsupported search model: {model_name}.")
    return entry
