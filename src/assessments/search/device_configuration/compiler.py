"""Model-specific canonical search compilation for device configuration profiles."""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_boolean import (
    SUPPORTED_OPERATORS as BOOLEAN_OPERATORS,
    compile_scalar_boolean_clause,
)
from assessments.search.device_configuration.fields.scalar_integer import (
    SUPPORTED_OPERATORS as INTEGER_OPERATORS,
    compile_scalar_integer_clause,
)
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
    compile_scalar_text_clause,
)


DEVICE_CONFIGURATION_MODEL = "integrations.DeviceConfigurationProfile"


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        return compile_scalar_boolean_clause(
            clause,
            field_name=field_name,
            lookup_field=lookup_field,
        )

    compiler.SUPPORTED_OPERATORS = BOOLEAN_OPERATORS
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        return compile_scalar_integer_clause(
            clause,
            field_name=field_name,
            lookup_field=lookup_field,
        )

    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        return compile_scalar_text_clause(
            clause,
            field_name=field_name,
            lookup_field=lookup_field,
        )

    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


FIELD_COMPILERS = {
    "appliance_group": build_text_compiler("appliance_group", "appliance_group__name"),
    "ha_enabled": build_boolean_compiler("ha_enabled", "ha_enabled"),
    "ha_link_monitoring_enabled": build_boolean_compiler(
        "ha_link_monitoring_enabled",
        "ha_link_monitoring_enabled",
    ),
    "ha_required": build_boolean_compiler("ha_required", "ha_required"),
    "ha_state_sync_enabled": build_boolean_compiler(
        "ha_state_sync_enabled",
        "ha_state_sync_enabled",
    ),
    "ack_login_banner": build_boolean_compiler("ack_login_banner", "ack_login_banner"),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "log_on_high_dp_load": build_boolean_compiler("log_on_high_dp_load", "log_on_high_dp_load"),
    "idle_timeout_minutes": build_integer_compiler("idle_timeout_minutes", "idle_timeout_minutes"),
    "login_banner": build_text_compiler("login_banner", "login_banner"),
    "management_station": build_text_compiler("management_station", "management_station__hostname"),
    "ntp_primary_server": build_text_compiler("ntp_primary_server", "ntp_primary_server"),
    "ntp_secondary_server": build_text_compiler("ntp_secondary_server", "ntp_secondary_server"),
    "permitted_ip_count": build_integer_compiler("permitted_ip_count", "permitted_ip_count"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "server_verification_enabled": build_boolean_compiler(
        "server_verification_enabled", "server_verification_enabled"),
    # PAN-MGT-010. The binding is a name; the assertion lives in the profile it resolves to,
    # so the resolved floor is a separate field from the name and either can be blank on its
    # own. Blank name means nothing is bound. Blank floor with a name present means the
    # binding did not resolve, or resolved to a profile carrying no protocol-settings - and
    # those are reported, never treated as satisfied.
    "ssl_tls_service_profile_name": build_text_compiler(
        "ssl_tls_service_profile_name", "ssl_tls_service_profile_name"),
    "ssl_tls_profile_scope": build_text_compiler(
        "ssl_tls_profile_scope", "ssl_tls_profile_scope"),
    "ssl_tls_min_version": build_text_compiler("ssl_tls_min_version", "ssl_tls_min_version"),
    "ssl_tls_max_version": build_text_compiler("ssl_tls_max_version", "ssl_tls_max_version"),
    "ssl_tls_certificate_name": build_text_compiler(
        "ssl_tls_certificate_name", "ssl_tls_certificate_name"),
    # PAN-CRT-006. A classified value, not a boolean - see the model. Blank is a fourth state
    # meaning nothing is bound, and like `undetermined` it is not `ca_issued`, so a control
    # written as "fires unless CA-issued" catches both without enumerating them.
    "ssl_tls_certificate_trust": build_text_compiler(
        "ssl_tls_certificate_trust", "ssl_tls_certificate_trust"),
    "ssl_tls_certificate_issuer": build_text_compiler(
        "ssl_tls_certificate_issuer", "ssl_tls_certificate_issuer"),
    "ssl_tls_certificate_scope": build_text_compiler(
        "ssl_tls_certificate_scope", "ssl_tls_certificate_scope"),
    # PAN-CRT-007. Classified rather than boolean for the reason the certificate trust field
    # is: UNDETERMINED means the properties were never collected, which is neither a pass nor
    # a fail, and a nullable boolean invites a query that reads it as one.
    "master_key_state": build_text_compiler("master_key_state", "master_key_state"),
    "master_key_on_hsm": build_boolean_compiler("master_key_on_hsm", "master_key_on_hsm"),
    # PAN-AUTH-001 through 013. Three directions live here, which is why they are not
    # generated: most want AT LEAST a value, two want AT MOST, and expiration_period is
    # bounded at both ends - zero never expires and a long period is a weak one.
    "password_complexity_enabled": build_boolean_compiler(
        "password_complexity_enabled", "password_complexity_enabled"),
    "password_minimum_length": build_integer_compiler(
        "password_minimum_length", "password_minimum_length"),
    "password_minimum_uppercase": build_integer_compiler(
        "password_minimum_uppercase", "password_minimum_uppercase"),
    "password_minimum_lowercase": build_integer_compiler(
        "password_minimum_lowercase", "password_minimum_lowercase"),
    "password_minimum_numeric": build_integer_compiler(
        "password_minimum_numeric", "password_minimum_numeric"),
    "password_minimum_special": build_integer_compiler(
        "password_minimum_special", "password_minimum_special"),
    "password_block_username_inclusion": build_boolean_compiler(
        "password_block_username_inclusion", "password_block_username_inclusion"),
    "password_new_differs_by_characters": build_integer_compiler(
        "password_new_differs_by_characters", "password_new_differs_by_characters"),
    "password_history_count": build_integer_compiler(
        "password_history_count", "password_history_count"),
    "password_expiration_period": build_integer_compiler(
        "password_expiration_period", "password_expiration_period"),
    "password_expiration_warning_period": build_integer_compiler(
        "password_expiration_warning_period", "password_expiration_warning_period"),
    "admin_lockout_failed_attempts": build_integer_compiler(
        "admin_lockout_failed_attempts", "admin_lockout_failed_attempts"),
    "admin_lockout_time_minutes": build_integer_compiler(
        "admin_lockout_time_minutes", "admin_lockout_time_minutes"),
    "api_key_lifetime_minutes": build_integer_compiler(
        "api_key_lifetime_minutes", "api_key_lifetime_minutes"),
    "password_post_expiration_admin_login_count": build_integer_compiler(
        "password_post_expiration_admin_login_count",
        "password_post_expiration_admin_login_count"),
    "password_post_expiration_grace_period": build_integer_compiler(
        "password_post_expiration_grace_period", "password_post_expiration_grace_period"),
}


FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_device_configuration_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled_clauses = [compile_device_configuration_search_node(clause) for clause in group["clauses"]]
    predicate = compiled_clauses[0]
    for compiled_clause in compiled_clauses[1:]:
        if group["operator"] == "and":
            predicate &= compiled_clause
        else:
            predicate |= compiled_clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    subquery = compiler(clause)
    predicate = Q(pk__in=Subquery(subquery))
    if clause["negated"]:
        predicate = ~predicate
    return predicate
