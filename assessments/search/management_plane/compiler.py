"""Model-specific canonical search compilation for management-plane profiles."""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.management_plane.fields.scalar_boolean import (
    SUPPORTED_OPERATORS as BOOLEAN_OPERATORS,
    compile_scalar_boolean_clause,
)
from assessments.search.management_plane.fields.scalar_integer import (
    SUPPORTED_OPERATORS as INTEGER_OPERATORS,
    compile_scalar_integer_clause,
)
from assessments.search.management_plane.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
    compile_scalar_text_clause,
)


MANAGEMENT_PLANE_MODEL = "integrations.ManagementPlaneProfile"


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
    "has_permitted_ip_restrictions": build_boolean_compiler(
        "has_permitted_ip_restrictions",
        "has_permitted_ip_restrictions",
    ),
    "has_unrestricted_permitted_ips": build_boolean_compiler(
        "has_unrestricted_permitted_ips",
        "has_unrestricted_permitted_ips",
    ),
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "http_disabled": build_boolean_compiler("http_disabled", "http_disabled"),
    "https_disabled": build_boolean_compiler("https_disabled", "https_disabled"),
    "icmp_disabled": build_boolean_compiler("icmp_disabled", "icmp_disabled"),
    "idle_timeout_minutes": build_integer_compiler("idle_timeout_minutes", "idle_timeout_minutes"),
    "login_banner": build_text_compiler("login_banner", "login_banner"),
    "management_station": build_text_compiler("management_station", "management_station__hostname"),
    "ntp_primary_server": build_text_compiler("ntp_primary_server", "ntp_primary_server"),
    "ntp_secondary_server": build_text_compiler("ntp_secondary_server", "ntp_secondary_server"),
    "permitted_ip_count": build_integer_compiler("permitted_ip_count", "permitted_ip_count"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    "snmp_disabled": build_boolean_compiler("snmp_disabled", "snmp_disabled"),
    "ssh_disabled": build_boolean_compiler("ssh_disabled", "ssh_disabled"),
    "telnet_disabled": build_boolean_compiler("telnet_disabled", "telnet_disabled"),
}


FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_management_plane_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled_clauses = [compile_management_plane_search_node(clause) for clause in group["clauses"]]
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
