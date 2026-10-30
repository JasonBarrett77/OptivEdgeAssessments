"""Canonical search compiler for one appliance's registration with its management estate.

PAN-HAP-005. ONE ROW PER APPLIANCE: both nodes behind it - `system/panorama/local-panorama` and
`setting/management/secure-conn-client` - are device-wide `deviceconfig`, so there is no vsys
axis. On an HA pair this yields two rows for one configuration and, unlike the HA model beside
it, these two ARE expected to agree: `panorama-server-2` written on one member of this lab's pair
was present on BOTH twenty minutes later, carried by configuration synchronisation with nothing
ever addressed to the peer.

THE TEXT COLUMNS ARE BLANK AND NOT NULL, AND THAT IS WHY THIS CONTROL WORKS AT ALL. PAN-HAP-005's
assertion clause is `panorama_server_secondary is empty`, and `is_empty` compiles to
`filter(field="")` here as it does in every per-model compiler in this package. A NULL matches
that and nothing else, so storing the absence of a second management address as SQL NULL would
take this control from "fires on every appliance in this estate" to "never fires anywhere", with
nothing erroring and no test failing. Stage 7 of the `ha-panorama` domain stored `""` for exactly
that reason and recorded the departure from stage 5's declaration; this module is the half that
depends on it.

`is_empty` IS THE ONLY OPERATOR IN THIS LANGUAGE THAT IS ABOUT ABSENCE and it tests the empty
string alone. So the two nullable booleans on this model - `secure_panorama_communication_enabled`
and `check_server_identity_enabled` - are NOT registered: a clause over either would pass every
appliance whose certificate posture nobody read, which is the reassuring direction. Both are
folded into `management_channel_not_hardened` at normalization with the firing direction
preserved, and `management_config_collected` is the registered boolean that answers "nobody
looked".

THE CERTIFICATE NAME AND TYPE ARE NOT REGISTERED EITHER. `client_certificate_name` points at a
certificate object no subject of this domain models, so an unresolvable name is indistinguishable
from a resolvable one here; the verdict column already treats an unresolvable name as "the
firewall presents no customer certificate". Leaving the two unregistered also keeps the cell a
finding colours on the verdict rather than on a name a reader would read as the fault.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import PanoramaRegistration

PANORAMA_REGISTRATION_MODEL = "integrations.PanoramaRegistration"


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return PanoramaRegistration.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return PanoramaRegistration.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return PanoramaRegistration.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # One stage 5 column - `appliance` - and two fields, as every shipped compiler does.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # FALSE MEANS NOBODY LOOKED, and false is the migration default.
    "management_config_collected": build_boolean_compiler(
        "management_config_collected", "management_config_collected"),
    # The two address slots. Blank is a MEASURED READING on the second one: an absent
    # `panorama-server-2` asserts the firewall names no secondary appliance, paid in both
    # directions against `show panorama-status` by stage 4.
    "panorama_server_primary": build_text_compiler(
        "panorama_server_primary", "panorama_server_primary"),
    "panorama_server_secondary": build_text_compiler(
        "panorama_server_secondary", "panorama_server_secondary"),
    # The applicability column for the redundancy half. TRUE by default and false by nothing: the
    # answer lives on the management station's own HA node, which is out of assessment scope, so
    # only an engineer can set it. True is the APPLYING side, because a false here would suppress
    # the control on every firewall.
    "management_estate_is_a_pair": build_boolean_compiler(
        "management_estate_is_a_pair", "management_estate_is_a_pair"),
    # The hardening verdict. True is the finding side and the migration default.
    "management_channel_not_hardened": build_boolean_compiler(
        "management_channel_not_hardened", "management_channel_not_hardened"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_panorama_registration_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_panorama_registration_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause["negated"] else predicate
