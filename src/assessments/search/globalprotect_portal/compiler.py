"""Canonical search compiler for one GlobalProtect portal entry of one virtual system.
PAN-GPP-001, -003, -004, -005.

ONE ROW PER NAMED PORTAL PER VSYS. `appliance` is NON-NULLABLE on this model - introspected, not
assumed - so `hostname` needs no appliance-group fallback, unlike the enforcement-point and
security-profile compilers whose subjects can hang off a group instead.

FOUR CONTROLS, ONE MODEL, ONE TYPE. That is the normal case and the one `_CONTROL_TYPE_TARGET_MODEL`
is built for; what it forbids is a SECOND type for this model, which nothing in the suite catches.

WHAT IS REGISTERED AND WHY, because the rule is that a field earns its place by a control needing
it and registering the rest ships a search surface no control asks for:

* the four assertion columns of the four controls that target this model -
  `tls_profile_binding_missing`, `upgrade_posture`, `saved_credentials_posture` and
  `custom_login_page`. Three of the four are ALSO their control's grading column, so a calibration
  query compares on the same field the baseline asserts on.
* `mandatory_keys_present`, which is PAN-GPP-005's COMPANION column. `custom_login_page` reads as
  COMPLIANT when unknown - stage 5 declares `when_unknown.reads_as: passes` with this column as its
  `companion_column` - and there is no is-null operator in this language, so without a clause on
  this field a portal whose read never carried the key passes a control about an unauthenticated
  credential prompt published on the internet. It is a non-nullable boolean defaulting to FALSE,
  the firing side.
* `portal_name`, which resolves to the base's `name`. The model carries a `portal_name` PROPERTY
  for exactly this: the artifact layer resolves a control's tested fields against the subject model
  and accepts a name the model stores OR COMPUTES, and the finding prints the portal name because
  that is what an engineer opens.

WHAT IS REGISTERED AND QUERIED BY NOTHING, which is deliberate and has a shipped precedent in
`saas_application_policy_posture`. `clientless_vpn_state`, `clientless_vpn_min_version` and
`clientless_vpn_floor_known` are PAN-GPP-006's SECOND half - the transport floor of the browser
sessions carrying a portal's published web applications. That control targets
`integrations.GlobalProtectEnforcementPoint`, chosen from its own language, and
`ControlQuery.clean()` refuses a query whose model differs from its control's target, so no query
of PAN-GPP-006 can reach these three. They are registered because the columns exist to be queried,
because a reader needs the cell if a second control id is ever minted for that half, and because
leaving them out would hide the gap rather than record it. The stage 8 artifact names the half as
silent in `subjects_in_two_models`.

WHAT IS NOT REGISTERED AND MUST NOT BE. `agent_configurations` is a JSONField - the ordered agent
configuration list, kept so a remediation can name WHICH configuration to edit - and
`test_findings_rest_on_columns` fails any registered field that resolves to one. Stage 5 marks it
`not_searchable` and says a finding may not rest on it: the two posture columns beside it carry the
reading, and they are the ones registered here. `ssl_tls_service_profile` is also left out, because
stage 5 clauses PAN-GPP-001 on the derived verdict and NOT on `ssl_tls_service_profile is empty` on
purpose - the binding is MANDATORY on a committed portal, so an empty string is evidence about the
READ rather than a device state.

A NULL IS UNREACHABLE BY THE ONE ABSENCE OPERATOR THIS LANGUAGE OFFERS, and that shapes two
fields. `is_empty` compiles to `filter(field="")`, so the text compiler below ORs an `__isnull`
term into it - which is what makes `clientless_vpn_min_version`, a nullable column, answerable at
all. The booleans are non-nullable with FALSE as the default and FALSE as the firing side, so a
portal nobody has normalized reports rather than reading as a clean estate.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import GlobalProtectPortal

GLOBALPROTECT_PORTAL_MODEL = "integrations.GlobalProtectPortal"


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        predicate = Q()
        for lookup in lookups:
            predicate &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return predicate
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    predicate = Q()
    for lookup in lookups:
        predicate |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return predicate


def build_text_compiler(field_name, *lookups):
    def compiler(clause):
        return GlobalProtectPortal.objects.filter(
            _text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return GlobalProtectPortal.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: ONE COLUMN, TWO FIELDS, which is the convention every shipped
    # compiler follows and what `probe.model_brief` records. The hostname is what a reader
    # recognises and the serial is what identifies the appliance across a rename, so neither field
    # can do the other's job. `appliance` is non-nullable here, so there is no group fallback.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # Stage 5's `vsys_name` column. Portal content is vsys-scoped and nothing else - there is no
    # shared portal and no predefined one, measured - so this is the whole of the row's scope.
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # Stage 5's `portal_name`, which IS the base's `name`. See the module docstring: the model's
    # `portal_name` property exists so that a search field of this name resolves.
    "portal_name": build_text_compiler("portal_name", "name"),
    # PAN-GPP-001's assertion. TRUE fires, and true is the stored default: a portal nobody has
    # looked at has not been shown to bind a transport profile.
    "tls_profile_binding_missing": build_boolean_compiler(
        "tls_profile_binding_missing", "tls_profile_binding_missing"),
    # PAN-GPP-003's assertion AND its grading column. Five vendor values and three sentinels for
    # the states one value cannot express - the commonest in this estate being
    # `no_agent_configuration`, which no comparison on a nested key can tell from silence.
    "upgrade_posture": build_text_compiler("upgrade_posture", "upgrade_posture"),
    # PAN-GPP-004's assertion AND its grading column. THE STORED ORDER IS NOT THE EXPOSURE ORDER -
    # the column runs 0,1,2,3 and the exposure runs 0 < 2 < 3 < 1 - so this is registered for
    # EQUALITY and the control's calibrations are equalities. A threshold over it would report
    # `Save Username Only` as worse than `Only with User Fingerprint`.
    "saved_credentials_posture": build_text_compiler(
        "saved_credentials_posture", "saved_credentials_posture"),
    # PAN-GPP-005's assertion AND its grading column.
    "custom_login_page": build_text_compiler("custom_login_page", "custom_login_page"),
    # PAN-GPP-005's COMPANION column - "did anybody read the login page at all". See the module
    # docstring; without it an unknown reads as compliant and nothing errors.
    "mandatory_keys_present": build_boolean_compiler(
        "mandatory_keys_present", "mandatory_keys_present"),
    # PAN-GPP-006's second half. REGISTERED AND QUERIED BY NOTHING - that control targets the
    # enforcement point and `ControlQuery.clean()` refuses a query on another model. See the
    # module docstring and the stage 8 artifact's `subjects_in_two_models`.
    "clientless_vpn_state": build_text_compiler(
        "clientless_vpn_state", "clientless_vpn_state"),
    "clientless_vpn_min_version": build_text_compiler(
        "clientless_vpn_min_version", "clientless_vpn_min_version"),
    "clientless_vpn_floor_known": build_boolean_compiler(
        "clientless_vpn_floor_known", "clientless_vpn_floor_known"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_globalprotect_portal_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_globalprotect_portal_search_node(c) for c in group["clauses"]]
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
