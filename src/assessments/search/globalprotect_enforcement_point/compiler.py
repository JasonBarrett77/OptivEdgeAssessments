"""Canonical search compiler for one virtual system's GlobalProtect objects taken as a whole.
PAN-GPP-006.

ONE ROW PER VSYS, AND THE ROW IS A VERDICT RATHER THAN AN ENTRY. PAN-GPP-006 asserts that no
portal publishes internal web applications for browser access AND that neither the portal nor the
firewall holds the application definitions or application groups such publishing would draw on.
That is a statement about the virtual system, not about any one portal, and the target model was
chosen from that language.

THE RANK THIS GRAIN EXISTS FOR IS `latent` - a vsys holding a clientless application definition
that NO portal publishes. Measured on vsys6 of this estate: one definition, no portal, no interface
imported, so nothing is reachable today and what is present is a configuration one edit from being
live. There is no portal row for it to be reported on, so a portal-grain control is silent on it by
construction. That silence is this model's reason for existing, and it is why the enforcement point
took the control id rather than the portal.

NODE PRESENCE IS THE WRONG TEST AND AN ENTRY COUNT IS THE RIGHT ONE, measured: deleting the last
entry leaves the container present and empty, deleting the container leaves `global-protect` present
and empty, and one appliance in this estate carries exactly that - committed, undecorated, with
`action=get` answering a count of one for it. A truthiness test on the container reports a portal
where there is none, which is why the four counts below are registered beside the verdict.

THERE IS NO BOOLEAN TO READ FOR THE FEATURE ITSELF, and a reader who assumes one reports the
opposite. Stage 4 enumerated the `clientless-vpn` container's children on three builds - ten of
them, and not one is a boolean - so `absent OR disabled` collapses to "the element exists or it does
not", and reading the missing switch as `off` would report every portal with the feature fully
configured as COMPLIANT. `clientless_vpn_feature_state` is the four-state verdict that replaces it.

THE APPLICABILITY TRAP IS ON `licence_excludes_globalprotect` AND IT IS THE REASON THAT COLUMN
EXISTS. An `applies_when` clause reading "unlicensed, so there was never a choice" SUPPRESSES the
control where the answer is no - and on two appliances of this estate the answer is not no, it is
UNKNOWN: `{'licenses': None}` arrives truthy and empty with status=success. So the column is built
to be FALSE on an unknown and the control fires. DO NOT RE-POINT A CLAUSE AT
`globalprotect_portal_licensed` to get the same effect: that column's `unknown` and `no` are both
"not yes", and a negated clause over it would suppress on both. The model's own comment says so and
it is repeated here because this is where a clause gets written.

WHAT IS DELIBERATELY NOT REACHABLE FROM HERE, and it is the one gap this domain ships. PAN-GPP-006's
SECOND half - where a portal does publish, its browser sessions may not negotiate weaker transport
than the portal itself requires - clauses on `integrations.GlobalProtectPortal`. `ControlQuery.clean()`
refuses a query whose model differs from its control's target, and standing ruling 6's remedy is to
reach the other half by a relation. THERE IS NO RELATION TO WALK, in either direction, and that is
introspected rather than argued: this model carries FKs to `management_station`, `appliance`,
`appliance_group` and `source_snapshot` and nothing else, and `GlobalProtectPortal` carries the same
four and no enforcement-point FK. The only path between them is through `appliance`, whose reverse
accessor `globalprotectportals` is to-MANY and - worse than the `file-data-filtering` case that
produced ruling 6's direction qualifier - CROSSES VSYS BOUNDARIES, so one virtual system's row
would fire for a portal in another. The stage 8 artifact records that half as silent in
`subjects_in_two_models`; what would close it is a column on THIS model carrying the floor at this
grain, which stage 8 may not add, or a second control id, which a build run may not mint.

NO is-null OPERATOR EXISTS IN THIS LANGUAGE and none is invented here. Every boolean registered
below is non-nullable with FALSE as both the default and the firing side, and the counts are
non-nullable with 0 as the default - so a vsys nobody has normalized reports rather than reading as
a clean estate.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import GlobalProtectEnforcementPoint

GLOBALPROTECT_ENFORCEMENT_POINT_MODEL = "integrations.GlobalProtectEnforcementPoint"

INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


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
        return GlobalProtectEnforcementPoint.objects.filter(
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
        return GlobalProtectEnforcementPoint.objects.filter(
            **{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return GlobalProtectEnforcementPoint.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column, as two fields. `appliance` is non-nullable on this model, so
    # there is no appliance-group fallback - unlike `data_filtering_posture`, whose subject can
    # hang off a group. THE LICENCE COLUMNS BELOW ARE DEVICE-WIDE and are duplicated across every
    # vsys row of one appliance, which the serial is what a reader reconciles them by.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # The row's own grain. A PA-5220 in this estate reports eight firewall-local vsys under
    # `action=show` and a ninth under `action=get`; the name is enumerated from the device's own
    # config and never from a list the collector chooses.
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # PAN-GPP-006's assertion AND its grading column. Four placements over an invented four-state
    # vocabulary stage 5 declares `unmeasured`: `live`, `latent`, `absent`, `unknown`.
    "clientless_vpn_feature_state": build_text_compiler(
        "clientless_vpn_feature_state", "clientless_vpn_feature_state"),
    # PAN-GPP-006's APPLICABILITY clause, which must appear in every query this control produces -
    # a rank query missing it widens the control onto rows that never qualified. See the module
    # docstring for why this column and not `globalprotect_portal_licensed`.
    "licence_excludes_globalprotect": build_boolean_compiler(
        "licence_excludes_globalprotect", "licence_excludes_globalprotect"),
    # PAN-GPP-003's SECOND half. The count of HIP objects carrying a client-version criterion at
    # all - "below the documented floor" is not something the object can say, because the matcher
    # has exactly three children, `contains`, `is` and `is-not`, every one a string match with no
    # numeric comparison anywhere beneath it. REGISTERED AND QUERIED BY NOTHING: PAN-GPP-003
    # targets `integrations.GlobalProtectPortal`, chosen from the control's own language and its
    # own severity, so no query of that control can reach this field. The stage 8 artifact records
    # that half as silent in `subjects_in_two_models`.
    "hip_objects_testing_client_version": build_integer_compiler(
        "hip_objects_testing_client_version", "hip_objects_testing_client_version"),
    # The four counts the feature-state verdict is computed from, registered so a finding can say
    # WHICH part of the absence failed - `live` and `latent` differ only in whether a portal
    # publishes, and the remediation differs with it. An entry count rather than node presence;
    # see the module docstring.
    "portal_count": build_integer_compiler("portal_count", "portal_count"),
    "clientless_app_count": build_integer_compiler(
        "clientless_app_count", "clientless_app_count"),
    "clientless_app_group_count": build_integer_compiler(
        "clientless_app_group_count", "clientless_app_group_count"),
    "portals_publishing_clientless_apps": build_integer_compiler(
        "portals_publishing_clientless_apps", "portals_publishing_clientless_apps"),
    # What tells an UNKNOWN licence answer from a NO, which is what keeps the applicability clause
    # above honest. These two are indistinguishable from the reply - `{'licenses': None}` arrives
    # with status=success - so the normalizer records that it ASKED, and zero entries does NOT mean
    # unlicensed. Registered for the reader; no clause rests on either.
    "licence_reply_collected": build_boolean_compiler(
        "licence_reply_collected", "licence_reply_collected"),
    "licence_entry_count": build_integer_compiler(
        "licence_entry_count", "licence_entry_count"),
    # Whether a GlobalProtect Portal licence is installed. THE JOIN IS ON A PROSE STRING matched
    # against a vendor label nothing guarantees stable across releases, which is the whole
    # fragility and why `unknown` is a member. Registered for the reader; a clause here would
    # suppress on `unknown` as well as on `no`, which is the trap the module docstring names.
    "globalprotect_portal_licensed": build_text_compiler(
        "globalprotect_portal_licensed", "globalprotect_portal_licensed"),

    # --------------------------------- `globalprotect-gateway` adds ONE field, 2026-11-01
    # THE ONLY CHANGE THIS DOMAIN MAKES TO A SHIPPED COMPILER, and it is additive: nothing above
    # was renamed, removed or re-lookup-ed, and the OEA gate was taken immediately before and
    # immediately after it. PAN-GPP-006 compiles through this same compiler and its four fields
    # are untouched.
    #
    # PAN-GPG-005's ASSERTION, and the only assertion of the whole `globalprotect-gateway` domain
    # with a stage 6 verdict to be graded against - which is why that control took this model as
    # its target rather than the gateway its third record names. The verdict is a conjunction
    # resolved at normalisation over THREE aggregates on this row: `hip_object_count`,
    # `hip_profile_count` and `rules_referencing_a_hip_profile_count`. It is true only where a HIP
    # object exists, a HIP profile exists, AND at least one security rule names that profile, so a
    # clause list - which is one conjunction with no edge to walk into another model's rows -
    # could not have expressed it.
    #
    # THE COMMONEST FAILING STATE IS THAT NONE OF THEM EXISTS, which is the grain this model is
    # for: the rows whose absence IS the finding are the rows that do not exist, so at the entry
    # grain there would be nothing to report it with. Measured on vsys1 of fw-core-tpa-a - the one
    # standing subject this domain has - the hip-objects collection is absent in both views, the
    # hip-profiles collection beside it is absent in both, and no rule in the vsys rulebase names
    # a HIP profile. The column is false and the clause holds.
    #
    # `default=False` IS THE FIRING SIDE, so a row nobody recomputed reports itself rather than
    # passing. Non-nullable, so `cannot_be_unknown` holds and no companion column is owed.
    "posture_referenced_in_policy": build_boolean_compiler(
        "posture_referenced_in_policy", "posture_referenced_in_policy"),
    # AND NOTHING ELSE, DELIBERATELY. The three aggregates this verdict is resolved from -
    # `hip_object_count`, `hip_profile_count` and `rules_referencing_a_hip_profile_count` - are
    # NOT registered, because no clause and no grading of any control names them and the
    # compiler's own rule is that a field earns its place by a control needing it. A finding that
    # wants to say WHICH part of the posture apparatus is missing reads them off its own row in
    # the generator, which needs no search surface; registering them would widen a SHIPPED
    # compiler's probe surface for no control's benefit. This entry is the fourteenth field here
    # and the only change `globalprotect-gateway` makes to a shipped compiler.
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_globalprotect_enforcement_point_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_globalprotect_enforcement_point_search_node(c)
                for c in group["clauses"]]
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
