"""Canonical search compiler for one security zone's Device-ID settings. PAN-IOT-002.

ONE ROW PER NAMED ZONE PER VSYS, so the owner is reached through the enforcement point and the
appliance lookups branch on either owner - `appliance` set means locally managed, `appliance_group`
set means Panorama-managed. That is the same two-path shape every enforcement-point-owned compiler
in this package uses.

THE MODEL PREDATES THIS DOMAIN BY MONTHS AND HAD NO COMPILER AT ALL. `Zone` already stored
`enable_device_identification`, `device_include_acl` and `device_exclude_acl`; no control had
ever asserted over a zone, so there was no control type, no finding model and no search surface.
PAN-IOT-002 is the first.

THE FIRING STATE OF THE NARROWING HALF IS A POPULATED LIST, WHICH IS THE OPPOSITE OF WHAT A
REVIEWER LOOKS FOR. With no `device-acl` node the grid renders INCLUDED NETWORKS `any` and
EXCLUDED `none`, so an absent or empty include list means identification applies to EVERY address
in the zone - the most permissive reading, and the COMPLIANT one for this control. Stage 4
measured it on two platforms and called absence "the dangerous one for anybody who assumed
absence meant scoped to nothing". It also measured that an empty member list is not storable:
deleting the last member leaves the container present and empty and PAN-OS drops it, so absent
and empty are one state and there is no third reading to clause on.

NEITHER ACL IS REACHABLE FROM HERE AND THAT IS WHY `device_identification_is_narrowed` EXISTS.
Both are JSON columns; a JSON column is reachable from no query in this language, there is no
count operator, and there is no way to write an OR across two columns in one clause - so "either
list has at least one member" has to be computed at normalization or not asked at all. Stage 5
marks both `not_searchable` and stage 7 computed the boolean.

`device_identification_is_narrowed` READS AS COMPLIANT WHEN NOBODY LOOKED, and false is not a
guess: it is the MEASURED meaning of an absent device-acl, which 48 of the 50 zones measured are
genuinely in. So it cannot simply be flipped to the firing side, and the unknown is carried by
`device_acl_lists_computed` instead - registered beside it, clause on it, and PAN-IOT-002 carries
a second query that fires on it at false so a zone whose lists were never read reports "the scope
of identification in this zone could not be established" rather than passing.

WHAT NO COLUMN OF THIS MODEL CAN SAY. `Zone` carries no scope, `config_source` or provenance
column of any kind, so a zone pushed from a Panorama template is indistinguishable in the row
from a firewall-local one - and a finding on a pushed zone names a local zone and implies a
remediation this firewall will refuse. Nor does `device_acl_lists_computed` cover a zone with NO
ROW: if the per-vsys merged read is missed the zone is absent rather than unknown, which is a
collection-coverage question and not a column default.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import Zone

ZONE_MODEL = "integrations.Zone"


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
        return Zone.objects.filter(_text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return Zone.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column: one column, two fields, and each field two lookup paths
    # because exactly one of the enforcement point's two owners is set.
    "hostname": build_text_compiler(
        "hostname", "enforcement_point__appliance__hostname",
        "enforcement_point__appliance_group__appliances__hostname"),
    "serial_number": build_text_compiler(
        "serial_number", "enforcement_point__appliance__serial_number",
        "enforcement_point__appliance_group__appliances__serial_number"),
    # Stage 5's `vsys_name`. A zone name is unique only per enforcement point, so this is part
    # of the zone's identity and not a convenience.
    "vsys_name": build_text_compiler("vsys_name", "enforcement_point__vsys_name"),
    # Stage 5's `name` - the zone's own entry name.
    "name": build_text_compiler("name", "name"),
    # PAN-IOT-002's first half, and the applicability clause of its second. FALSE fires: stage 4
    # measured on two platforms that a committed zone with no key renders the Device-ID ENABLED
    # box UNTICKED, so a zone with no key identifies nothing.
    "enable_device_identification": build_boolean_compiler(
        "enable_device_identification", "enable_device_identification"),
    # PAN-IOT-002's second half. TRUE fires - a populated list is the narrowing. Reads as
    # compliant when nobody looked; clause on the companion below beside it.
    "device_identification_is_narrowed": build_boolean_compiler(
        "device_identification_is_narrowed", "device_identification_is_narrowed"),
    # The companion that answers "were this row's Device-ID lists ever read".
    "device_acl_lists_computed": build_boolean_compiler(
        "device_acl_lists_computed", "device_acl_lists_computed"),
    # PAN-UID-001's assertion, and the FIRST USER-ID control over a zone. TRUE fires: the
    # switch being on is what exposes internal username-to-IP mappings in a zone, and whether
    # this zone faces a network the customer does not control is not readable from a firewall -
    # so it is deliberately NOT a qualifying condition here, for the reason the Device-ID half
    # above gives. The column is a non-nullable boolean whose absent key resolves to the
    # measured implicit, so it has no unknown state and needs no companion.
    #
    # `include_acl` and `exclude_acl` - the zone's USER-ID address lists, distinct from the two
    # Device-ID lists above - are NOT registered: both are JSON columns, a JSON column is
    # reachable from no query in this language, and stage 5 marks them `not_searchable`. What
    # bounds User-ID discovery is PAN-UID-002's own subject, which is a separate model.
    "enable_user_identification": build_boolean_compiler(
        "enable_user_identification", "enable_user_identification"),
    # ------------------------------------------------------ PAN-ZON-001's three fields
    #
    # `zone-dos-protection`, 2026-11-01. THE THIRD CONTROL OVER THIS MODEL and the first that is
    # not about identification at all: whether any zone defence is in force where traffic
    # enters. These three are added to a shipped compiler rather than given a package of their
    # own, because the model already has one.
    #
    # PAN-ZON-001's APPLICABILITY. TRUE is IN the population: the zone carries one of the six
    # type subtrees and either names an interface or is an inter-vsys `external` zone, which has
    # no interfaces of its own and still offers the attachment. The column's default is TRUE and
    # the model's own comment says why - a zone nobody has recomputed would otherwise compute
    # false and drop out of the control silently, which is the direction rules.md refuses.
    "can_receive_traffic": build_boolean_compiler(
        "can_receive_traffic", "can_receive_traffic"),
    # PAN-ZON-001's ASSERTION, and the reason this control is not `zone_protection_profile
    # is_empty`. TRUE FIRES. The attachment leaf is a free string with no referential integrity
    # the configuration expresses - measured - so a zone naming a profile that does not exist
    # reads as configured and meters nothing. This column is the RESOLVED answer: the leaf is
    # empty, or it names a profile absent from this appliance's device-local collection under a
    # case-SENSITIVE comparison. `zone_protection_profile` is deliberately NOT registered: it is
    # the naive reading, a clause on it PASSES exactly the dangling-name case this column exists
    # to catch, and registering it would ship that trap as a search surface.
    "zone_protection_unresolved": build_boolean_compiler(
        "zone_protection_unresolved", "zone_protection_unresolved"),
    # PAN-ZON-001's GRADING AXIS, which is a clause NOWHERE in stage 5 and is what five
    # calibration queries assert on. A PROXY, AND THE ARTIFACT SAYS SO: what stage 3 grades on
    # is the zone's EXPOSURE - which side of the perimeter it faces - and no column of any model
    # holds that, so the nearest thing the configuration offers is which subtree carried the
    # interfaces. Text rather than boolean because the column is a seven-member enum, and the
    # placements are mutually exclusive equalities on it, which is what makes a calibration
    # query at the baseline's own tier safe to build here: no row can match two of them, so the
    # worst matched calibration is the only matched one.
    "zone_type": build_text_compiler("zone_type", "zone_type"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_zone_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_zone_search_node(c) for c in group["clauses"]]
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
