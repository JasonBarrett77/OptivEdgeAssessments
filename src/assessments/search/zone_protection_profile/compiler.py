"""Canonical search compiler for one zone protection profile. PAN-ZON-002 to -006, and -008.

ONE ROW PER NAMED PROFILE PER APPLIANCE, and the owner is the APPLIANCE DIRECTLY rather than an
enforcement point. That is not a simplification: `network/profiles/zone-protection-profile` has
exactly ONE scope on a firewall - measured, `action=complete` answers code=6 Invalid sequence at
both the shared and the vsys spellings - so there is no per-vsys copy to tell apart and no
either-owner branch of the kind every policy-object compiler in this package carries. The model's
`appliance` foreign key is non-nullable, so each lookup here is a single path.

SIX CONTROLS SHARE THIS MODEL AND ASSERT ON DISJOINT COLUMNS, which is the ordinary case a
one-to-one type map describes: PAN-ZON-002 on the SYN flood enable, -003 on the four volumetric
flood enables rolled into one verdict, -004 on reconnaissance detection and its exemption list,
-005 on the spoofed-address drop, -006 on the non-SYN refusal and the four packet drops, and -008
on whether any zone names the profile at all.

THE FOUR DERIVED VERDICT COLUMNS ARE THIS QUERY LANGUAGE'S LIMIT AND NOT THE DEVICE'S, and a
reader of the column names alone would get this wrong. `volumetric_flood_gap` and
`packet_drop_gap` each stand for "ANY ONE OF FOUR leaves is off" - a four-way disjunction - and
the clause list of a control query is one conjunction. The language DOES ship nested OR groups,
so the alternative was four arms each repeating the applicability gate; stage 5 asked for the
derived column and stage 7 built it, and the four measured enable columns behind each verdict are
deliberately NOT registered below. Registering them would ship a search surface no control asks
for and would let a later clause answer a quarter of the question under the whole question's name.

`is_in_force` AND `is_unreferenced` ARE NOT EACH OTHER'S NEGATION, and this is the one thing in
this module most likely to be mistaken for tidiness. `is_in_force` defaults TRUE - a profile
nobody has swept is assessed for its contents, because a missed defense reported as present is
the error rules.md refuses. `is_unreferenced` defaults FALSE and is gated by
`attachment_sweep_complete`, because PAN-ZON-008's remediation is a DELETION: a false "nothing
references this" ends in a profile deleted out from under the zone that was using it, which is
neither checkable in a minute nor reversible by reading. The two columns therefore default to
OPPOSITE SIDES on purpose, and the model's own `clean()` refuses a row where both are true.

EVERY `is_empty` HERE TAKES THE BARE `filter(field="")` SHAPE, WHICH IS CORRECT ON THIS MODEL AND
IS NOT A CONVENTION TO COPY. Measured 2026-11-01 across all 58 shipped compilers: 35 compile
`is_empty` to `filter(field="")` alone and 22 OR an `__isnull=True` branch beside it, and the
choice is decided by the column rather than by taste - a `null=True` column whose normalizer
writes NULL for the absent case is unreachable by the bare shape, so the clause compiles, passes
every gate and matches nothing on the exact population it was written for. Every text column
registered below is `null=False` with a blank default, checked field by field, so there is no
null for the bare shape to miss. The three nullable columns on this model are `flood_rates`,
`scan_interval` and `scan_threshold`, and NONE of them is registered: the first is a JSONField a
consumer test refuses to register at all, and the other two are the two integers whose genuine
NULL no operator in this language reaches - which is precisely why
`scan_sensitivity_known` exists as a real stored column and is registered beside them.

`scan_weakest_action`'s EMPTY STRING IS A REACHABLE STATE AND `is_empty` IS THE ONLY OPERATOR
THAT REACHES IT POSITIVELY. The sentinel means a scan type with no entry on the profile at all -
measured, and different from an entry whose `action` child is absent, which the device reads as
`alert`. An `eq ""` clause would raise `SearchSyntaxError` in `_text_filter` below,
`evaluate_queryset_control_queries` CATCHES that and counts the query as skipped, and the control
would ship narrower than its catalog entry says with nothing raised. So the calibration at that
member is written `is_empty`.

WHAT IS DELIBERATELY NOT REACHABLE FROM HERE. Thirty-odd columns of this model carry no clause
and no grading in any control of this domain: the five individual flood enables, the eight
individual packet drops, the four per-entry scan actions, `syn_flood_action`,
`strict_ip_check`, `discard_record_route`, `discard_timestamp`, `attached_zone_count`,
`scan_block_ip_track_by`, `scan_interval` and `scan_threshold`. Stage 5 declares each of them so
that a READER of a finding can be shown the number, which is stage 9's business and not a
clause's, and the compiler's own rule is that a field earns its place by a control needing it.
Two of them are the sharper case and are named rather than lumped in: stage 4 records
`asserted_by: [PAN-ZON-006]` for `discard_record_route` and `discard_timestamp` and stage 3 says
in terms that the vendor's hardening line for that tab does not ask for either, so stage 5 took
stage 3 and declared the columns with no clause. Taking stage 4 here would have widened a control
on an index that its own author calls "not identity".
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import ZoneProtectionProfile

ZONE_PROTECTION_PROFILE_MODEL = "integrations.ZoneProtectionProfile"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            # BARE, and the module docstring argues it: every text column here is `null=False`
            # with a blank default, so there is no NULL for an `__isnull` branch to reach.
            return ZoneProtectionProfile.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return ZoneProtectionProfile.objects.filter(
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
        return ZoneProtectionProfile.objects.filter(**{lookup_field: value}).values("pk")
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
        return ZoneProtectionProfile.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column, which is ONE COLUMN AND TWO FIELDS - the convention every
    # shipped compiler in this package follows. The hostname is what a reader recognises; the
    # serial number is what identifies the appliance when two carry the same hostname, which on
    # an HA pair is the normal case rather than the edge one. ONE LOOKUP PATH EACH, because this
    # collection is device-local and the model's `appliance` is non-nullable.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # Stage 5's `profile_name` - the profile's own entry name, and half of its identity. Names
    # are case-sensitive and unnormalised on the device (help p.663), which is why the
    # ATTACHMENT join is computed at normalisation rather than written as a clause here.
    "profile_name": build_text_compiler("profile_name", "profile_name"),
    # ------------------------------------------------ the applicability gate five controls share
    #
    # PAN-ZON-002 to -006 all carry this as `role: applicability`. TRUE is in the population: at
    # least one zone of some vsys of this appliance names the profile. A profile nobody attached
    # enforces nothing however it is set, and PAN-ZON-008 is the control that reports THAT - so
    # this gate is what stops one profile producing two findings about the same fact.
    #
    # ITS DEFAULT IS TRUE AND THAT IS THE SAFE SIDE HERE: a profile whose attachment sweep has
    # not run is assessed for its contents rather than excused. The opposite default would make
    # every control on this model silent on exactly the appliances nobody has swept.
    "is_in_force": build_boolean_compiler("is_in_force", "is_in_force"),
    # ------------------------------------------------------------- PAN-ZON-002's assertion
    # FALSE FIRES. Stage 4 measured the implicit as `no` on two oracles including an operational
    # one, so an absent key is a vendor fact rather than an unknown and this column needs no
    # companion.
    "syn_flood_enabled": build_boolean_compiler("syn_flood_enabled", "syn_flood_enabled"),
    # ------------------------------------------------------------- PAN-ZON-003's assertion
    # TRUE FIRES, and the column is a DISJUNCTION over four leaves - the UDP, ICMP, ICMPv6 and
    # other-IP flood enables. Its default is TRUE, the firing side. The object has SIX flood
    # branches and not four: PAN-ZON-002 owns the fifth and the stream-control transport's
    # initiation flood is asserted by no control anywhere, so `other_ip_flood_enabled` must not
    # be read as a catch-all that covers it.
    "volumetric_flood_gap": build_boolean_compiler(
        "volumetric_flood_gap", "volumetric_flood_gap"),
    # ------------------------------------------------------------- PAN-ZON-005's assertion
    # FALSE FIRES, and the clause is deliberately UNGATED by zone type. The vendor asks for this
    # drop on INTERNAL zones only, twice (help p.674, guide p.1265), and the profile holds NO
    # RECORD of which zone it is attached to - one profile may be in force on an internal zone
    # and an internet-facing one at once, so there is no row on which that predicate could be
    # true or false. The control therefore fires on every profile in force, which is stage 3's
    # own fail-safe direction, and the finding owes the sentence that the population was not
    # established. That sentence is in the generator, not here.
    "discard_ip_spoof": build_boolean_compiler("discard_ip_spoof", "discard_ip_spoof"),
    # ------------------------------------------------- PAN-ZON-006's two assertions
    #
    # The RESOLVED answer, and the reason this control is not `non_syn_reject_configured eq yes`.
    # The profile's own leaf is a THREE-VALUED enum whose schema default and measured implicit
    # are both `global` - A POINTER, not a value - so the commonest state of an untouched profile
    # is one the catalogue row's boolean scale cannot score. Comparing the leaf to `yes` reports a
    # profile at `global` as non-compliant on a device whose device-wide setting rejects non-SYN
    # TCP, and treating `global` as satisfied misses the exposure where that setting is `no`.
    # This column holds what the chain resolves to, measured in both directions on the device.
    # The clause is a NEGATED equality, which is a clause flag in this language rather than an
    # operator, so "any value except yes" needs no OR group.
    "non_syn_reject_effective": build_text_compiler(
        "non_syn_reject_effective", "non_syn_reject_effective"),
    # THE GRADING AXIS beside it, which is the profile's OWN leaf rather than the resolution.
    # Graded apart from the other two states because the middle one is not an answer at all but
    # a deferral to a device-wide setting that has to be read separately. A profile at `global`
    # on a device whose global setting is `yes` does not fire the baseline at all, so this
    # placement can only ever match a row the baseline already reported.
    "non_syn_reject_configured": build_text_compiler(
        "non_syn_reject_configured", "non_syn_reject_configured"),
    # PAN-ZON-006's second half. TRUE FIRES, and the column is a DISJUNCTION over the four drops
    # the catalogue row's DESCRIPTION names - unknown-and-malformed, strict source routing, loose
    # source routing and mismatched overlapping TCP segment. The row's longer list adds the
    # Record Route and network-layer Timestamp drops and NO VENDOR HARDENING LINE asks for those
    # two, so they are declared as columns, asserted by nothing, and not registered here.
    "packet_drop_gap": build_boolean_compiler("packet_drop_gap", "packet_drop_gap"),
    # --------------------------------------------------- PAN-ZON-004's three fields
    #
    # TRUE FIRES: at least one of the four scan types the profile can carry has no entry, or has
    # one whose action does not record the event. FOUR COLUMNS ON A CLOSED SET rather than a
    # child table, and the closure is measured - the scan entry's id is a REFERENCE, so no fifth
    # entry can be invented. The device offers FOUR entries where the catalogue row names three,
    # so an assertion written over the row leaves IP Protocol Scan unaudited entirely.
    "scan_detection_gap": build_boolean_compiler("scan_detection_gap", "scan_detection_gap"),
    # THE GRADING AXIS: which action the weakest of the four entries carries. ITS ORDERING IS NOT
    # A LADDER and no comparison on this column produces it - `block-ip-source-and-destination`
    # sorts below the plain `block` beside it while being the more elaborate setting, which is
    # why the order is computed at normalisation and the calibrations are equalities. The empty
    # string is the sentinel for a scan type with no entry at all and is reached by `is_empty`
    # alone; see the module docstring.
    "scan_weakest_action": build_text_compiler("scan_weakest_action", "scan_weakest_action"),
    # THE COMPANION THAT CARRIES THE SENSITIVITY HALF, and the reason it is a stored boolean
    # rather than a threshold comparison. `scan_interval` and `scan_threshold` both store a
    # genuine NULL for an absent key - stage 4 measured neither implicit and refuted the reading
    # that looked like one - and NO OPERATOR IN THIS LANGUAGE REACHES A NULL: there is no is-null
    # operator and `is_empty` is refused on an integer. So a threshold comparison would silently
    # pass every unedited profile in the estate, which is the whole estate. FALSE FIRES.
    "scan_sensitivity_known": build_boolean_compiler(
        "scan_sensitivity_known", "scan_sensitivity_known"),
    # PAN-ZON-004's SECOND RECORD asserts on this. GREATER THAN ZERO FIRES, and the finding is a
    # request for confirmation rather than an accusation: the control cannot say whether an
    # exempted source is a vulnerability-testing host the customer owns, because no configuration
    # says which hosts those are. The count is of ADDRESSES and not of entries - the vendor's own
    # help describes one address field and the configuration holds TWO separate leaves, so a
    # count that reads one of them sees half the list. `scan_white_list` itself is a JSONField and
    # is not registered: a finding must not rest on a stored structure.
    "scan_white_list_count": build_integer_compiler(
        "scan_white_list_count", "scan_white_list_count"),
    # --------------------------------------------------- PAN-ZON-008's zone-profile half
    #
    # TRUE FIRES: no zone of any vsys of this appliance names the profile. DEFAULTS FALSE, which
    # is the non-firing side, and that asymmetry with `zone_protection_unresolved` on the zone
    # model is deliberate - stage 5 says so in terms: a missed exposure and a wrongly-deleted
    # profile are opposite errors.
    "is_unreferenced": build_boolean_compiler("is_unreferenced", "is_unreferenced"),
    # THE DELETION-SAFETY GATE. TRUE means a second reference surface could not have been missed:
    # stage 7 built it as "does the appliance carry a `shared-gateway` node", because the zone
    # collection of a shared gateway has nowhere to be stored and the literal reading would make
    # the column false on every appliance for ever - suppressing PAN-ZON-008 everywhere while
    # reading as careful. Its default is FALSE, so it SUPPRESSES rather than fires before the
    # reverse lookup has run, which is the one place in this domain where the renormalisation
    # window is deliberately silent. A second query fires on it at false so that the silence
    # reports itself instead of passing for a pass.
    "attachment_sweep_complete": build_boolean_compiler(
        "attachment_sweep_complete", "attachment_sweep_complete"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_zone_protection_profile_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_zone_protection_profile_search_node(c) for c in group["clauses"]]
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
