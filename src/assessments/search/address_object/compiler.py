"""Canonical search compiler for address objects. The PAN-COV coverage controls.

Narrow on purpose. This exists so coverage controls can ask what is NOT known about an address
object — whether its size was established, whether its content was collected whole, whether
anything in policy actually references it. It is not an attempt to make address objects
searchable in general; fields earn their place by a control needing them, the same rule the
payload contract runs under.

`size_known` is a boolean rather than an `is_null` operator on `num_hosts`. The underlying
question is "did we establish this object's size", and asking it that way keeps the two states
that matter apart: `num_hosts` NULL means UNKNOWN, never zero. An EDL the device could not
fetch covers an unknown number of addresses, and 0 is the narrowest possible value — scoring it
would make an unreachable list look like the tightest object on a rule, which is the failure
direction these controls exist to prevent.

`referenced_by_policy` is what keeps the coverage controls proportionate. An EDL nobody
references being uncollected is not a finding — it is a list sitting unused in the address
book. The collection flow only fetches lists that normalized rule refs point at, so the
unreferenced ones are expected to be unsized and must not be reported as a gap.

`size_known` AND `collection_attempted` STAY REGISTERED AND NOTHING SHOULD CLAUSE ON THEM. They
are kept because the shipped PAN-COV-001 baseline rested on both until 2026-10-31, and because
dropping a registration refuses any catalog payload that still carries one. Both are TRUE for
a list the firewall has never read a byte of: a never-fetched list answers `total-valid 1` with
the single member `0.0.0.0/32`, which is a syntactically valid address, so
`resolved_content_source_total` becomes 1 and `num_hosts` becomes 1. `content_was_fetched` is
the column that tells the device's answers apart, and a coverage assertion belongs on that.

`build_choice_compiler` RAISES ON A VALUE OUTSIDE THE COLUMN'S CHOICES rather than matching
nothing. Copied from `search/normalization_issue/compiler.py`, where the reasoning is written
out; used here for the two columns a control's whole population turns on. A mistyped
`address_type` would make one half of PAN-COV-001 match no row and say nothing, and a mistyped
`content_shortfall_band` would drop a severity band the same way. `address_type` was registered
as free text until 2026-10-31, when the name-based half of PAN-COV-001 made it load-bearing; no
catalog query had used it before that, and the configuration pages that map to it ask `eq`
with a value read off a row, which is always a member.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import (
    AddressObject,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
)

ADDRESS_OBJECT_MODEL = "integrations.AddressObject"
INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def build_text_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in TEXT_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if op == "is_empty":
            if not isinstance(value, str) or value.strip():
                raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
            return AddressObject.objects.filter(**{lookup_field: ""}).values("pk")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
        return AddressObject.objects.filter(
            **{f"{lookup_field}__{suffix}": value.strip()}).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_choice_compiler(field_name, lookup_field, choices):
    """`eq` against a closed set, refusing a value the column cannot hold.

    See the module docstring for why this raises where `build_text_compiler` would compile a
    clause that matches nothing. The members are read off the model's own `choices` rather than
    restated, so a member added to the column cannot go missing here.
    """
    members = {str(stored) for stored, _label in choices}

    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, str) or not value.strip():
            raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
        candidate = value.strip()
        if candidate not in members:
            raise SearchSyntaxError(
                f"{field_name} has no value {candidate!r}. It is one of: "
                f"{', '.join(sorted(members))}.")
        return AddressObject.objects.filter(**{lookup_field: candidate}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_boolean_compiler(field_name, lookup_field, *, invert=False):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return AddressObject.objects.filter(
            **{lookup_field: (not value) if invert else value}).values("pk")
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
        return AddressObject.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


def build_referenced_by_policy_compiler(field_name):
    """Whether any security rule points at this object, on either side.

    Both ref tables, because a list used only as a destination is referenced just as much as
    one used as a source. Group membership is already flattened onto the ref rows by
    resolve_static_group_members, so an object reached only through a nested group counts here
    without this having to walk groups itself.
    """
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        referenced = Q(pk__in=Subquery(
            SecurityRuleSourceAddressRef.objects.filter(
                address_object__isnull=False).values("address_object_id"))
        ) | Q(pk__in=Subquery(
            SecurityRuleDestinationAddressRef.objects.filter(
                address_object__isnull=False).values("address_object_id"))
        )
        queryset = AddressObject.objects.filter(referenced) if value \
            else AddressObject.objects.exclude(referenced)
        return queryset.values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    "name": build_text_compiler("name", "name"),
    #: The kind discriminator, and the scope clause of both halves of PAN-COV-001: `edl` for the
    #: imported-list half and `fqdn` for the name-based half. The four address kinds are
    #: mutually exclusive on the device - it names the choice set in its own validation message -
    #: so this is the clause that keeps one half from reporting the other half's rows.
    "address_type": build_choice_compiler(
        "address_type", "address_type", AddressObject.ADDRESS_TYPE_CHOICES),
    "namespace_type": build_text_compiler("namespace_type", "namespace_type"),
    "is_edl": build_boolean_compiler("is_edl", "is_edl"),
    "num_hosts": build_integer_compiler("num_hosts", "num_hosts"),
    #: Did we establish a size at all. NULL means unknown, never zero - see the module
    #: docstring. Inverted because the column stores the absence, not the knowledge.
    "size_known": build_boolean_compiler("size_known", "num_hosts__isnull", invert=True),
    #: Whether the DEVICE answered about this object's content at all. True means a collection
    #: reached the device and it reported its own totals - so an object that is still unsized
    #: after that is unsized because the DEVICE could not resolve it, which is the customer's
    #: fault and not a gap in this assessment. False means nobody has asked yet. The two look
    #: identical in `num_hosts` and must not be reported as the same thing.
    "collection_attempted": build_boolean_compiler(
        "collection_attempted", "resolved_content_source_total__isnull", invert=True),
    "resolved_content_truncated": build_boolean_compiler(
        "resolved_content_truncated", "resolved_content_truncated"),
    "referenced_by_policy": build_referenced_by_policy_compiler("referenced_by_policy"),
    #: WHETHER THE FIREWALL HAS EVER FETCHED THIS LIST'S CONTENT, and the only column that tells
    #: the device's answers apart. MEASURED on pan-fw-111 2026-10-29: never fetched answers
    #: total-valid 1 with the single member `0.0.0.0/32`; a fetch that FAILED answers
    #: total-valid 0 / total-invalid 1 with the reason verbatim; a fetched list answers a real
    #: count with real members; and a fourth reply carries every counter zero with no member key
    #: at all. The first, second and fourth are all False here, because nothing in the reply
    #: separates "fetched an empty list" from "never fetched" and the unknown fires.
    #:
    #: It is the ASSERTION of PAN-COV-001's imported-list half and the APPLICABILITY of
    #: PAN-COV-002: a list nobody fetched cannot be found to be part-kept. That pair is what
    #: makes the two controls a partition rather than two chances to report one row.
    "content_was_fetched": build_boolean_compiler(
        "content_was_fetched", "content_was_fetched"),
    #: Whether this collection read the firewall's FQDN resolution table AND found a stanza for
    #: this object's name. TRUE DOES NOT MEAN THE REACH IS KNOWN - a stanza answering only AAAA,
    #: or the `::  unknown` sentinel, leaves num_hosts null with this true. What it establishes
    #: is that somebody asked, which `size_known` cannot say: it reads false for a name nobody
    #: looked up, a name looked up and answered with nothing, and a name that resolved correctly
    #: to IPv6 only - and the third of those is a healthy object.
    "resolution_was_read": build_boolean_compiler(
        "resolution_was_read", "resolution_was_read"),
    #: How far the content this collection kept falls short of what the device said the list
    #: holds, bucketed. The GRADED column of PAN-COV-002, so the severity queries clause on it.
    #: A closed choice set rather than the raw ratio on purpose: a grading over the integer
    #: range would have had to place the two sentinels stage 4 measured - total-valid 1 and
    #: total-valid 0 - and both of them sort at the gentle end of a numeric comparison while
    #: meaning the two worst-known states. Equality on a band keeps them out of it, and
    #: `content_not_fetched` is where they land.
    "content_shortfall_band": build_choice_compiler(
        "content_shortfall_band", "content_shortfall_band",
        AddressObject.CONTENT_SHORTFALL_BAND_CHOICES),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_address_object_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_address_object_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause.get("negated") else predicate
