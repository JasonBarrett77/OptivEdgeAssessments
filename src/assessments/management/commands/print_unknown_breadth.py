"""Which rule sides PAN-POL-002 could not size, and which member made each one unmeasurable.

WHY THIS EXISTS. PAN-POL-002 grades a rule on how much address space it exposes, and reports an
INDETERMINATE side at medium rather than saying nothing - *"A side's breadth could not be
established"*. The surfaces then print `(Unknown addresses)` under the side's member names, which
says that the side could not be sized and nothing at all about WHICH member stopped it. Jason, on
a production estate 2026-11-12: *"I am seeing findings for PAN-POL-002 that aren't making
sense... in sources I see address objects followed by '(Unknown addresses)'. Three of the objects
are ip_netmask kind, one object is an ip_range kind. Their values look normal."* Four members that
all look sizable and a side that was not sized is a question the document cannot answer, and
guessing at it from the shape of the finding is how a real defect gets explained away.

WHAT IT PRINTS. Every rule side whose host count is null, the members behind it, and for each
member the reason it contributes no interval - a dynamic address group, a region, an object with
no IPv4 extent, or content truncated at the collection ceiling. A side with NO such member is
called out on its own, because it is a different fault: either the side has no member at all, or
it is negated and its complement computed to nothing, which is a side that permits NOTHING being
reported as a side nobody could measure.

WHY IT IS A COMMAND. The answer is about one estate's data, and the lab cannot stand in for a
production estate - its 30 unsized sides are all regions, dynamic groups, EDLs and one negated
rule, so it cannot show a shape it does not have. The same reasoning as
`print_unattributed_findings`, and the same shape.

    python manage.py print_unknown_breadth
    python manage.py print_unknown_breadth --name "Range _172" --sides 0

THE ATTRIBUTION IS THE NORMALIZER'S OWN. `_member_intervals_or_none` is the function that
decided these counts when the rules were normalized, and it is called here on the STORED ref rows
rather than reimplemented - a stored `SecurityRuleSourceAddressRef` carries the `ref_type` and
`address_object` it reads. A second definition of "can this member be sized" that disagreed with
the one that produced the number would explain the wrong thing convincingly.

IT ONLY READS. No row is written, no appliance is touched, nothing is collected.
"""

from __future__ import annotations

from collections import Counter

from django.core.management.base import BaseCommand

#: What `_member_intervals_or_none` returning None means, in the words the control uses. Keyed by
#: the ref's own type where the type is the answer, and worked out from the object otherwise.
DYNAMIC_GROUP = "a dynamic address group - its membership is not knowable from the configuration"
REGION = "a region - the addresses behind it are not in the configuration"
NO_OBJECT = "a ref with no address object behind it, which the model should not allow"
TRUNCATED = "content truncated at the collection ceiling, so the set is a known under-count"
NEVER_FETCHED = "an {kind} whose content this firewall has never fetched"
FETCH_FAILED = "an {kind} the device answered about and could not resolve"
NO_EXTENT = "an {kind} object with no IPv4 extent: value {value!r}"

#: And the two faults that are NOT a member. Either is a side the surfaces call unmeasurable when
#: something else is true of it.
NO_MEMBERS = "the side has no member at all, so there was nothing to size"
NEGATED_EMPTY = ("negated over the whole address space: the complement is empty, so the rule "
                 "permits NOTHING - which is 0 addresses, not an unknown number")
UNEXPLAINED = ("every member sizes, the side is not negated, and it is still null - a defect "
               "in the count rather than in the configuration")


def member_reason(ref) -> str:
    """Why this ref contributes no interval. Call it only on a ref that contributes none."""
    from optivedge_integrations.integrations.models import (
        AddressObject, SecurityRuleAddressRef)

    if ref.ref_type == SecurityRuleAddressRef.RefType.DYNAMIC_ADDRESS_GROUP:
        return DYNAMIC_GROUP
    if ref.ref_type == SecurityRuleAddressRef.RefType.REGION:
        return REGION
    address_object = ref.address_object
    if address_object is None:
        return NO_OBJECT
    if address_object.resolved_content_truncated:
        return TRUNCATED
    kind = address_object.get_address_type_display()
    if address_object.address_type in (AddressObject.TYPE_EDL, AddressObject.TYPE_FQDN):
        if not address_object.collection_attempted:
            return NEVER_FETCHED.format(kind=kind)
        return FETCH_FAILED.format(kind=kind)
    return NO_EXTENT.format(kind=kind, value=address_object.value)


#: HOW THE RULES ARE FOUND, and it is PAN-POL-002's own question rather than a second one. This
#: is the breadth half of the `A side's breadth could not be established` query's
#: `canonical_query`, verbatim; `test_the_query_is_the_controls_own` asserts it still matches
#: what the catalogue ships, so the two cannot drift apart unnoticed.
#:
#: The query's three SCOPE clauses - allow, not a default rule, not disabled - are deliberately
#: NOT here. A deny rule with an unsized side is the same fault in the same data and worth
#: seeing while chasing one; the per-side line says whether a PAN-POL-002 finding exists, which
#: is the scope question answered where it matters.
#:
#: IT GOES THROUGH THE SEARCH SERVICE, which is not a formality. `source_breadth_known` is a
#: search field with no column behind it - it compiles to `source_num_hosts__isnull` - so the
#: service is where the question "did we establish this side's breadth" is defined, and asking
#: it here any other way would be this command deciding privately what the control decided
#: publicly. `test_query_service_boundary` enforces exactly that.
BREADTH_UNKNOWN = {
    "model": "integrations.SecurityRule",
    "operator": "or",
    "clauses": [
        {"field": "source_breadth_known", "op": "eq", "value": False},
        {"field": "destination_breadth_known", "op": "eq", "value": False},
    ],
}


def unsized_sides(name: str = ""):
    """Every rule side with a null host count, as (rule, side, negated, refs, reasons).

    `reasons` is one entry per member that contributes no interval, in member order. It is EMPTY
    for a side nothing is wrong with member by member, which is the case worth reading.
    """
    from assessments.search.compiler import apply_search_node
    from optivedge_integrations.integrations.models import SecurityRule
    from optivedge_integrations.integrations.platforms.pan_os.normalization.security_rules import (
        _member_intervals_or_none)

    rules = apply_search_node(
        (SecurityRule.objects.all()
         .select_related("enforcement_point", "enforcement_point__appliance",
                         "enforcement_point__management_station")
         .prefetch_related("source_address_refs__address_object",
                           "destination_address_refs__address_object",
                           "source_address_refs__address_group",
                           "destination_address_refs__address_group")),
        BREADTH_UNKNOWN,
    ).order_by("enforcement_point_id", "effective_order", "rule_position")
    for rule in rules:
        for side, count, refs, negated in (
                ("source", rule.source_num_hosts, rule.source_address_refs.all(),
                 rule.negate_source),
                ("destination", rule.destination_num_hosts, rule.destination_address_refs.all(),
                 rule.negate_destination)):
            if count is not None:
                continue
            refs = list(refs)
            if name and name.lower() not in rule.name.lower() and not any(
                    name.lower() in ref.raw_value.lower() for ref in refs):
                continue
            reasons = [(ref, member_reason(ref)) for ref in refs
                       if _member_intervals_or_none(ref) is None]
            yield rule, side, negated, refs, reasons


def side_fault(negated: bool, refs: list, reasons: list) -> str:
    """The one line that says what is wrong with a side, where no member is."""
    if reasons:
        return reasons[0][1]
    if not refs:
        return NO_MEMBERS
    if negated:
        return NEGATED_EMPTY
    return UNEXPLAINED


def where(rule) -> str:
    point = rule.enforcement_point
    appliance = point.appliance
    station = point.management_station
    held_by = (appliance.hostname or appliance.serial_number) if appliance else (
        station.name if station else "an enforcement point naming no device")
    return f"{held_by} {point.vsys_name}"


class Command(BaseCommand):
    help = ("Report every rule side PAN-POL-002 could not size, and the member that made each "
            "one unmeasurable. Reads only.")

    def add_arguments(self, parser):
        parser.add_argument(
            "--sides", type=int, default=10,
            help="how many sides to describe in full (default 10, 0 for all)")
        parser.add_argument(
            "--name", default="",
            help="only sides whose rule or whose member names contain this text")

    def handle(self, *args, **options):
        from assessments.models import RuleFinding

        sides = list(unsized_sides(options["name"]))
        if not sides:
            self.stdout.write(self.style.SUCCESS(
                "Every side of every rule was sized, so PAN-POL-002 reports no "
                "indeterminate side here."))
            return

        faults = Counter()
        for _rule, _side, negated, refs, reasons in sides:
            faults[side_fault(negated, refs, reasons)] += 1
        rules = len({rule.pk for rule, *_rest in sides})
        self.stdout.write(f"rule sides with no host count: {len(sides):,} over {rules:,} rules")
        self.stdout.write("\nby cause, one per side:")
        for fault, count in faults.most_common():
            self.stdout.write(f"  {count:>6,}  {fault}")

        graded = set(RuleFinding.objects
                     .filter(control__control_id="PAN-POL-002",
                             security_rule_id__in=[rule.pk for rule, *_rest in sides])
                     .values_list("security_rule_id", flat=True))
        self.stdout.write(f"\nof those rules, {len(graded):,} carry a PAN-POL-002 finding")

        listed = sides if not options["sides"] else sides[:options["sides"]]
        self.stdout.write(f"\n{len(listed)} of {len(sides)} sides in full:")
        for rule, side, negated, refs, reasons in listed:
            self.stdout.write(
                f"\n  {where(rule)}  {rule.name!r}  {side}"
                + ("  NEGATED" if negated else "")
                + ("" if rule.pk in graded else "  (no PAN-POL-002 finding)"))
            unsizable = {id(ref) for ref, _reason in reasons}
            for ref in refs:
                mark = "unsized" if id(ref) in unsizable else "  sized"
                address_object = ref.address_object
                detail = (f"{address_object.address_type} {address_object.value!r} "
                          f"num_hosts={address_object.num_hosts}"
                          if address_object else f"no object, ref_type={ref.ref_type}")
                self.stdout.write(f"      {mark}  {ref.raw_value!r}  {detail}")
            self.stdout.write(f"      -> {side_fault(negated, refs, reasons)}")
