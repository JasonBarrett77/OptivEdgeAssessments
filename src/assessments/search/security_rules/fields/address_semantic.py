"""Semantic compiler helpers for security-rule address fields."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from django.db.models import Q

from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import AddressObject


SUPPORTED_OPERATORS = {"matches", "includes", "exactly", "intersects", "equals"}


IPV4_ANY_END = 4_294_967_295


@dataclass(frozen=True)
class IPv4Interval:
    start: int
    end: int

    @property
    def is_contiguous(self) -> bool:
        return self.start <= self.end


def parse_ipv4_query_value(field_name: str, value) -> IPv4Interval:
    if not isinstance(value, str):
        raise SearchSyntaxError(f"{field_name} search value must be a string.")

    trimmed_value = value.strip()
    if not trimmed_value:
        raise SearchSyntaxError(f"{field_name} search value must not be empty.")

    lowered_value = trimmed_value.lower()
    if lowered_value == "any":
        return IPv4Interval(0, IPV4_ANY_END)

    if "-" in trimmed_value:
        start_text, end_text = trimmed_value.split("-", 1)
        try:
            start_ip = ipaddress.IPv4Address(start_text.strip())
            end_ip = ipaddress.IPv4Address(end_text.strip())
        except ipaddress.AddressValueError as exc:
            raise SearchSyntaxError(f"{field_name} IPv4 range is invalid.") from exc
        start = int(start_ip)
        end = int(end_ip)
        if start > end:
            raise SearchSyntaxError(f"{field_name} IPv4 range start must not exceed end.")
        return IPv4Interval(start, end)

    try:
        if "/" in trimmed_value:
            network = ipaddress.IPv4Network(trimmed_value, strict=False)
            return IPv4Interval(int(network.network_address), int(network.broadcast_address))
        host = ipaddress.IPv4Address(trimmed_value)
        host_int = int(host)
        return IPv4Interval(host_int, host_int)
    except ipaddress.AddressValueError as exc:
        raise SearchSyntaxError(
            f"{field_name} semantic address queries currently support IPv4 host, CIDR, range, or 'any'."
        ) from exc
    except ipaddress.NetmaskValueError as exc:
        raise SearchSyntaxError(f"{field_name} IPv4 CIDR is invalid.") from exc


def _negate_field_name(model_class) -> str:
    """Which SecurityRule boolean field governs this ref model's negation state."""
    return "negate_source" if "Source" in model_class.__name__ else "negate_destination"


def _negated_complement_gate(negate_field: str) -> Q:
    """Excludes a negated rule's ORIGINAL (excluded-member) refs from positive semantic
    matching - those represent what's NOT allowed, not what is. Only a synthetic
    negated-complement ref (materialized at normalize time when the complement was
    computable) is let through for a negated rule; if no complement was computed, every ref
    on that rule/side fails this gate, so the rule is safely excluded from semantic matching
    entirely rather than matched backwards. A no-op for non-negated rules (first branch)."""
    return Q(**{f"security_rule__{negate_field}": False}) | Q(
        address_object__is_synthetic=True,
        address_object__synthetic_kind=AddressObject.SYNTHETIC_KIND_NEGATED_COMPLEMENT,
    )


def supported_member_query(*, include_any=False, negate_field: str):
    """Refs excluded from every semantic address operator regardless of the specific interval
    comparison: dynamic groups are never IP-resolvable, is_any is opt-in via include_any, and
    a negated rule's original member refs are excluded per _negated_complement_gate().

    Deliberately does NOT gate on address_type="fqdn" or on ipv4_start_int/end_int being set -
    an EDL(ip)/FQDN object can now carry real interval data via its resolved_entries (populated
    by the "Refresh EDL/FQDN cache" action) even though its own scalar ipv4_start_int/end_int
    stay null. Each operator below combines this gate with its own "own field OR resolved_entries"
    interval comparison instead, since a single shared clause can't express both shapes at once.
    """
    predicate = ~Q(ref_type="dynamic_address_group") & _negated_complement_gate(negate_field)
    if not include_any:
        predicate &= ~Q(address_object__is_any=True)
    return predicate


def address_object_intervals(address_object) -> list[IPv4Interval]:
    """Every disjoint IPv4 interval this address object represents.

    Checks resolved_entries first, regardless of address_type - covers EDL(ip)/FQDN objects
    (populated only by the "Refresh EDL/FQDN cache" action) and negated-complement objects
    (populated at rule-normalization time, possibly several disjoint ranges) via the same
    mechanism. Falls back to the object's own scalar ipv4_start_int/end_int for a plain object
    (ip_netmask/ip_range/builtin any), unchanged. An object with neither (e.g. an EDL/FQDN never
    refreshed) contributes nothing, same as it does today.
    """
    resolved_entries = list(address_object.resolved_entries.all())
    if resolved_entries:
        return [
            IPv4Interval(entry.ipv4_start_int, entry.ipv4_end_int)
            for entry in resolved_entries
        ]
    if address_object.ipv4_start_int is not None and address_object.ipv4_end_int is not None:
        return [IPv4Interval(address_object.ipv4_start_int, address_object.ipv4_end_int)]
    return []


def member_covers_query(interval: IPv4Interval, *, include_any=False, negate_field: str):
    own_covers = (
        Q(address_object__ipv4_start_int__isnull=False)
        & Q(address_object__ipv4_end_int__isnull=False)
        & Q(address_object__ipv4_start_int__lte=interval.start)
        & Q(address_object__ipv4_end_int__gte=interval.end)
    )
    resolved_entry_covers = Q(address_object__resolved_entries__ipv4_start_int__lte=interval.start) & Q(
        address_object__resolved_entries__ipv4_end_int__gte=interval.end
    )
    return supported_member_query(include_any=include_any, negate_field=negate_field) & (
        own_covers | resolved_entry_covers
    )


def member_equals_query(interval: IPv4Interval, *, include_any=False, negate_field: str):
    own_equals = Q(address_object__ipv4_start_int=interval.start) & Q(
        address_object__ipv4_end_int=interval.end
    )
    resolved_entry_equals = Q(address_object__resolved_entries__ipv4_start_int=interval.start) & Q(
        address_object__resolved_entries__ipv4_end_int=interval.end
    )
    return supported_member_query(include_any=include_any, negate_field=negate_field) & (
        own_equals | resolved_entry_equals
    )


def member_intersects_query(interval: IPv4Interval, *, include_any=False, negate_field: str):
    own_intersects = (
        Q(address_object__ipv4_start_int__isnull=False)
        & Q(address_object__ipv4_end_int__isnull=False)
        & Q(address_object__ipv4_start_int__lte=interval.end)
        & Q(address_object__ipv4_end_int__gte=interval.start)
    )
    resolved_entry_intersects = Q(address_object__resolved_entries__ipv4_start_int__lte=interval.end) & Q(
        address_object__resolved_entries__ipv4_end_int__gte=interval.start
    )
    return supported_member_query(include_any=include_any, negate_field=negate_field) & (
        own_intersects | resolved_entry_intersects
    )


def normalize_and_merge(intervals: list[IPv4Interval]) -> list[IPv4Interval]:
    if not intervals:
        return []
    sorted_intervals = sorted(intervals, key=lambda interval: (interval.start, interval.end))
    merged = [sorted_intervals[0]]
    for interval in sorted_intervals[1:]:
        current = merged[-1]
        if interval.start <= current.end + 1:
            merged[-1] = IPv4Interval(current.start, max(current.end, interval.end))
            continue
        merged.append(interval)
    return merged


def compile_semantic_address_clause(
    clause,
    *,
    model_class,
    field_name,
):
    op = clause["op"]
    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")

    interval = parse_ipv4_query_value(field_name, clause["value"])
    include_any = clause.get("include_any", False)
    negate_field = _negate_field_name(model_class)

    if op == "includes":
        predicate = member_covers_query(interval, include_any=include_any, negate_field=negate_field)
        return model_class.objects.filter(predicate).values("security_rule_id")

    if op == "exactly":
        predicate = member_equals_query(interval, include_any=include_any, negate_field=negate_field)
        return model_class.objects.filter(predicate).values("security_rule_id")

    if op == "intersects":
        predicate = member_intersects_query(interval, include_any=include_any, negate_field=negate_field)
        return model_class.objects.filter(predicate).values("security_rule_id")

    matching_rule_ids = []

    # 'matches' (query interval covered by the union of a rule's members) and 'equals' (a
    # rule's merged interval equals the query exactly) can't be expressed in SQL, so they are
    # evaluated in Python. Rather than materialize every IP-resolvable ref in the dataset
    # (O(all refs), independent of selectivity), restrict the set to only the refs that can
    # possibly matter:
    #   - matches: a member that does not intersect the query interval can never contribute to
    #     covering it, so only intersecting members are needed - identical result, far less data.
    #   - equals: exact equality depends on all of a candidate rule's members, but only rules
    #     with a member intersecting the query can equal it, so load the full member set of just
    #     those candidate rules.
    intersecting_gate = member_intersects_query(
        interval, include_any=include_any, negate_field=negate_field
    )
    if op == "matches":
        member_refs = (
            model_class.objects.filter(intersecting_gate)
            .select_related("address_object")
            .prefetch_related("address_object__resolved_entries")
            .order_by("security_rule_id", "position", "id")
            .distinct()
        )
    else:  # equals
        candidate_rule_ids = list(
            model_class.objects.filter(intersecting_gate)
            .values_list("security_rule_id", flat=True)
            .distinct()
        )
        member_refs = (
            model_class.objects.filter(
                supported_member_query(include_any=include_any, negate_field=negate_field),
                security_rule_id__in=candidate_rule_ids,
            )
            .filter(
                Q(address_object__ipv4_start_int__isnull=False, address_object__ipv4_end_int__isnull=False)
                | Q(address_object__resolved_entries__isnull=False)
            )
            .select_related("address_object")
            .prefetch_related("address_object__resolved_entries")
            .order_by("security_rule_id", "position", "id")
            .distinct()
        )

    intervals_by_rule_id: dict[int, list[IPv4Interval]] = {}
    for ref in member_refs:
        address_object = ref.address_object
        if address_object is None:
            continue
        intervals_by_rule_id.setdefault(ref.security_rule_id, []).extend(
            address_object_intervals(address_object)
        )

    for rule_id, member_intervals in intervals_by_rule_id.items():
        merged_intervals = normalize_and_merge(member_intervals)

        if op == "matches":
            if not merged_intervals:
                continue
            cursor = interval.start
            fully_covered = True
            for merged_interval in merged_intervals:
                if merged_interval.end < cursor:
                    continue
                if merged_interval.start > cursor:
                    fully_covered = False
                    break
                cursor = merged_interval.end + 1
                if cursor > interval.end:
                    break
            if fully_covered and cursor > interval.end:
                matching_rule_ids.append(rule_id)
            continue

        if op == "equals":
            if len(merged_intervals) != 1:
                continue
            only_interval = merged_intervals[0]
            if only_interval.start == interval.start and only_interval.end == interval.end:
                matching_rule_ids.append(rule_id)

    return model_class.objects.filter(security_rule_id__in=matching_rule_ids).values("security_rule_id")
