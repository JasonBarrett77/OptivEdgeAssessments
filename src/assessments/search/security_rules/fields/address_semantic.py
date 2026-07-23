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


def supported_member_query(*, include_any=False):
    """Refs excluded from every semantic address operator regardless of the specific interval
    comparison: dynamic groups are never IP-resolvable, and is_any is opt-in via include_any.

    Deliberately does NOT gate on address_type="fqdn" or on ipv4_start_int/end_int being set -
    an EDL(ip)/FQDN object can now carry real interval data via its resolved_entries (populated
    by the "Refresh EDL/FQDN cache" action) even though its own scalar ipv4_start_int/end_int
    stay null. Each operator below combines this gate with its own "own field OR resolved_entries"
    interval comparison instead, since a single shared clause can't express both shapes at once.
    """
    predicate = ~Q(ref_type="dynamic_address_group")
    if not include_any:
        predicate &= ~Q(address_object__is_any=True)
    return predicate


def address_object_intervals(address_object) -> list[IPv4Interval]:
    """Every disjoint IPv4 interval this address object represents.

    A plain object (ip_netmask/ip_range/builtin any) uses its own scalar ipv4_start_int/end_int,
    unchanged. An EDL(ip)/FQDN object instead uses its resolved_entries - possibly several
    disjoint ranges, populated only by the "Refresh EDL/FQDN cache" action. An EDL/FQDN object
    with no resolved entries yet (never refreshed, or nothing parseable) contributes nothing,
    same as it does today.
    """
    if address_object.address_type in (AddressObject.TYPE_EDL, AddressObject.TYPE_FQDN):
        return [
            IPv4Interval(entry.ipv4_start_int, entry.ipv4_end_int)
            for entry in address_object.resolved_entries.all()
        ]
    if address_object.ipv4_start_int is not None and address_object.ipv4_end_int is not None:
        return [IPv4Interval(address_object.ipv4_start_int, address_object.ipv4_end_int)]
    return []


def member_covers_query(interval: IPv4Interval, *, include_any=False):
    own_covers = (
        Q(address_object__ipv4_start_int__isnull=False)
        & Q(address_object__ipv4_end_int__isnull=False)
        & Q(address_object__ipv4_start_int__lte=interval.start)
        & Q(address_object__ipv4_end_int__gte=interval.end)
    )
    resolved_entry_covers = Q(address_object__resolved_entries__ipv4_start_int__lte=interval.start) & Q(
        address_object__resolved_entries__ipv4_end_int__gte=interval.end
    )
    return supported_member_query(include_any=include_any) & (own_covers | resolved_entry_covers)


def member_equals_query(interval: IPv4Interval, *, include_any=False):
    own_equals = Q(address_object__ipv4_start_int=interval.start) & Q(
        address_object__ipv4_end_int=interval.end
    )
    resolved_entry_equals = Q(address_object__resolved_entries__ipv4_start_int=interval.start) & Q(
        address_object__resolved_entries__ipv4_end_int=interval.end
    )
    return supported_member_query(include_any=include_any) & (own_equals | resolved_entry_equals)


def member_intersects_query(interval: IPv4Interval, *, include_any=False):
    own_intersects = (
        Q(address_object__ipv4_start_int__isnull=False)
        & Q(address_object__ipv4_end_int__isnull=False)
        & Q(address_object__ipv4_start_int__lte=interval.end)
        & Q(address_object__ipv4_end_int__gte=interval.start)
    )
    resolved_entry_intersects = Q(address_object__resolved_entries__ipv4_start_int__lte=interval.end) & Q(
        address_object__resolved_entries__ipv4_end_int__gte=interval.start
    )
    return supported_member_query(include_any=include_any) & (own_intersects | resolved_entry_intersects)


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

    if op == "includes":
        predicate = member_covers_query(interval, include_any=include_any)
        return model_class.objects.filter(predicate).values("security_rule_id")

    if op == "exactly":
        predicate = member_equals_query(interval, include_any=include_any)
        return model_class.objects.filter(predicate).values("security_rule_id")

    if op == "intersects":
        predicate = member_intersects_query(interval, include_any=include_any)
        return model_class.objects.filter(predicate).values("security_rule_id")

    matching_rule_ids = []
    queryset = (
        model_class.objects.select_related("security_rule", "address_object")
        .prefetch_related("address_object__resolved_entries")
        .filter(
            Q(address_object__ipv4_start_int__isnull=False, address_object__ipv4_end_int__isnull=False)
            | Q(address_object__resolved_entries__isnull=False)
        )
        .exclude(ref_type=model_class.RefType.DYNAMIC_ADDRESS_GROUP)
        .order_by("security_rule_id", "position", "id")
        .distinct()
    )
    if not include_any:
        queryset = queryset.exclude(address_object__is_any=True)

    intervals_by_rule_id: dict[int, list[IPv4Interval]] = {}
    for ref in queryset:
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
