"""Semantic compiler helpers for security-rule address fields."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from django.db.models import Q

from assessments.search.exceptions import SearchSyntaxError


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
    predicate = (
        Q(address_object__ipv4_start_int__isnull=False)
        & Q(address_object__ipv4_end_int__isnull=False)
        & ~Q(address_object__address_type="fqdn")
        & ~Q(ref_type="dynamic_address_group")
    )
    if not include_any:
        predicate &= ~Q(address_object__is_any=True)
    return predicate


def member_covers_query(interval: IPv4Interval, *, include_any=False):
    return (
        supported_member_query(include_any=include_any)
        & Q(address_object__ipv4_start_int__lte=interval.start)
        & Q(address_object__ipv4_end_int__gte=interval.end)
    )


def member_equals_query(interval: IPv4Interval, *, include_any=False):
    return (
        supported_member_query(include_any=include_any)
        & Q(address_object__ipv4_start_int=interval.start)
        & Q(address_object__ipv4_end_int=interval.end)
    )


def member_intersects_query(interval: IPv4Interval, *, include_any=False):
    return (
        supported_member_query(include_any=include_any)
        & Q(address_object__ipv4_start_int__lte=interval.end)
        & Q(address_object__ipv4_end_int__gte=interval.start)
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
        .filter(
            address_object__ipv4_start_int__isnull=False,
            address_object__ipv4_end_int__isnull=False,
        )
        .exclude(address_object__address_type="fqdn")
        .exclude(ref_type=model_class.RefType.DYNAMIC_ADDRESS_GROUP)
        .order_by("security_rule_id", "position", "id")
    )
    if not include_any:
        queryset = queryset.exclude(address_object__is_any=True)

    intervals_by_rule_id: dict[int, list[IPv4Interval]] = {}
    for ref in queryset:
        address_object = ref.address_object
        if address_object is None:
            continue
        if address_object.ipv4_start_int is None or address_object.ipv4_end_int is None:
            continue
        intervals_by_rule_id.setdefault(ref.security_rule_id, []).append(
            IPv4Interval(address_object.ipv4_start_int, address_object.ipv4_end_int)
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
