"""Shared SecurityRule queryset construction and caching.

Centralizes how the display-ready SecurityRule queryset is built (select_related,
prefetch_related, ordering) so callers stay consistent instead of hand-maintaining
separate copies that can drift.
"""

from __future__ import annotations

from django.core.cache import cache
from django.db.models import Max, QuerySet

from optivedge_integrations.integrations.models import IntegrationRun, SecurityRule

# Relation paths every SecurityRule display consumer (list view, workbook export) should
# eager-load. Kept as a named constant so both call sites visibly draw from the same set
# rather than drifting the way the workbook export previously did (missing profile
# groups/profiles that the list view included).
SECURITY_RULE_DISPLAY_PREFETCH_RELATIONS = (
    "securityrulefromzones",
    "securityruletozones",
    "source_address_refs__address_object",
    "source_address_refs__address_group",
    "destination_address_refs__address_object",
    "destination_address_refs__address_group",
    "securityruleapplications",
    "securityruleservices",
    "securityruleprofilegroups",
    "securityruleprofiles",
)


def build_security_rule_display_queryset() -> QuerySet:
    """Return the standard, fully-optimized SecurityRule queryset used for display.

    Ordering is by the FK id columns (management_station_id, enforcement_point_id)
    rather than dereferenced joined string columns (hostname/vsys_name) - same visual
    grouping, but satisfiable with a single composite index on SecurityRule alone
    instead of forcing a join purely to sort.
    """
    return (
        SecurityRule.objects.select_related(
            "management_station",
            "enforcement_point",
            "enforcement_point__appliance_group",
            "source_snapshot",
        )
        .prefetch_related(*SECURITY_RULE_DISPLAY_PREFETCH_RELATIONS)
        .order_by(
            "management_station_id",
            "enforcement_point_id",
            "effective_order",
            "name",
            "pk",
        )
    )


_PK_CACHE_KEY_PREFIX = "assessments:security_rule_pks"


def _security_rule_freshness_fingerprint() -> str:
    """A value that changes whenever a sync/renormalize could have altered SecurityRule
    rows, derived from the same IntegrationRun tracking already used to surface sync
    status in the UI. No TTL is needed for the cache built on top of this - a new
    fingerprint after the next completed run naturally produces a new cache key, so
    stale entries just go unused rather than needing active invalidation."""
    latest_completed = IntegrationRun.objects.filter(
        status__in=[IntegrationRun.STATUS_SUCCEEDED, IntegrationRun.STATUS_PARTIAL],
    ).aggregate(Max("completed_at"))["completed_at__max"]
    return latest_completed.isoformat() if latest_completed else "never"


def get_cached_security_rule_pks() -> list[int]:
    """Return every SecurityRule pk in canonical display order, cached until the next
    completed sync/renormalize changes the freshness fingerprint.

    Only valid for the unfiltered base listing - callers applying a search or control
    filter should query live instead, since caching per-filter-shape has no natural
    reuse and would grow unbounded.
    """
    cache_key = f"{_PK_CACHE_KEY_PREFIX}:{_security_rule_freshness_fingerprint()}"
    pks = cache.get(cache_key)
    if pks is None:
        pks = list(build_security_rule_display_queryset().values_list("pk", flat=True))
        cache.set(cache_key, pks, timeout=None)
    return pks
