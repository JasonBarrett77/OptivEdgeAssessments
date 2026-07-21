"""One-off diagnostic module for the Security Rules page performance investigation.

Isolates the security_rule_queries caching logic from the HTTP/template layer to see
directly whether the cache is being hit, how big the underlying data is, and where time
is going. Read-only - makes no changes to any data. Not meant to be permanent tooling;
delete once the investigation is done.

Usage (after `pip install --force-reinstall ...` picks this up):
    python manage.py shell -c "from assessments.diagnose_security_rule_cache import run; run()"
    python manage.py shell -c "from assessments.diagnose_security_rule_cache import run_page_diagnosis; run_page_diagnosis()"
"""
from __future__ import annotations

import time

from django.core.cache import cache
from django.db import connection

from assessments.security_rule_queries import (
    _security_rule_freshness_fingerprint,
    get_cached_security_rule_pks,
)
from optivedge_integrations.integrations.models import IntegrationRun, SecurityRule


def run() -> None:
    # Force query logging on regardless of settings.DEBUG, so this works without
    # needing to flip DEBUG and restart the server.
    connection.force_debug_cursor = True

    print("=" * 60)
    print(f"Total SecurityRule rows: {SecurityRule.objects.count()}")
    print(f"Total IntegrationRun rows: {IntegrationRun.objects.count()}")
    print(
        "Most recent completed IntegrationRun: "
        f"{IntegrationRun.objects.filter(status__in=[IntegrationRun.STATUS_SUCCEEDED, IntegrationRun.STATUS_PARTIAL]).order_by('-completed_at').values_list('completed_at', flat=True).first()}"
    )

    fingerprint_1 = _security_rule_freshness_fingerprint()
    print(f"\nFreshness fingerprint (call 1): {fingerprint_1}")

    connection.queries_log.clear()
    t0 = time.perf_counter()
    pks_1 = get_cached_security_rule_pks()
    t1 = time.perf_counter()
    print(
        f"get_cached_security_rule_pks() call 1: {t1 - t0:.3f}s, {len(pks_1)} pks, "
        f"{len(connection.queries_log)} queries issued"
    )

    fingerprint_2 = _security_rule_freshness_fingerprint()
    print(f"\nFreshness fingerprint (call 2, should match call 1): {fingerprint_2}")
    print(f"Fingerprints match: {fingerprint_1 == fingerprint_2}")

    connection.queries_log.clear()
    t0 = time.perf_counter()
    pks_2 = get_cached_security_rule_pks()
    t1 = time.perf_counter()
    print(
        f"get_cached_security_rule_pks() call 2 (should be a cache hit): {t1 - t0:.3f}s, "
        f"{len(pks_2)} pks, {len(connection.queries_log)} queries issued"
    )

    print(f"\npks_1 == pks_2: {pks_1 == pks_2}")

    cache_key = f"assessments:security_rule_pks:{fingerprint_1}"
    print(
        f"\nDirect cache.get() for key {cache_key!r}: "
        f"{'HIT' if cache.get(cache_key) is not None else 'MISS'}"
    )
    print("=" * 60)


def run_page_diagnosis(page_size: int = 100) -> None:
    """Breaks down where time goes in rendering one page of results - since run() above
    proves the pk-list caching itself is fast, this isolates the next step: fetching and
    rendering the ~100 displayed rows (the live filter(pk__in=...) + prefetch_related
    queries, the Python row-shaping, and full end-to-end template rendering)."""
    from django.test import Client
    from django.urls import reverse

    from assessments.security_rule_queries import build_security_rule_display_queryset
    from assessments.views import build_security_rule_rows
    from optivedge_integrations.integrations.models import (
        SecurityRuleApplication,
        SecurityRuleDestinationAddressRef,
        SecurityRuleFromZone,
        SecurityRuleProfile,
        SecurityRuleProfileGroup,
        SecurityRuleService,
        SecurityRuleSourceAddressRef,
        SecurityRuleToZone,
    )

    connection.force_debug_cursor = True

    pks = get_cached_security_rule_pks()
    page_pks = pks[:page_size]
    print(f"\n--- Page-render diagnosis (first {len(page_pks)} of {len(pks)} pks) ---")

    connection.queries_log.clear()
    t0 = time.perf_counter()
    list(SecurityRule.objects.filter(pk__in=page_pks))
    t1 = time.perf_counter()
    print(f"Bare fetch, no select_related/prefetch: {t1 - t0:.3f}s, {len(connection.queries_log)} queries")

    connection.queries_log.clear()
    t0 = time.perf_counter()
    list(
        SecurityRule.objects.filter(pk__in=page_pks).select_related(
            "management_station", "enforcement_point", "enforcement_point__appliance_group", "source_snapshot",
        )
    )
    t1 = time.perf_counter()
    print(f"select_related only, no prefetch: {t1 - t0:.3f}s, {len(connection.queries_log)} queries")

    connection.queries_log.clear()
    t0 = time.perf_counter()
    full_rules = list(build_security_rule_display_queryset().filter(pk__in=page_pks))
    t1 = time.perf_counter()
    print(f"Full display queryset (select_related + prefetch_related, matches real page load): {t1 - t0:.3f}s, {len(connection.queries_log)} queries")

    print("\nChild row counts for this page's rules only (spot a disproportionately large relation):")
    for label, model in [
        ("securityrulefromzones", SecurityRuleFromZone),
        ("securityruletozones", SecurityRuleToZone),
        ("source_address_refs", SecurityRuleSourceAddressRef),
        ("destination_address_refs", SecurityRuleDestinationAddressRef),
        ("securityruleapplications", SecurityRuleApplication),
        ("securityruleservices", SecurityRuleService),
        ("securityruleprofilegroups", SecurityRuleProfileGroup),
        ("securityruleprofiles", SecurityRuleProfile),
    ]:
        print(f"  {label}: {model.objects.filter(security_rule_id__in=page_pks).count()}")

    t0 = time.perf_counter()
    rows = build_security_rule_rows(full_rules)
    t1 = time.perf_counter()
    print(f"\nbuild_security_rule_rows() (Python row-shaping only): {t1 - t0:.3f}s")

    print("\nFull end-to-end request via Django test client (DB + view + template render):")
    connection.queries_log.clear()
    client = Client()
    t0 = time.perf_counter()
    response = client.get(reverse("assessment_security_rule_list"))
    t1 = time.perf_counter()
    print(f"  {response.status_code}, {t1 - t0:.3f}s, {len(connection.queries_log)} queries")

    print("\n--- end page-render diagnosis ---")
