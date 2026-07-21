"""One-off diagnostic script - run via: python manage.py shell < diagnose_security_rule_cache.py

Isolates the Security Rules caching logic from the HTTP/template layer to see directly
whether the cache is being hit, how big the underlying data is, and where time is going.
Safe to delete after use - makes no changes to any data.
"""
import time

from django.core.cache import cache
from django.db import connection

from assessments.security_rule_queries import (
    _security_rule_freshness_fingerprint,
    get_cached_security_rule_pks,
)
from optivedge_integrations.integrations.models import IntegrationRun, SecurityRule

print("=" * 60)
print(f"Total SecurityRule rows: {SecurityRule.objects.count()}")
print(f"Total IntegrationRun rows: {IntegrationRun.objects.count()}")
print(f"Most recent completed IntegrationRun: "
      f"{IntegrationRun.objects.filter(status__in=[IntegrationRun.STATUS_SUCCEEDED, IntegrationRun.STATUS_PARTIAL]).order_by('-completed_at').values_list('completed_at', flat=True).first()}")

fingerprint_1 = _security_rule_freshness_fingerprint()
print(f"\nFreshness fingerprint (call 1): {fingerprint_1}")

connection.queries_log.clear()
t0 = time.perf_counter()
pks_1 = get_cached_security_rule_pks()
t1 = time.perf_counter()
print(f"get_cached_security_rule_pks() call 1: {t1 - t0:.3f}s, {len(pks_1)} pks, "
      f"{len(connection.queries_log)} queries issued")

fingerprint_2 = _security_rule_freshness_fingerprint()
print(f"\nFreshness fingerprint (call 2, should match call 1): {fingerprint_2}")
print(f"Fingerprints match: {fingerprint_1 == fingerprint_2}")

connection.queries_log.clear()
t0 = time.perf_counter()
pks_2 = get_cached_security_rule_pks()
t1 = time.perf_counter()
print(f"get_cached_security_rule_pks() call 2 (should be a cache hit): {t1 - t0:.3f}s, "
      f"{len(pks_2)} pks, {len(connection.queries_log)} queries issued")

print(f"\npks_1 == pks_2: {pks_1 == pks_2}")

cache_key = f"assessments:security_rule_pks:{fingerprint_1}"
print(f"\nDirect cache.get() for key {cache_key!r}: "
      f"{'HIT' if cache.get(cache_key) is not None else 'MISS'}")
print("=" * 60)
