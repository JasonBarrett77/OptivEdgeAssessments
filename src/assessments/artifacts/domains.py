"""The findings domains, in one order, for every surface that presents them.

The workbook has a tab per domain and the app has a page per domain, and they are the same
list: `workbook.SHEETS` builds its findings tabs from this, and the views route on it. The
order is the Summary's - by PAN-OS category, and within a category in `finding_run.GENERATORS`
order (Jason, 2026-09-21) - so a domain added here appears in both places, in the same place,
without anyone remembering the second one.

**Slugs are explicit rather than derived from the title.** A title is the vendor's word for the
object and can be renamed to follow a PAN-OS release; a slug is a URL someone has bookmarked.
That is the same argument `configuration_navigation` makes for its own slugs.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from django.db.models import Count

from assessments.models import Control

from .sheets import authentication_settings, management_crypto, objects, password_complexity
from .sheets import security_rules
from .sheets.findings import DeviceSettingSheet

T = Control.ControlType


@dataclass(frozen=True)
class FindingsDomain:
    """One domain: a tab in the workbook, a page in the app."""

    slug: str
    spec: DeviceSettingSheet

    @property
    def title(self) -> str:
        return self.spec.sheet_title

    @property
    def description(self) -> str:
        return self.spec.description


def _object_domain(slug, control_type) -> FindingsDomain:
    return FindingsDomain(slug, objects.SPEC_BY_TYPE[control_type])


#: Summary order. Categories run Policies, Objects, Network, Device - the product's own - and a
#: category's domains follow the order findings are generated in.
DOMAINS = (
    # Policies
    FindingsDomain("security-rules", security_rules.SPEC),
    # Objects
    _object_domain("security-profiles", T.SECURITY_PROFILE),
    # Network
    _object_domain("interface-management-profiles", T.INTERFACE_MANAGEMENT_PROFILE),
    # Device
    FindingsDomain("password-complexity", password_complexity.SPEC),
    FindingsDomain("authentication-settings", authentication_settings.SPEC),
    _object_domain("login-banner", T.LOGIN_BANNER),
    FindingsDomain("management-crypto", management_crypto.SPEC),
    _object_domain("master-key", T.MASTER_KEY),
    _object_domain("update-server", T.UPDATE_SERVER),
    _object_domain("logging-settings", T.LOGGING_SETTINGS),
    _object_domain("ntp", T.NTP_SETTINGS),
    _object_domain("snmp", T.SNMP_SETTINGS),
    _object_domain("system-identity", T.SYSTEM_IDENTITY),
    _object_domain("management-interfaces", T.MANAGEMENT_INTERFACE),
    _object_domain("ssl-tls-service-profiles", T.SSL_TLS_SERVICE_PROFILE),
    _object_domain("certificate-profiles", T.CERTIFICATE_PROFILE),
    _object_domain("certificates", T.CERTIFICATE),
    _object_domain("authentication-profiles", T.AUTHENTICATION_PROFILE),
    _object_domain("authentication-sequences", T.AUTHENTICATION_SEQUENCE),
    _object_domain("password-profiles", T.PASSWORD_PROFILE),
    _object_domain("administrators", T.ADMIN_USER),
    _object_domain("aaa-server-profiles", T.SERVER_PROFILE),
)

DOMAIN_BY_SLUG = {domain.slug: domain for domain in DOMAINS}


def domain_for_model(model_label: str) -> FindingsDomain | None:
    """The domain whose findings are about this model, or None where nothing reports on it.

    DERIVED from the specs rather than listed beside the configuration rail, so a new domain
    is linked from its object's page the day it exists. Two rail items can share one domain -
    anti-spyware and vulnerability protection are both security profiles, and management TLS
    and SSH are both management crypto - which a list would have to remember and this cannot
    get wrong.
    """
    return _DOMAIN_BY_MODEL.get(model_label)


def _build_model_index():
    index = {}
    for domain in DOMAINS:
        spec = domain.spec
        for control_type in spec.control_types:
            model = spec.subject_model(spec.kind_for(control_type))
            index.setdefault(model._meta.label, domain)
    return index


class _LazyModelIndex(dict):
    """Built on first use: this module is imported while the app registry is still loading."""

    def get(self, key, default=None):
        if not self:
            self.update(_build_model_index())
        return super().get(key, default)


_DOMAIN_BY_MODEL = _LazyModelIndex()


def severity_counts() -> dict[str, dict[str, int]]:
    """{slug: {severity: count}} for every domain, in one query per finding model.

    Counted rather than built: the Summary needs how many and how bad, and building all
    twenty-two tables to total them would do the whole job of every page to draw one.
    """
    counts: dict[str, dict[str, int]] = {}
    for domain in DOMAINS:
        spec = domain.spec
        by_severity: dict[str, int] = defaultdict(int)
        for kind in {spec.kind_for(control_type) for control_type in spec.control_types}:
            rows = (kind.model.objects
                    .filter(control__control_type__in=spec.control_types,
                            control__is_active=True)
                    .values_list("severity")
                    .annotate(total=Count("severity")))
            for severity, total in rows:
                by_severity[severity] += total
        counts[domain.slug] = dict(by_severity)
    return counts
