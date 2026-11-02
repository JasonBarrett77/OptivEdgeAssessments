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
from .sheets import policy_rule_settings
from .sheets import profile_rules
from .sheets import security_rules
from .sheets import vsys_rule_posture
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
    #
    # BEFORE the rules, 2026-11-01, which is `finding_run.GENERATORS` order and is also the
    # order a reader needs: a finding here says this virtual system's policy refuses nothing at
    # all, and that makes a finding about one rule inside it a smaller question. GENERATORS'
    # own comment makes the same argument for the generator order it takes this from.
    #
    # It does not disturb the note below. That one is about `_build_model_index` taking the
    # FIRST domain claiming a MODEL, and this domain claims `VsysRulePosture`, which no other
    # domain claims - `SecurityRule` links still land on `security-rules`.
    FindingsDomain("vsys-rule-posture", vsys_rule_posture.SPEC),
    #
    # The generic rules sheet comes first and stays first: `_build_model_index` takes the FIRST
    # domain claiming a model, so SecurityRule links keep landing here rather than on one of
    # the per-kind views below.
    FindingsDomain("security-rules", security_rules.SPEC),
    # One view per security-profile kind, over rules (Jason, 2026-10-12: "present each security
    # profile finding on its own ... still rule based"). Eleven controls about profiles share
    # the security_rule type with the PAN-POL controls, so the rules sheet excludes them and
    # each kind gets a sheet whose Profiles cell names only its own verdicts.
    *(FindingsDomain(f"{slug}-by-rule", profile_rules.SPEC_BY_KIND[slug])
      for slug, _title, _ids, _fields in profile_rules.KINDS),
    # Objects
    _object_domain("security-profiles", T.SECURITY_PROFILE),
    # Objects, not last. It reads as a footnote to the whole run and was placed at the end for
    # that reason - but the workbook requires tabs to follow the Summary's category order, and
    # coverage categorises as Objects because its subject is an address object. The product's
    # own ordering wins over the editorial preference.
    _object_domain("coverage", T.COVERAGE),
    # Objects, beside coverage: same family, different subject. See the sheet spec for why it
    # claims the Objects category rather than one of its own.
    _object_domain("normalization-coverage", T.NORMALIZATION),
    # Network
    _object_domain("interface-management-profiles", T.INTERFACE_MANAGEMENT_PROFILE),
    # Network > Network Profiles, 2026-10-28. Both after the interface-management profiles,
    # which is this category's order in `finding_run.GENERATORS` - and the proposal set before
    # the gateway, which is that tuple's own reasoning: a gateway's finding names the profile it
    # points at, so a reader meets the proposal before the binding that chooses it.
    _object_domain("ike-crypto-profiles", T.IKE_CRYPTO_PROFILE),
    # Network, 2026-11-02 - the two PHASE 2 objects, BETWEEN the two phase-1 ones. That is this
    # category's order in `finding_run.GENERATORS`, which runs ike crypto profile, ipsec crypto
    # profile, ipsec tunnel, ike gateway - and within a category that tuple is this list's order.
    #
    # It reads oddly and it is deliberate on both sides: the proposal sets come before the
    # bindings that choose them, because a binding's finding names the profile it points at, and
    # a reader meets the thing being named before the thing that names it. Phase 2's pair sits
    # inside phase 1's for that reason rather than for a chronological one.
    #
    # The crypto profile's tab is `IPSec Crypto`, at Network > Network Profiles > IPSec Crypto;
    # the tunnel's is `IPSec Tunnels`, at Network > IPSec Tunnels. Both categorise as Network,
    # DERIVED from the rail rather than declared on the sheet - which is right for every tab
    # whose subject IS a configuration object, because deriving it means the workbook cannot
    # disagree with the app about where an object lives.
    _object_domain("ipsec-crypto-profiles", T.IPSEC_CRYPTO_PROFILE),
    _object_domain("ipsec-tunnels", T.IPSEC_TUNNEL),
    _object_domain("ike-gateways", T.IKE_GATEWAY),
    # Device
    FindingsDomain("password-complexity", password_complexity.SPEC),
    FindingsDomain("authentication-settings", authentication_settings.SPEC),
    _object_domain("login-banner", T.LOGIN_BANNER),
    FindingsDomain("management-crypto", management_crypto.SPEC),
    _object_domain("master-key", T.MASTER_KEY),
    _object_domain("update-server", T.UPDATE_SERVER),
    _object_domain("logging-settings", T.LOGGING_SETTINGS),
    # Device > Setup > WildFire. The device-wide settings - PAN-AVW-004 and PAN-AVW-005 -
    # NOT the WildFire analysis profile, whose control reports on the security rule.
    _object_domain("wildfire-settings", T.WILDFIRE_SETTINGS),
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
    # Device, LAST, 2026-11-01: `finding_run.GENERATORS` runs "policy rule settings" after every
    # other device generator, and within a category that tuple is this list's order.
    #
    # ITS TAB IS EMPTY, by design and not by accident - its one control ships inactive - which
    # is why the sheet's description says so in the customer's words. A domain for a control
    # type nobody can see is the other half of the hazard "a tab with no rows is
    # indistinguishable from a tab that is broken": a MISSING tab for a shipped control type is
    # indistinguishable from a control nobody built.
    FindingsDomain("policy-rule-settings", policy_rule_settings.SPEC),
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
