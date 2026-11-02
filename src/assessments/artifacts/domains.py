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
    # Policies, 2026-11-02, for PAN-IOT-004 - the other verdict over a virtual system's whole
    # rule set, so it sits beside `vsys-rule-posture` above and AFTER it, which is
    # `finding_run.GENERATORS` order and the order a reader needs: that tab says whether the
    # policy refuses anything at all, and this one asks a narrower question of the same rules.
    #
    # ITS CATEGORY IS DERIVED FROM THE RAIL (`category=''`), which is right for a subject whose
    # address is a PAN-OS node: deriving it means the workbook cannot disagree with the app about
    # where the subject lives. The rail item is `rulebase-device-match`, at Policies > Security,
    # the third item at that address.
    #
    # THIS DOMAIN'S OTHER TWO TABS ARE NOT BESIDE IT, and that is required rather than untidy:
    # its three subjects categorise as Policies, Network and Device, so they sit in three
    # different blocks of this list. Tabs must follow the Summary's category order and the
    # product's order wins over keeping one pipeline domain's tabs together.
    # `finding_run.GENERATORS` runs them device identification, security zone, rulebase device
    # match - the REVERSE of their category rank - and that tuple's order governs only WITHIN a
    # category, so nothing here contradicts it.
    _object_domain("rulebase-device-match", T.RULEBASE_DEVICE_MATCH),
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
    # Policies, LAST in this category, 2026-11-02, for PAN-ZON-007.
    #
    # THE VENDOR'S RAIL ORDER WINS OVER `finding_run.GENERATORS` HERE, and the departure is
    # stated rather than taken quietly. GENERATORS runs "DoS policy rule" at index 59, before
    # "vsys rule posture" (72) and "security rule" (73) - so that tuple alone would put this tab
    # at the TOP of the Policies block. PAN-OS's own Policies rail runs Security, NAT, QoS,
    # Policy Based Forwarding, Decryption, Network Packet Broker, Tunnel Inspection, Application
    # Override, Authentication, DoS Protection, SD-WAN, which puts the DoS rulebase at the tail.
    #
    # The Policies block above is ALREADY editorially ordered rather than GENERATORS-ordered -
    # `vsys-rule-posture` is first on the argument that a whole-policy finding reframes a
    # per-rule one, and GENERATORS puts it second-to-last - and the Network block below is
    # ordered by the vendor's rail for the reason its own comment gives. This follows the
    # second: a DoS rule is a DIFFERENT RULEBASE at a different screen, and a reader meets the
    # security policy before it. `check_tabs_follow_the_summary` constrains only that category
    # RANKS do not decrease, so within a category this is a choice and not a gate.
    #
    # Category DERIVED from the rail (`category=''`), whose item is `dos-protection-rules` at
    # Policies > DoS Protection - right for a subject that IS a configuration object.
    _object_domain("dos-protection-rules", T.DOS_POLICY_RULE),
    # Objects, 2026-11-02, for PAN-URL-006, and BEFORE `security-profiles` on purpose.
    #
    # The `url-filtering` domain reports to two tabs: its other five controls land on the shared
    # profile tab below, and this one is the only control over
    # `integrations.CustomUrlCategory`. A custom category is an INPUT to a URL filtering profile -
    # the profile's Categories grid lists these entries under its own "Custom URL Categories"
    # drop-down (Web Interface Help 11.2 p.296) - so a reader meets the objects a profile is built
    # out of before the profiles built out of them, and that is also PAN-OS's own tree order:
    # Custom Objects sits above Security Profiles.
    #
    # `finding_run.GENERATORS` order governs only WITHIN a category and both of these are Objects,
    # so the order here is this list's own choice and this is the editorial one.
    # `check_tabs_follow_the_summary` constrains only that category RANKS do not decrease.
    #
    # It does not disturb the `_build_model_index` note above: that index takes the FIRST domain
    # claiming a MODEL, and this domain claims `integrations.CustomUrlCategory`, which no other
    # domain claims. `SecurityProfile` links still land on `security-profiles`.
    #
    # Category DERIVED from the rail (`category=''`), whose item is `custom-url-categories` at
    # Objects > Custom Objects > URL Category - right for a subject that IS a configuration object.
    _object_domain("custom-url-categories", T.CUSTOM_URL_CATEGORY),
    # Objects
    _object_domain("security-profiles", T.SECURITY_PROFILE),
    # Objects, 2026-11-02, for PAN-FIL-003, and IMMEDIATELY AFTER `security-profiles` on purpose.
    #
    # This domain's other three controls report onto the tab above - they target
    # `integrations.SecurityProfile` with `kind` in {file-blocking, data-filtering} - so these two
    # tabs are one question at two grains, and a reader meets the findings about a profile that
    # exists and is wrong before the verdict that says nothing is watching at all.
    # `finding_run.GENERATORS` runs "data filtering posture" among the per-point conclusions, well
    # before "security profile"; that tuple's order governs only WITHIN a category and both of
    # these are Objects, so the order here is this list's own choice and this is the editorial one.
    # `check_tabs_follow_the_summary` constrains only that category RANKS do not decrease.
    #
    # It does not disturb the `_build_model_index` note above: that index takes the FIRST domain
    # claiming a MODEL, and this domain claims `integrations.DataFilteringPosture`, which no other
    # domain claims. `SecurityProfile` links still land on `security-profiles`.
    _object_domain("data-filtering-posture", T.DATA_FILTERING_POSTURE),
    # Objects, not last. It reads as a footnote to the whole run and was placed at the end for
    # that reason - but the workbook requires tabs to follow the Summary's category order, and
    # coverage categorises as Objects because its subject is an address object. The product's
    # own ordering wins over the editorial preference.
    _object_domain("coverage", T.COVERAGE),
    # Objects, beside coverage: same family, different subject. See the sheet spec for why it
    # claims the Objects category rather than one of its own.
    _object_domain("normalization-coverage", T.NORMALIZATION),
    # Network
    #
    # Network, 2026-11-02, for PAN-IOT-002, and FIRST in this category because that is where the
    # vendor puts the object: help p.359 enumerates the Network rail as Interfaces, Traffic
    # Objects, ZONES, VLANs, Virtual Wires, Virtual Routers, Routing, IPSec Tunnels, ... Network
    # Profiles LAST - so a zone precedes every other Network subject this report has a tab for.
    # Category DERIVED from the rail, at Network > Zones.
    #
    # THE TAB IS THIS DOMAIN'S AND THE MODEL IS NOT. `integrations.Zone` is shared with two later
    # pipeline domains - `user-id` over the zone's User-ID switch and ACLs, `zone-dos-protection`
    # over its protection-profile attachment - and both have their own control types and so their
    # own tabs. `_build_model_index` takes the FIRST domain claiming a model, so every Zone
    # findings link lands HERE until somebody decides otherwise; that is worth knowing when those
    # domains run, because their rows will be on their own tabs while the model's links are not.
    _object_domain("security-zones", T.ZONE),
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
    # Network, LAST in this category, 2026-11-02, for PAN-ZON-002 to -006 - and here BOTH orders
    # agree for once, which is worth saying because the two neighbours above departed from each
    # other. `finding_run.GENERATORS` runs "zone protection profile" at index 58, after every
    # other Network generator (ike gateway is 29, security zone 49); and the vendor's Network
    # rail puts Network Profiles LAST while its Network Profiles sections run GlobalProtect
    # IPSec Crypto, IKE Gateways, IPSec Crypto, IKE Crypto, Monitor, Interface Mgmt, ZONE
    # PROTECTION (help 11.2 p.635-650) - so Zone Protection is the last section of the last
    # group. GENERATORS order and rail order both land on this position.
    #
    # NOT BESIDE `security-zones` AT THE TOP OF THIS BLOCK, which is where the domain's name
    # would have put it. The profile and the zone are two different subjects at two different
    # vendor addresses: a profile is a reusable proposal under Network Profiles, and the
    # ATTACHMENT of one to a zone is a leaf on the zone. That is the same split as between this
    # domain's PAN-ZON-002..006 (here) and PAN-ZON-001 (on `security-zones`), and an engineer
    # fixes one or the other.
    #
    # Category DERIVED from the rail (`category=''`), whose item is `zone-protection`.
    _object_domain("zone-protection", T.ZONE_PROTECTION_PROFILE),
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
    # Device, 2026-11-02, for PAN-IOT-001 and PAN-IOT-003. HERE rather than beside the master key
    # at the top of this block, because within a category this list takes
    # `finding_run.GENERATORS`' order and that tuple runs "device identification" after "aaa
    # server profile" and before "policy rule settings" below. The RAIL puts the object elsewhere
    # - Device > Licenses, which help p.950-956 lists immediately above Master Key and
    # Diagnostics - and the two orders are allowed to differ: the rail is the product's
    # navigation and this is the Summary's reading order.
    #
    # Category DERIVED from the rail, like its two siblings. The subject is read from three
    # instruments and only one of them has a configuration xpath, but two of the three are
    # screens an assessor opens - which is the test `configuration_navigation` states for being
    # on the rail at all, and it passes it.
    _object_domain("iot-security", T.DEVICE_IDENTIFICATION),
    # Device, 2026-11-02, for PAN-UID-002, -003, -004 and -006. HERE, after `iot-security` and
    # before `policy-rule-settings`, because within a category this list takes
    # `finding_run.GENERATORS`' order and that tuple runs "device identification", then the two
    # User-ID entries, then "policy rule settings" last.
    #
    # THE COLLECTOR BEFORE THE DISCOVERY BOUND, which is GENERATORS' order and its stated reason:
    # the collector is the thing that performs discovery, so a reader meeting an unbounded
    # discovery scope wants to know first whether the agent probing it is the credentialed kind.
    #
    # CATEGORY DERIVED FROM THE RAIL (`category=''`) on both, which is right for a subject whose
    # address is a PAN-OS node: deriving it means the workbook cannot disagree with the app about
    # where the subject lives. Both rail items are at Device > User Identification > User Mapping.
    #
    # THE DOMAIN'S OTHER TWO CONTROLS ADD NO ENTRY HERE. PAN-UID-001 reports on `security-zones`
    # and PAN-UID-005 on `management-interfaces`, both of which already exist and are claimed by
    # other domains - which is also why neither appears twice: `_build_model_index` takes the
    # FIRST domain claiming a model, and neither of these two claims `Zone` or
    # `ManagementInterface`.
    _object_domain("user-id-collector", T.USER_ID_COLLECTOR),
    _object_domain("user-id-discovery", T.USER_ID_DISCOVERY_BOUND),
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
