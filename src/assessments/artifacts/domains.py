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
    # REGISTERED WITH `_object_domain` AND NOT `FindingsDomain(slug, module.SPEC)`, and that is
    # not a style choice: `probe.oea_registry.domain_slug` in OptivEdgeProbe parses THIS FILE as
    # text, and its second form is the regex `FindingsDomain\(\s*["\']([a-z0-9-]+)["\']\s*,\s*
    # (\w+)\.SPEC`, which requires the attribute to be literally `SPEC` and so admits exactly ONE
    # spec per sheet module. This domain has FOUR specs over four models, which that form cannot
    # express - and naming them `SPEC_*` would be worse than failing, because the unanchored regex
    # would match the prefix and return the FIRST slug for all four control types. Measured
    # 2026-11-02: registered the other way, `tests/test_oea_registry.py::
    # test_every_built_control_reaches_a_findings_domain_today` failed for this domain the moment
    # its stage 9 artifact existed. `_object_domain` names the control type in this file, so the
    # lookup resolves per type and cannot be ambiguous.
    #
    # Policies, 2026-11-02, for PAN-SAS-003 - the THIRD verdict over a virtual system's whole
    # rule set, so it sits beside the two above and after them, which is the order a reader
    # needs by those entries' own argument: `vsys-rule-posture` says whether the policy refuses
    # anything at all, and these two ask narrower questions of the same rules.
    #
    # NOT IN `finding_run.GENERATORS` ORDER RELATIVE TO THIS CATEGORY, and that is stated rather
    # than quiet. Measured 2026-11-02: the Policies block's generator indices already run 72,
    # 50, 73, 73, 73, 73, 69, 70, 59 - so the convention is not held here today, and placing
    # this domain (index 33) in index order would mean putting it first and rearranging nothing
    # usefully. `check_tabs_follow_the_summary` enforces CATEGORY order only. Placed by the
    # reader's need and by the three tabs' shared subject instead.
    _object_domain("saas-application-policy", T.SAAS_APPLICATION_POLICY_POSTURE),
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
    # Policies, 2026-11-02, for PAN-DEC-001 and -009 - the verdict over a whole decryption
    # rulebase - and BEFORE the per-rule tab below it, on the same argument `vsys-rule-posture`
    # makes at the top of this block: a finding here says this virtual system's policy opens no
    # session for inspection at all, and that makes a finding about one rule inside it a smaller
    # question. `finding_run.GENERATORS` runs the two in this order too.
    #
    # BOTH SIT AFTER THE SECURITY-POLICY TABS AND BEFORE `dos-protection-rules`, which is the
    # vendor's own Policies rail order: Security, NAT, QoS, Policy Based Forwarding, DECRYPTION,
    # Network Packet Broker, Tunnel Inspection, Application Override, Authentication, DoS
    # Protection, SD-WAN. `check_tabs_follow_the_summary` constrains only that category RANKS do
    # not decrease, so within a category this is a choice, and it is the same choice this list
    # already made for the DoS tab.
    #
    # CATEGORY DERIVED FROM THE RAIL (`category=''`) on both, which is right for a subject whose
    # address is a PAN-OS node: deriving it means the workbook cannot disagree with the app about
    # where the subject lives. Both rail items are at Policies > Decryption, the second and third
    # instance in this report of two items over two models at one vendor address.
    #
    # THIS DOMAIN'S THIRD TAB IS NOT BESIDE THEM, and that is required rather than untidy: its
    # subject is at Device > Certificate Management > SSL Decryption Exclusion, so it
    # categorises as Device and sits in that block. Tabs follow the Summary's category order
    # rather than keeping a pipeline domain's tabs together.
    #
    # Neither disturbs the `_build_model_index` note above: that index takes the FIRST domain
    # claiming a MODEL, and these two claim `integrations.DecryptionRulebaseVerdict` and
    # `integrations.DecryptionPolicyRule`, which no other domain claims.
    _object_domain("decryption-coverage", T.DECRYPTION_RULEBASE_COVERAGE),
    _object_domain("decryption-rules", T.DECRYPTION_POLICY_RULE),
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
    # Objects, 2026-11-02, the two SaaS tabs whose subjects are Objects-category nodes - an
    # application's approval tag and a URL Filtering profile's SaaS controls. In
    # `finding_run.GENERATORS` order between themselves (indices 31 then 32), which is also the
    # order a reader needs: whether the partition records what the business approved at all,
    # before what its web controls do about the rest.
    #
    # BEFORE `coverage` AND `normalization-coverage`, which are deliberately last in this
    # category - they report what the run could NOT establish, so they read as the footnote to
    # everything above rather than as another finding family.
    _object_domain("sanctioned-application-marking", T.SANCTIONED_APPLICATION_MARKING),
    _object_domain("saas-url-filtering-posture", T.SAAS_URL_FILTERING_POSTURE),
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
    # Network > GlobalProtect, 2026-11-02, for PAN-GPP-001 to -006 - THREE tabs, AFTER
    # `zone-protection` and so last in this category, which is the Help's own chapter order:
    # Network Profiles is p.635-650 and the GlobalProtect chapter is p.997-1085. The rail items
    # sit in the same place relative to the same neighbours, so the two surfaces agree.
    #
    # THE ORDER WITHIN THE THREE IS THE VENDOR'S OWN SCREEN ORDER, from its enumeration at help
    # 11.2 p.997: Portals, then Gateways, then the clientless screens. So the portal leads, its
    # own authentication table follows it because that table is a tab INSIDE the portal dialog,
    # and the vsys-wide verdict comes last - which is also the order `finding_run.GENERATORS`
    # runs the three in. `check_tabs_follow_the_summary` constrains only that category RANKS do
    # not decrease, so within a category this is a choice, and here nothing competes for it.
    #
    # THE COVERAGE TAB LAST AND NOT FIRST, which is the opposite of the call `decryption-policy`
    # made one category up, and the difference is which finding makes the other smaller. There,
    # a rulebase with no decryption rule at all made a finding about one rule a smaller question.
    # Here the portal is the exposed service and the coverage row is a verdict about an OPTIONAL
    # feature on top of it: a portal with no transport profile is the bigger problem than a vsys
    # that publishes a web application, so the portal leads.
    #
    # CATEGORY DERIVED FROM THE RAIL (`category=''`) on all three, which is right for a subject
    # whose address is a PAN-OS node: deriving it means the workbook cannot disagree with the app
    # about where the subject lives. All three rail items are in the `Network` category under the
    # vendor's own `GlobalProtect` group.
    #
    # THE THIRD ONE IS SHARED WITH THE DOMAIN AFTER THIS. `globalprotect-gateway`'s PAN-GPG-005
    # reports on `integrations.GlobalProtectEnforcementPoint` too, so its findings will reach
    # `globalprotect-coverage` without that domain adding a tab - and `setting_columns` will
    # derive new columns on it for whatever that control clauses on. This entry is deliberately
    # NOT narrowed with `control_ids`: narrowing it would leave PAN-GPG-005 with no tab and fail
    # `check_every_finding_reached_a_tab` for the next domain.
    #
    # Neither disturbs the `_build_model_index` note above: that index takes the FIRST domain
    # claiming a MODEL, and these three claim `integrations.GlobalProtectPortal`,
    # `integrations.GlobalProtectPortalClientAuthRow` and
    # `integrations.GlobalProtectEnforcementPoint`, which no other domain claims.
    # Network > GlobalProtect > Gateways, 2026-11-02, for PAN-GPG-001 to -004, -006 and -007 -
    # THREE more tabs in the same block, added by `globalprotect-gateway`.
    #
    # BETWEEN THE PORTAL TABS AND THE COVERAGE TAB, which keeps BOTH of the orders the block above
    # was built on. The vendor's screen enumeration at help 11.2 p.997 runs Portals then Gateways,
    # so the gateway follows the portal; and the comment above states why the vsys-wide verdict
    # comes last - it is a conclusion over an OPTIONAL feature on top of the exposed service, so
    # the services lead. Inserting here satisfies both, and `check_tabs_follow_the_summary`
    # constrains only that category RANKS do not decrease, so within `Network` this is a choice.
    #
    # THE ORDER WITHIN THE THREE IS THE VENDOR'S OWN DIALOG ORDER: the gateway itself, then its
    # Authentication tab, then its Agent tab - which is the order help 11.2 p.1044 answers its own
    # "What are you looking for?" index in ("What general settings can I configure for the
    # GlobalProtect gateway? ... How do I configure the gateway client authentication? ... How do I
    # configure the tunnel and network settings that enable an app to establish a VPN tunnel with
    # the gateway?").
    #
    # CATEGORY DERIVED FROM THE RAIL (`category=''`) on all three, which is right for a subject
    # whose address is a PAN-OS node: deriving it means the workbook cannot disagree with the app
    # about where the subject lives. All three rail items are `Network`, under the vendor's own
    # `GlobalProtect` group.
    #
    # THE `_build_model_index` NOTE ABOVE IS UNDISTURBED: that index takes the FIRST domain
    # claiming a MODEL, and these three claim `integrations.GlobalProtectGateway`,
    # `integrations.GlobalProtectGatewayClientAuth` and
    # `integrations.GlobalProtectGatewayAgentConfig`, which no other domain claims. The FOURTH
    # model this domain's controls report on - `integrations.GlobalProtectEnforcementPoint`, for
    # PAN-GPG-005 - adds NO entry here: it is already claimed by `globalprotect-coverage` below,
    # which the domain before this one deliberately left un-narrowed so that exactly this would
    # happen. PAN-GPG-005's clause field adds a derived COLUMN to that tab instead of a tab.
    _object_domain("globalprotect-portals", T.GLOBALPROTECT_PORTAL),
    _object_domain("globalprotect-portal-authentication", T.GLOBALPROTECT_PORTAL_CLIENT_AUTH),
    _object_domain("globalprotect-gateways", T.GLOBALPROTECT_GATEWAY),
    _object_domain("globalprotect-gateway-authentication", T.GLOBALPROTECT_GATEWAY_CLIENT_AUTH),
    _object_domain("globalprotect-gateway-agent", T.GLOBALPROTECT_GATEWAY_AGENT_CONFIG),
    _object_domain("globalprotect-coverage", T.GLOBALPROTECT_ENFORCEMENT_POINT),
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
    # Device, 2026-11-02, for PAN-DCP-006. HERE, immediately after `certificates`, because within
    # a category this list takes `finding_run.GENERATORS`' order and that tuple already put this
    # control type exactly there, with its own stated reason: "Beside `certificate` on purpose,
    # and AFTER it: the forward-proxy signing designation is a POINTER into the certificate store,
    # so a reader meets the certificates before the node that names two of them."
    #
    # THIS DOMAIN'S OTHER SIX CONTROLS ADD NO ENTRY HERE. PAN-DCP-001 to -005 and -007 report onto
    # `security-profiles` in the Objects block - they target `integrations.SecurityProfile` with
    # `kind eq "decryption"` - which already exists and is claimed by that domain. So these two
    # tabs are one domain at two grains in two different PAN-OS categories, and tabs follow the
    # Summary's category order rather than keeping a pipeline domain's tabs together.
    #
    # It does not disturb the `_build_model_index` note above: that index takes the FIRST domain
    # claiming a MODEL, and this domain claims `integrations.DecryptionSettings`, which no other
    # domain claims. `SecurityProfile` links still land on `security-profiles`.
    #
    # Category DERIVED from the rail (`category=''`), whose item is `forward-proxy-signing` at
    # Device > Certificate Management > Certificates - right for a subject that IS a configuration
    # object, and the second item at that one vendor address.
    _object_domain("forward-proxy-signing", T.DECRYPTION_SETTINGS),
    # Device, 2026-11-02, for PAN-SAS-005 - the App-ID Cloud Engine, at Device > Setup > ACE.
    #
    # THIS POSITION IS `finding_run.GENERATORS` ORDER AND WAS CHOSEN FOR THAT. Its generator
    # index is 30 and the entry above it is 25, the one below 67, so 25 < 30 < 67 holds - which
    # is the convention this list follows within a category (Jason, 2026-09-21). The 67-then-36
    # break immediately below is older and is not this entry's to rearrange.
    #
    # FIRST OF THE DOMAIN'S FOUR TABS IN GENERATOR ORDER AND LAST IN THE SUMMARY, which is worth
    # naming because the tab's own description leans on the first half: the engine's state is the
    # PREMISE the other three rest on, so the findings are GENERATED first. The Summary groups by
    # PAN-OS category and this subject is a Device setting, so it reads last. Nothing can satisfy
    # both orders at once and the category order is the gated one.
    _object_domain("cloud-app-engine", T.CLOUD_APP_ENGINE_SETTING),
    # Device, 2026-11-02, for PAN-DEC-004's first record. HERE, immediately after
    # `forward-proxy-signing`, because within a category this list takes
    # `finding_run.GENERATORS`' order and both of these subjects are under the same rail group -
    # Device > Certificate Management - so a reader meets the certificates, then the node that
    # designates two of them, then the list of servers the firewall is told not to look inside.
    #
    # THIS DOMAIN'S OTHER TWO TABS ARE IN THE Policies BLOCK ABOVE, over the two models that
    # carry the decryption policy itself. So `decryption-policy` is one domain at three grains in
    # two PAN-OS categories, and tabs follow the Summary's category order rather than keeping a
    # pipeline domain's tabs together.
    #
    # Category DERIVED from the rail (`category=''`), whose item is `ssl-decryption-exclusion` at
    # Device > Certificate Management > SSL Decryption Exclusion - right for a subject that IS a
    # configuration object, and an address established in the vendor's own Help rather than
    # inferred from the domain's name. See that rail item for the citation.
    _object_domain("ssl-decryption-exclusions", T.SSL_DECRYPTION_EXCLUSION),
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
    # Device, 2026-11-02, for PAN-PLT-004, -002 and -006 in that order. THREE ENTRIES HERE AND
    # THEY ARE IN `finding_run.GENERATORS`' ORDER, which within a category is this list's order
    # (Jason, 2026-09-21). Their generator indices are 60, 62 and 63; the entry above this one is
    # 48 and the one below is 65, so 48 < 60 < 62 < 63 < 65 holds and nothing existing moves. The
    # 67-then-36 break further up this block is older and is not these entries' to rearrange.
    #
    # INDEX 61 IS NOT OURS AND ITS ABSENCE IS NOT A GAP: `content update schedule` sits between
    # the licence inventory and the content streams in GENERATORS, belongs to the `updates` domain,
    # and has no `FindingsDomain` yet - its own stage 9 run writes one and its
    # `AWAITING_PRESENTATION` entry is still open. GENERATORS' own comment says why it is placed
    # there: the schedule is the CONFIGURED CAUSE of stale content and PAN-PLT-002's streams are
    # the RUNTIME SYMPTOM, so a reader meets the cause first. When that entry lands it goes between
    # the two below, not beside them.
    #
    # THE ORDER IS ENTITLEMENT, THEN CONTENT, THEN ALARM, and GENERATORS states the reason this
    # list inherits: what the appliance is ENTITLED to, then what it has actually LOADED, then the
    # mechanism that would say a log database filled. A reader meets "this appliance's licence
    # table could not be read" before "its antivirus stream was never installed", because the
    # first is a candidate explanation for the second.
    #
    # REGISTERED WITH `_object_domain` AND NOT `FindingsDomain(slug, module.SPEC)`, which is not a
    # style choice: `probe.oea_registry.domain_slug` in OptivEdgeProbe parses THIS FILE as text and
    # its second form requires the attribute to be literally `SPEC`, so it admits exactly one spec
    # per sheet module. These three live in `sheets/objects.py` beside fifty others, which that
    # form cannot express - see the `rulebase-device-match` entry above, which paid for the lesson.
    #
    # CATEGORY DERIVED FROM THE RAIL (`category=''`) ON ALL THREE, which is right for a subject an
    # assessor opens a vendor screen to read: deriving it means the workbook cannot disagree with
    # the app about where the subject lives. The rail items are `licenses`, `content-streams` and
    # `log-alarms`.
    #
    # THE DOMAIN'S OTHER THREE CONTROLS ADD NO ENTRY HERE. PAN-PLT-001, -003 and -005 are
    # discharged `engineer_answers` by stage 5 and have no catalog entry at all, so there is no
    # control type to register and nothing that could write a finding. Two of them are CRITICAL
    # severity; stage 8's `needs_human` is where that is on the record.
    _object_domain("licenses", T.LICENCE_INVENTORY),
    # Device, 2026-11-03, for PAN-UPD-001, -002, -004 and -005 - FOUR controls on ONE model and so
    # ONE tab, which is the most concentrated shape the pipeline has produced. `probe.surface_for`
    # answered per control that all four reached NO sheet beforehand.
    #
    # BETWEEN `licenses` AND `content-streams`, which is `finding_run.GENERATORS` order read off
    # that file rather than chosen here: licence inventory, content update schedule, firewall
    # content streams. GENERATORS already carries the reader's argument for the second adjacency
    # in its own comment - this subject "is the CONFIGURED CAUSE of stale content and
    # PAN-PLT-002's streams are the RUNTIME SYMPTOM" - so a reader meets "this appliance retrieves
    # no antivirus content at all" before "its antivirus stream is a year old".
    #
    # CATEGORY DERIVED FROM THE RAIL (`category=''`), which is right for a subject an assessor
    # opens a vendor screen to read: the rail item is `content-update-schedule` at
    # Device > Dynamic Updates, and deriving the category means the workbook cannot disagree with
    # the app about where the subject lives.
    #
    # REGISTERED WITH `_object_domain` AND NOT `FindingsDomain(slug, module.SPEC)`, for the reason
    # the entries around it record: `probe.oea_registry.domain_slug` parses THIS FILE as text and
    # its second form requires the attribute to be literally `SPEC`, so it admits one spec per
    # sheet module. This spec lives in `sheets/objects.py` beside fifty others.
    #
    # THE DOMAIN'S OTHER TWO CONTROLS ADD NO ENTRY HERE, and neither ever will under the current
    # ruling. PAN-UPD-003 is discharged `engineer_answers` by stage 5; PAN-UPD-006 is
    # `not_in_configuration` (a scope ruling) plus `engineer_answers`. Neither has a catalog entry
    # in `seed.json` at all - checked control by control, the file carries exactly PAN-UPD-001,
    # -002, -004 and -005 - so there is no control type to register and nothing that could write a
    # finding. PAN-UPD-006's own subject model `ContentDeploymentSchedule` exists and reaches no
    # tab by the same token; the stage 9 artifact records why rather than dropping it.
    _object_domain("content-update-schedule", T.CONTENT_UPDATE_SCHEDULE),
    _object_domain("content-streams", T.FIREWALL_CONTENT_STREAMS),
    _object_domain("log-alarms", T.LOG_ALARM_SETTINGS),
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
