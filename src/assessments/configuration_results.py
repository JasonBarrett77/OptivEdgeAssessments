"""What a configuration query page SHOWS, once the query has chosen the rows.

One entry per object, keyed on the search registry's model label. The compiler already answers
"which rows match"; this answers "what does a row look like", which is the only part that cannot
be derived - a queryset knows its fields but not which five of them a person wants to read.

Columns are chosen to be the ones a QUERY is usually about, which is not the same set the
findings tabs show. There is no Findings column and no Collected column: this surface answers
"which objects look like this", and a finding count on the row would invite the reader to treat
it as the findings tab, which is a page away and says something else.

Kept apart from `configuration_navigation.py` on purpose. That module is imported by `app_meta`
during project composition, before the app registry is ready, so it must not reach a model. This
one is imported by the view, at request time, and reaches models freely.

Adding an object is an entry here plus `search_model` on its `ConfigObject`. Both, or neither:
navigation gates the query view on `search_model`, and a label with no entry here would render a
table with no columns, which reads as "nothing matched" rather than as "not built".
"""

from __future__ import annotations

from typing import Callable, NamedTuple

from django.urls import reverse

from assessments import configuration_navigation as config_nav
from assessments import decryption_policy_presentation as decryption_policy
from assessments import device_id_presentation as device_id
from assessments import ike_presentation as ike
from assessments import ipsec_presentation as ipsec
from assessments import user_id_presentation as user_id
from assessments.security_rule_queries import build_security_rule_display_queryset
from optivedge_integrations.integrations.presentation import (
    address_breadth_label,
    entry_device_group_name,
    listed_address_ref_values,
    listed_member_values,
    security_rule_config_source_label,
)

from optivedge_integrations.integrations.models import (
    AddressObject,
    AdminUser,
    AuthenticationProfile,
    AuthenticationSequence,
    Certificate,
    CertificateProfile,
    CustomUrlCategory,
    DataFilteringPosture,
    DecryptionSettings,
    DeviceIdentificationState,
    DosPolicyRule,
    IkeCryptoProfile,
    IkeGateway,
    DecryptionPolicyRule,
    DecryptionRulebaseVerdict,
    GlobalProtectEnforcementPoint,
    GlobalProtectPortal,
    GlobalProtectPortalClientAuthRow,
    SslDecryptionExclusion,
    InterfaceManagementProfile,
    IpsecCryptoProfile,
    IpsecTunnel,
    ManagementInterface,
    UserIdCollectorSettings,
    UserIdDiscoveryBound,
    AuthenticationSettings,
    LoggingSettings,
    WildfireSettings,
    LoginBanner,
    ManagementTlsBinding,
    ManagementSshSettings,
    MasterKey,
    NtpSettings,
    SnmpSettings,
    SystemIdentity,
    UpdateServerSettings,
    PasswordComplexityPolicy,
    PasswordProfile,
    PolicyRuleSettings,
    RulebaseDeviceMatchVerdict,
    SecurityProfile,
    ServerProfile,
    SslTlsServiceProfile,
    VsysRulePosture,
    Zone,
    ZoneProtectionProfile,
)


class ResultsSpec(NamedTuple):
    #: Column headings, left to right.
    columns: tuple[str, ...]
    #: The rows to search, before any query is applied. Ordered here rather than in the view so
    #: an unqueried page and a queried one list in the same order.
    base_queryset: Callable
    #: One row of cells, same length as `columns`. Checked by a test rather than by trust.
    row: Callable
    #: The searchable fields this page OFFERS, when it is one section of a larger model. Built
    #: for the six pages that shared `DeviceConfigurationProfile`; no page uses it since that
    #: model was split, and it stays because the next model shared between pages will need it.
    #: Empty means all of them.
    #:
    #: It scopes the DROPDOWN, not the compiler. A query naming a field outside the list still
    #: compiles - a saved control query applied here is not something to refuse on presentation
    #: grounds.
    fields: tuple[str, ...] = ()
    #: {column heading: queryable field}, for the columns that present ONE field. The "build a
    #: query from the selected rows" button reads these and nothing else, which is why a
    #: composite column - "Character Classes", "Protocol Range", "Referenced By" - simply has
    #: no entry: it presents a verdict or several fields at once, and there is no single value
    #: a clause could carry. Checked against the search registry by test, and every clause it
    #: produces is verified by the compiler before it reaches the builder.
    query_fields: dict = {}
    #: A fixed canonical query every row on this page must also match - how two pages split ONE
    #: model the way the vendor's UI splits it (anti-spyware and vulnerability profiles). Applied
    #: by the search service like any other query, never as a queryset filter here: filtering an
    #: asserted model is the service's job (test_query_service_boundary).
    scope: dict | None = None


def _nothing(count, unit):
    """A count column that says what zero MEANS.

    "Nothing" rather than 0, for the reason the findings tabs give: a bare zero in a reference
    column reads as "not counted" exactly where it means "counted, and the answer was none".
    """
    return f"{count} {unit}" if count else "Nothing"


def _where(obj):
    """`shared`, or the vsys that holds it. A name alone is not unique on a device."""
    return obj.vsys_name if obj.scope != "shared" and obj.vsys_name else obj.scope


def _yes_no(value):
    return "yes" if value else "no"


def _enforced_by(point) -> str:
    """The firewalls that run one virtual system, comma-separated.

    A vsys belongs to an enforcement point, which on an HA pair spans both members - so this
    lists the owner's appliances rather than naming one of them.

    ONE PER LINE, not comma-joined. The first version of this joined on commas on the reasoning
    that this surface's cells are single-line, and `MultiValueCellTests` refused it with Jason's
    own words from 2026-09-27: "In fields where multiple values may exist, the values should be
    separated by new lines." The template runs every cell through `linebreaksbr`, so the page
    renders the break; the test was right and the reasoning was wrong.
    """
    owner = point.appliance_group or point.appliance
    if owner is None:
        return "-"
    members = (owner.appliances.all() if hasattr(owner, "appliances") else [owner])
    return "\n".join(sorted(a.hostname or a.serial_number for a in members)) or "-"


def _tri(value) -> str:
    """yes / no / "not read" for a nullable boolean.

    `_yes_no` answers two ways for a three-state column, and on both of these models NULL is
    the FIRING side: it means nobody established what the absent key does. Printing it as "no"
    would put the reassuring answer in the cell the control fired on.
    """
    if value is None:
        return "not read"
    return "yes" if value else "no"


def _ordered(model, *fields, related=("appliance",)):
    def rows():
        return model.objects.select_related(*related).order_by(*fields)
    return rows


_security_profiles = _ordered(
    SecurityProfile, "is_predefined", "name", "appliance_group__name", "enforcement_point__vsys_name",
    related=("enforcement_point__appliance_group", "appliance_group"))

#: Ordered by NAME first, then by where it is defined. A custom category's name is what a profile
#: and a security rule both name it by, and the same name can exist at a vsys, at the firewall's
#: own shared scope and in the pushed view - so a reader comparing two definitions of one name
#: wants them adjacent, which is the opposite of grouping by scope.
_custom_url_categories = _ordered(
    CustomUrlCategory, "name", "precedence_rank", "appliance_group__name",
    "enforcement_point__vsys_name",
    related=("enforcement_point__appliance_group", "appliance_group"))


def _action(value) -> str:
    """A file-blocking or data-filtering rule's `action`, with the FOURTH case named.

    The vendor's Action has three values - alert, continue, block (help p.306) - and an action key
    ABSENT from a committed rule is legal, measured on `oep-fdf6-07`. The store holds the empty
    string for that, and it must NOT read as the schema default `alert`: that would tell an
    assessor the rule is known to deliver the file and log it, when what is known is nothing.

    "no action set" rather than `(empty)`, which is what the shared findings-tab renderer can say
    and which does not distinguish "this rule names no action" from "this branch does not exist on
    this profile kind".
    """
    return value or "no action set"


def _url_action(value) -> str:
    """A url-filtering profile's weakest Site Access action over a named category set.

    NULL IS NOT "none" HERE. The column is null exactly when the category catalogue was never
    read, so the set has no members to rank - which is a fact about the collection and not about
    the profile. `(none)`, which the shared findings renderer can say, would read as an action.
    """
    return value or "category list not read"


def _worst_category(value, collected) -> str:
    """The worst-ranked category on a verdict's failing side, with the TWO NULLS separated.

    `worst_reachable_unlogged_category` and `worst_credential_permissive_category` are both null
    for two unrelated reasons - the catalogue was never read, or the failing set is EMPTY and the
    profile passes - and the stored value cannot tell them apart. The companion column
    `category_catalogue_collected` is the only thing that can, so this reads it. Printing one
    word for both would put "nobody looked" and "nothing is wrong" in the same cell.
    """
    if value:
        return value
    return "None" if collected else "category list not read"


#: The vendor's own names for the four credential detection methods, URL Filtering admin guide
#: p.61 and p.132-134: "Use IP User Mapping", "Use Domain Credential Filter", "Use Group
#: Mapping", and the Disabled state. The STORE holds the device's own key, which is what the
#: findings tab shows and what a query is written against; this maps it for the explorer page
#: alone, where the cell is this module's lambda and costs nothing.
#:
#: NOT INSTALLED AS A `value_readers` ENTRY ON THE FINDINGS SHEET, deliberately. That column is a
#: MEASURED PAYLOAD KEY with a `FieldProvenance` row, and a reader makes `build_rows` hand
#: `stored=False` to `remediation_accessor`, which then never reads that row - so whether the
#: credential-enforcement node was ABSENT or explicitly `disabled` would stop being visible. That
#: distinction is what PAN-URL-003 is about: `disabled` is the measured absent value AND the
#: firing side, per the model's own comment. So the tab keeps the device's key and this page
#: carries the vendor's sentence.
CREDENTIAL_DETECTION_LABELS = {
    "disabled": "Disabled",
    "ip-user": "Use IP User Mapping",
    "group-mapping": "Use Group Mapping",
    "domain-credentials": "Use Domain Credential Filter",
}


def _credential_mode(value) -> str:
    return CREDENTIAL_DETECTION_LABELS.get(value, value or "Disabled")


#: THE VENDOR'S OWN UI VALUES for the decryption profile's two protocol-version leaves, against
#: the device spelling the store holds. Help 11.2 p.341 names five verbatim - "PAN-OS supports
#: SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and TLSv1.3" - and p.345 names the sixth, which the ceiling
#: carries and the floor refuses: "You can choose the option Max so that no maximum version is
#: specified". A token this map does not carry is printed as it was stored rather than guessed at.
TLS_VERSION_LABELS = {
    "sslv3": "SSLv3", "tls1-0": "TLSv1.0", "tls1-1": "TLSv1.1",
    "tls1-2": "TLSv1.2", "tls1-3": "TLSv1.3", "max": "Max",
}


def _tls_version(value) -> str:
    """The vendor's label for a stored version token. "Not set" for the empty string.

    The empty string is not a state this node reaches on a collected profile - both columns carry
    a MEASURED non-null default - so this arm exists to keep an unrecomputed row from printing a
    blank cell beside a firing verdict.
    """
    if not value:
        return "Not set"
    return TLS_VERSION_LABELS.get(value, value)


def _resolved_ceiling(profile) -> str:
    """What `Max Version` actually means on THIS appliance, with the unresolvable case named.

    Three columns and not one, because the stored literal is a POINTER: two appliances storing
    `max` can negotiate different ceilings, and an appliance upgraded between two collections
    changes what the literal means without the stored value moving. BLANK in the store means the
    build was not one the resolver covers, and the verdict beside it then stays on the firing
    side - so this says that rather than leaving the cell empty, which would read as "nobody
    looked" on the one row where the resolution is the finding.
    """
    if profile.ssl_max_version_resolved:
        return _tls_version(profile.ssl_max_version_resolved)
    return "Could not be resolved for this build"


def _permitted(value) -> str:
    """One decryption-profile ALGORITHM switch, which is an ALLOW and not a block.

    `yes`/`no` is ambiguous on this family in a way it is not elsewhere on the row: the twelve
    `block-*` keys beside them are BLOCK switches where false is the weak direction, and these
    seven are ALLOW switches where TRUE is. A column of `yes` and `no` under two opposite
    polarities, with nothing in the heading announcing the change, is the shape the model's own
    comment warns a query author about - so the cell says which it means.
    """
    return "permitted" if value else "not permitted"


def _weakest_primitive(value) -> str:
    """The worst algorithm a profile still leaves negotiable, with `none` SPELLED.

    `none` is the compliant member of both of these columns and the one a bare token reads
    wrongly: a cell saying `none` beside a passing row reads as "no value recorded" where it
    means "nothing weak is negotiable". The algorithm names themselves are the vendor's own -
    RC4, 3DES, MD5, SHA1 on help 11.2 p.345-346, and RSA / AES-128-CBC / AES-256-CBC from its
    Key Exchange and Encryption Algorithms lists - so only the compliant member needs help.
    """
    if not value:
        return "Not computed"
    if value == SecurityProfile.PRIMITIVE_NONE:
        return "None negotiable"
    # Upper-casing reproduces the vendor's own spelling for all seven members exactly - RC4,
    # 3DES, MD5, SHA1, RSA, AES-128-CBC, AES-256-CBC - so no per-token map is needed and a member
    # added to either ordering tuple comes out right rather than coming out missing.
    return value.upper()


def _kind_scope(kind):
    return {"model": "integrations.SecurityProfile", "operator": "and",
            "clauses": [{"field": "kind", "op": "eq", "value": kind, "negated": False}]}


#: A severity this kind of profile does not assess at all.
NOT_APPLICABLE = "n/a"


def _verdict(blocked, detail):
    """The reason on BOTH sides: which action blocks it, or why nothing does.

    `None` is a THIRD state and not a quiet `False`: the profile makes no claim about this
    severity. An antivirus profile has per-protocol decoders rather than severity rules, so it
    answers the question not at all - and a blank cell beside rows reading "blocked (reset-both)"
    would read as a failure.
    """
    if blocked is None:
        return NOT_APPLICABLE
    return f"blocked ({detail})" if blocked else detail


def _decoder_actions(profile) -> str:
    """Each protocol and what it RESOLVES to, one per line.

    The configured literal is almost always `default`, so a column showing it would read the
    same for a profile that blocks and one that does not. The bracketed word in the UI is the
    one that matters, and this is that word.
    """
    # All THREE columns, because they resolve independently and a profile hardened in the
    # first alone is the case this page exists to make visible.
    return _lines([
        f"{d.protocol}: {d.effective_action or '(unknown)'}"
        f" / {d.effective_wildfire_action or '(unknown)'}"
        f" / {'(not computed)' if d.mlav_blocks is None else (d.effective_mlav_action or '(unknown)')}"
        for d in profile.decoders.all()]) or "-"


def _security_profile_row(p):
    return (
        p.appliance_group.name if p.appliance_group_id else str(p.enforcement_point),
        p.name,
        p.get_namespace_type_display(),
        _verdict(p.critical_blocked, p.critical_detail),
        _verdict(p.high_blocked, p.high_detail),
        _verdict(p.medium_blocked, p.medium_detail),
        _nothing(p.referrer_count, "referrer(s)"),
    )


def _lines(values):
    """A multi-value cell: one value per line, `-` when there are none.

    The security rules page renders each member in its own `<div>`, and these cells hold four
    or five zones and addresses routinely - joined with commas they wrap into a paragraph. The
    template runs every cell through `linebreaksbr`, so the split happens here as text rather
    than as markup, and device-supplied values stay escaped.
    """
    return "\n".join(values) if values else "-"


def _addresses(rule, related_name, negated, num_hosts):
    """Addresses, with the negation marker the rules page puts in front of them.

    `negate-source` inverts the whole list - the rule matches everything EXCEPT these - so a
    cell that shows the addresses without saying so states the opposite of what the rule does.

    The last line is the side's BREADTH, which is what PAN-POL-002 scores and what its audit
    step tells an assessor to read. It belongs in this cell rather than a column of its own
    because the member names and their size are one fact - a list of names says nothing about
    how much space it covers, and one name can be a /8. On a negated side it is the size of the
    COMPLEMENT, so it is deliberately the one number here that does not describe the names
    above it; that is what the rule permits.
    """
    values = listed_address_ref_values(rule, related_name)
    return _lines((["NOT"] if negated else []) + values + [address_breadth_label(num_hosts)])


def _logged(value):
    """`-` for absent, which is not the same as No: PAN-OS stores only what was written, and
    the log-start/log-end implicit values are recorded as unmeasured in the vendor guide."""
    return "-" if value is None else ("Yes" if value else "No")


def _rule_appliance(rule):
    point = rule.enforcement_point
    appliance = point.appliance or (
        point.appliance_group.active_appliance if point.appliance_group_id else None)
    return str(appliance) if appliance else "-"


def _rule_profiles(rule):
    """What the rule names, plus what its WildFire analysis actually amounts to.

    The WildFire line is INSIDE this cell rather than in a column of its own, because this
    page has to match the rules page's column set (Jason, 2026-09-18) - the same reason
    address breadth renders inside the address cell. It earns the space because naming a
    profile group and being covered are different things: on the lab 113 rules name a group
    called `default` that lists no profiles at all, so the cell above this line reads
    `default` and the line itself reads that nothing reaches the rule.
    """
    groups = [value.value for value in rule.securityruleprofilegroups.all()]
    individual = [f"{profile.profile_type}: {profile.value}"
                  for profile in rule.securityruleprofiles.all()]
    if rule.wildfire_analysis_submits_all is True:
        wildfire = "WildFire analysis: all file types"
    elif rule.wildfire_analysis_detail:
        wildfire = f"WildFire analysis: {rule.wildfire_analysis_detail}"
    else:
        wildfire = "WildFire analysis: not yet computed - re-normalize"
    return _lines(groups + individual + [wildfire])


def _resolved_content(obj) -> str:
    """What is known about an object's runtime content, in the terms the coverage controls use.

    Only EDL and FQDN objects have runtime content at all; for everything else the size comes
    from the value itself, so there is nothing to say and saying "none" would read as a gap.
    """
    if obj.address_type not in (AddressObject.TYPE_EDL, AddressObject.TYPE_FQDN):
        return "\u2013"
    if obj.resolved_content_truncated:
        total = obj.resolved_content_source_total
        return f"Truncated ({obj.num_hosts:,} of {total:,})" if total else "Truncated"
    if obj.num_hosts is None:
        return "Not collected"
    return f"Resolved ({obj.resolved_entries.count():,} range(s))"


def _is_referenced(obj) -> bool:
    """Whether any security rule points at this object, ON EITHER SIDE.

    BOTH TABLES, and until 2026-11-02 this consulted only one. The guard read
    `obj.securityrulesourceaddressref_set.exists() if hasattr(...) else
    obj.source_address_refs.exists() or obj.destination_address_refs.exists()` - and an
    `AddressObject` ALWAYS has `securityrulesourceaddressref_set`, so the first arm always won
    and the `or destination` in the second was unreachable. The only caller is the `addresses`
    ResultsSpec below, whose queryset is `AddressObject`, so the destination table was never
    consulted at all and the else arm would have raised if it had been reached: an
    `AddressObject` has no `source_address_refs` - that is the SecurityRule's accessor name.

    The consequence was the two surfaces of the coverage domain disagreeing about one boolean on
    one object. Measured 2026-11-02 on an external dynamic list referenced only as a rule
    DESTINATION: the findings tab's `referenced_by_policy` cell read `Yes` and PAN-COV-001 fired
    on it - because `search/address_object/compiler.py` reads both ref tables, saying so in its
    own docstring: "a list used only as a destination is referenced just as much as one used as
    a source" - while THIS column, on the page that finding links to, read `no`. A reader
    following a coverage finding arrived at a page saying nothing referenced the object the
    finding is about.

    Group membership is already flattened onto the ref rows by `resolve_static_group_members`,
    so an object reached only through a nested group counts here without walking groups.
    """
    return (obj.securityrulesourceaddressref_set.exists()
            or obj.securityruledestinationaddressref_set.exists())


RESULTS = {
    # --- Policies > Security ---------------------------------------------------------------
    # The same columns and the same values as /assessments/security-rules/, deliberately. Two
    # tables over one object that disagree about what a rule looks like make the reader check
    # which page they are on before reading a row, and the older page is the one people know.
    #
    # Flattened in one respect: that page groups `vsys` over id/name and `Source`/`Destination`
    # over zone/address with a two-row header. This frame has one header row, so the grouping
    # is carried in the labels instead - the columns and their order are unchanged.
    #
    # It takes the rules page's own queryset, so the prefetches stay in step: a row here reads
    # zones, addresses, applications, services, profile groups and profiles, and building that
    # list again separately is how the workbook export once drifted two relations behind.
    "security": ResultsSpec(
        query_fields={
            "Station": "management_station", "vsys id": "vsys_name",
            "vsys name": "vsys_display_name", "Config Source": "config_source",
            "Rule": "name", "Source Zone": "from_zone", "Source Address": "source_address_name",
            "Destination Zone": "to_zone", "Destination Address": "destination_address_name",
            "Application": "application", "Service": "service", "Action": "action",
            "Log Start": "log_start", "Log End": "log_end", "Log Profile": "log_setting"},
        # NO entry for wildfire_analysis_submits_all. `query_fields` maps a COLUMN to a
        # searchable field and every key must name a column on this page - and this page has
        # to match the rules page's column set (Jason, 2026-09-18), so the WildFire verdict
        # renders inside the Profiles cell instead, as address breadth does inside the
        # address cell. The field is still searchable: a control's query goes through the
        # search compiler, not through this map.
        columns=("Station", "Appliance", "vsys id", "vsys name", "Order", "Config Source",
                 "Device Group", "Rule", "Source Zone", "Source Address", "Destination Zone",
                 "Destination Address", "Application", "Service", "Action", "Log Start",
                 "Log End", "Log Profile", "Profiles"),
        base_queryset=build_security_rule_display_queryset,
        row=lambda r: (
            str(r.management_station),
            _rule_appliance(r),
            r.enforcement_point.vsys_name,
            r.enforcement_point.vsys_display_name or "-",
            r.effective_order,
            security_rule_config_source_label(r.config_source),
            entry_device_group_name(r) or "-",
            r.name,
            _lines(listed_member_values(r, "securityrulefromzones")),
            _addresses(r, "source_address_refs", r.negate_source, r.source_num_hosts),
            _lines(listed_member_values(r, "securityruletozones")),
            _addresses(r, "destination_address_refs", r.negate_destination,
                       r.destination_num_hosts),
            _lines(listed_member_values(r, "securityruleapplications")),
            _lines(listed_member_values(r, "securityruleservices")),
            r.action or "-",
            _logged(r.log_start),
            _logged(r.log_end),
            r.log_setting or "-",
            _rule_profiles(r),
        ),
    ),
    # --- Device > Setup. Six pages over ONE model, split the way the CONTROLS are: 13 password
    # controls, 4 authentication-settings, 2 login banner, 2 management TLS, 1 master key, and
    # PAN-MGT-009/011 left on Management itself. Jason, 2026-09-10: an object with no control
    # comes out of the view, and these all have one.
    # Device > Setup > Services and Device > Setup > Management > Logging and Reporting.
    # One field each, and their implicit values point OPPOSITE ways - which is the whole reason
    # they are two models and two pages rather than one convenience row.
    # --- Device > Setup ---------------------------------------------------------------------
    # All six were cut out of `DeviceConfigurationProfile` on 2026-09-10, one control cluster
    # at a time, and none of these pages reads it any more.
    "addresses": ResultsSpec(
        query_fields={"Name": "name", "Type": "address_type", "Scope": "namespace_type",
                      "Addresses": "num_hosts", "Referenced": "referenced_by_policy"},
        columns=("Name", "Type", "Scope", "Addresses", "Content", "Referenced"),
        base_queryset=_ordered(AddressObject, "name",
                               related=("enforcement_point", "appliance_group")),
        row=lambda o: (
            o.name,
            o.get_address_type_display(),
            f"{o.namespace_type}:{o.namespace_value}" if o.namespace_value else o.namespace_type,
            # "Unknown" rather than blank or 0. NULL means the size was never established - an
            # EDL nobody collected, or one the device could not fetch - and 0 would read as the
            # narrowest possible object, which is the whole hazard the PAN-COV controls exist
            # for. A blank cell reads as missing data, which is right but says nothing about
            # whether that is expected.
            "Unknown" if o.num_hosts is None else f"{o.num_hosts:,}",
            _resolved_content(o),
            _yes_no(_is_referenced(o)),
        ),
    ),
    "login-banner": ResultsSpec(
        query_fields={"Appliance": "hostname", "Banner": "text",
                      "Acknowledgement Required": "acknowledgement_required"},
        columns=("Appliance", "Banner", "Acknowledgement Required"),
        base_queryset=_ordered(LoginBanner, "appliance__hostname"),
        row=lambda p: (
            str(p.appliance),
            # Truncated: a banner is paragraphs, and the question a query asks of it is whether
            # there is one and roughly what it says. "None" rather than blank, because no
            # banner is the FINDING and a blank cell reads as missing data.
            (p.text[:80] + "\u2026" if len(p.text or "") > 80 else (p.text or "None")),
            _yes_no(p.acknowledgement_required),
        ),
    ),
    "management-tls": ResultsSpec(
        query_fields={"Appliance": "hostname", "Profile": "profile_name",
                      "Certificate": "certificate_name", "Trust": "certificate_trust"},
        columns=("Appliance", "Profile", "Protocol Range", "Certificate", "Trust"),
        base_queryset=_ordered(ManagementTlsBinding, "appliance__hostname",
                               related=("appliance", "ssl_tls_service_profile")),
        row=lambda p: (
            str(p.appliance),
            # No profile bound means the device serves its default certificate over whatever it
            # negotiates, which is the finding PAN-MGT-010 makes - so it is spelled out.
            (f"{p.profile_name} ({p.profile_scope})" if p.profile_name else "None"),
            # Read THROUGH the profile row: these are the values the aggregate copied and let
            # drift. "unresolved" rather than "? - ?" when the name matches no row.
            (f"{p.min_version or '?'} - {p.max_version or '?'}" if p.ssl_tls_service_profile
             else ("unresolved" if p.profile_name else "-")),
            p.certificate_name or "None",
            p.get_certificate_trust_display() if p.certificate_trust else "-",
        ),
    ),
    "management-ssh": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Bound Profile": "profile_name",
            # Each algorithm cell IS its verdict field: "preferred", or the offers that broke
            # it. The names in that cell are the reason, not the value a clause can carry.
            "Ciphers": "ciphers_below_preferred", "KEX": "kex_below_preferred",
            "MACs": "macs_below_preferred"},
        columns=("Appliance", "Bound Profile", "Ciphers", "KEX", "MACs", "Host Key"),
        base_queryset=_ordered(ManagementSshSettings, "appliance__hostname"),
        row=lambda s: (
            str(s.appliance),
            # No profile means the device default, which is the answer - spelled out.
            (s.profile_name if s.profile_found else
             (f"{s.profile_name} (not found)" if s.profile_name else "None - device default")),
            # Each algorithm cell answers the question its control now asks - does the offer hold
            # the preferred value and nothing outside its allowed set - and names what broke it.
            # These columns used to show the minimum-value flags, which no control asserts.
            ("preferred" if not s.ciphers_below_preferred
             else ("\n".join(s.non_preferred_ciphers) or "no aes256-gcm")),
            ("preferred" if not s.kex_below_preferred
             else ("\n".join(s.non_preferred_kex) or "no ECDH")),
            ("preferred" if not s.macs_below_preferred
             else ("\n".join(s.non_preferred_macs) or "no hmac-sha2-512")),
            # NO KEY TYPE CONFIGURED IS THE COMMONEST STATE AND IT HAS TO BE SPELLED OUT, the
            # same way "None - device default" is spelled out for the binding above. Measured by
            # the stage 9 run on `mgmt-crypto`, 2026-11-01, on all three appliances of its
            # reconstructed estate: `host_key_type` is "" and `host_key_bits` is None on two of
            # the three, and this cell interpolated them into the string " None" - a leading
            # space and Python's repr of a null - in the one state PAN-MCR-004 fires on for
            # every appliance in that estate. No test covered it: the one test that renders this
            # row passes `host_key_type="RSA", host_key_bits=2048`.
            #
            # It cannot be inferred either. OptivEdgeIntegrations stores this blank on purpose
            # since 2026-10-06: Help p.904 gives the default as RSA 2048, and a 2026-09-14
            # measurement found that false on any device ever set to `all`, which keeps serving
            # the ECDSA keys it generated after the setting is deleted. So absence means RSA 2048
            # on most devices and something else on an unknown subset, and only the live SSH
            # offer can tell which. The cell says it was not configured and claims nothing about
            # what is served.
            #
            # THE WORDING IS A PROPOSAL, not a decision: a cell a customer reads is Jason's.
            ("All (RSA + every ECDSA curve)" if s.host_key_type.lower() == "all"
             else "None configured" if not s.host_key_type
             # The branch element holds the key length as its text, so a type with no length is
             # not a state the normalizer produces today - and printing the type alone is the
             # answer if it ever does, rather than interpolating a null beside it.
             else f"{s.host_key_type} {s.host_key_bits}" if s.host_key_bits is not None
             else s.host_key_type),
        ),
    ),
    "ntp": ResultsSpec(
        query_fields={"Appliance": "hostname", "Primary": "primary_server",
                      "Secondary": "secondary_server",
                      "Authentication": "all_servers_symmetric_key"},
        columns=("Appliance", "Primary", "Secondary", "Authentication"),
        base_queryset=_ordered(NtpSettings, "appliance__hostname"),
        row=lambda n: (
            str(n.appliance),
            n.primary_server or "None",
            # Spelled out rather than blank: a missing secondary is the finding PAN-SVC-001
            # makes, and an empty cell reads as missing data.
            n.secondary_server or "None",
            ("symmetric key" if n.all_servers_symmetric_key
             else ("\n".join(n.unauthenticated_servers) or "no server configured")),
        ),
    ),
    "snmp": ResultsSpec(
        query_fields={"Appliance": "hostname", "Version": "version",
                      "Exposed": "is_exposed"},
        columns=("Appliance", "Version", "Community", "Exposed"),
        base_queryset=_ordered(SnmpSettings, "appliance__hostname"),
        row=lambda s: (
            str(s.appliance),
            ("Not configured" if not s.is_configured
             else f"{s.version}{' (vendor default)' if s.version_implicit else ''}"),
            ("default string" if s.community_is_default
             else ("set" if s.community_set else "-")),
            # The question the version alone cannot answer: is any of this reachable.
            ("\n".join(s.exposed_surfaces) if s.is_exposed else "no surface enables SNMP"),
        ),
    ),
    "system-identity": ResultsSpec(
        query_fields={"Appliance": "hostname", "Hostname": "configured_hostname",
                      "Time Zone": "timezone", "Management Address": "addressing_mode"},
        columns=("Appliance", "Hostname", "Time Zone", "Management Address"),
        base_queryset=_ordered(SystemIdentity, "appliance__hostname"),
        row=lambda i: (
            str(i.appliance),
            (f"{i.hostname or 'unset'} (factory default)" if i.hostname_is_factory_default
             else i.hostname),
            i.timezone or "unset",
            # "static" and "static because nothing was written" both pass, and they are
            # different configurations - see the tab for why that distinction is kept.
            ("DHCP client" if i.addressing_mode == "dhcp-client"
             else ("Static" if i.addressing_mode_explicit else "Static - by default")),
        ),
    ),
    "authentication-settings": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Idle Timeout": "idle_timeout_minutes",
            "Lockout After": "lockout_failed_attempts", "Lockout Time": "lockout_time_minutes",
            "API Key Lifetime": "api_key_lifetime_minutes"},
        columns=("Appliance", "Idle Timeout", "Lockout After", "Lockout Time",
                 "API Key Lifetime"),
        base_queryset=_ordered(AuthenticationSettings, "appliance__hostname"),
        row=lambda p: (
            str(p.appliance),
            # 0 is not strict on three of these four - no idle timeout, unlimited attempts, a
            # key that never expires - and IS strict on the fourth, where it means held until
            # released. The number alone reverses three cells out of four.
            "never" if not p.idle_timeout_minutes else f"{p.idle_timeout_minutes} min",
            ("unlimited attempts" if not p.lockout_failed_attempts
             else f"{p.lockout_failed_attempts} attempts"),
            # And NULL is not 0 on this one. The column became nullable on 2026-10-29 so an
            # unread node stores nothing; a falsiness test printed "until released" - the strict
            # reading - for a device nobody had measured.
            ("not established" if p.lockout_time_minutes is None
             else "until released" if not p.lockout_time_minutes
             else f"{p.lockout_time_minutes} min"),
            "never" if not p.api_key_lifetime_minutes else f"{p.api_key_lifetime_minutes} min",
        ),
    ),
    "password-complexity": ResultsSpec(
        query_fields={"Appliance": "hostname", "Complexity": "enabled",
                      "Min Length": "minimum_length", "Expires": "expiration_period",
                      "History": "history_count"},
        columns=("Appliance", "Complexity", "Min Length", "Character Classes", "Expires",
                 "History"),
        base_queryset=_ordered(PasswordComplexityPolicy, "appliance__hostname"),
        row=lambda p: (
            str(p.appliance),
            # The switch first: every other cell on this row is unenforced without it.
            _yes_no(p.enabled),
            p.minimum_length or "none",
            # The four class minimums as one cell: they are read together, and four columns of
            # single digits is four columns nobody scans.
            f"U{p.minimum_uppercase} L{p.minimum_lowercase} "
            f"N{p.minimum_numeric} S{p.minimum_special}",
            "never" if not p.expiration_period else f"{p.expiration_period} days",
            _nothing(p.history_count, "remembered"),
        ),
    ),
    "master-key": ResultsSpec(
        query_fields={"Appliance": "hostname", "State": "state",
                      "On HSM": "on_hsm"},
        columns=("Appliance", "State", "Expires", "On HSM"),
        base_queryset=_ordered(MasterKey, "appliance__hostname"),
        row=lambda p: (
            str(p.appliance),
            # Three states, and two of them fire: a factory key is a device nobody hardened,
            # undetermined is a device nobody asked.
            p.state,
            p.expires_at or "-",
            _yes_no(p.on_hsm),
        ),
    ),
    "services": ResultsSpec(
        query_fields={"Appliance": "hostname",
                      "Verify Update Server Identity": "verify_identity"},
        columns=("Appliance", "Verify Update Server Identity"),
        base_queryset=_ordered(UpdateServerSettings, "appliance__hostname"),
        row=lambda p: (str(p.appliance), _yes_no(p.verify_identity)),
    ),
    # Device > Setup > WildFire. PAN-AVW-004 and PAN-AVW-005 - the DEVICE-WIDE settings, as
    # against the WildFire analysis PROFILE that PAN-AVW-003 reads. The profile says what is
    # asked for; these say what the platform forwards.
    "wildfire-settings": ResultsSpec(
        query_fields={"Appliance": "hostname",
                      "File size limits untuned": "size_limits_untuned",
                      "Full session info": "shares_full_session_info",
                      "Report benign": "report_benign_file",
                      "Report grayware": "report_grayware_file"},
        columns=("Appliance", "File size limits untuned", "Still at default",
                 "Full session info", "Withheld", "Report benign", "Report grayware"),
        base_queryset=_ordered(WildfireSettings, "appliance__hostname"),
        row=lambda p: (
            str(p.appliance),
            _yes_no(p.size_limits_untuned),
            # The list, not just the verdict: an engineer needs to know WHICH types nobody
            # sized, and the count alone sends them back to the device to find out.
            _lines(p.untuned_file_types) if p.untuned_file_types else "none",
            _yes_no(p.shares_full_session_info),
            # Empty is the GOOD state here - the config stores exclusions - so the cell says
            # "nothing withheld" rather than leaving a blank that reads as missing data.
            (_lines(sorted(p.session_info_excluded)) if p.session_info_excluded
             else "nothing withheld"),
            _yes_no(p.report_benign_file),
            _yes_no(p.report_grayware_file),
        ),
    ),
    # --- Policies > Security, second rail item: the virtual system's policy taken as a whole.
    # Every column but the first two is a VERDICT this assessment computed over the vsys's
    # stored rules, which is why the page says so in its headings ("exists", "answered") rather
    # than printing a bare yes/no that reads like a key off the device.
    #
    # `Firewalls` has no `query_fields` entry and cannot have one: it lists the HA pair, and a
    # clause over one hostname would not select the row it was read from - the model's own
    # appliance FK is NULL for a pair. That is the composite-column case this map's own comment
    # describes.
    "rule-posture": ResultsSpec(
        query_fields={
            "Vsys": "vsys_name",
            "Rulebase read answered": "rules_collected",
            "Logged catch-all deny": "has_logged_catch_all_deny",
            "Default rules log at session end": "default_rules_log_session_end",
            "Application block above the permits": "has_application_block_rule_above_permits",
            "Hostile-list directions unblocked":
                "vendor_hostile_list_block_directions_missing",
            "Geography expressed": "expresses_geographic_boundary",
            "Port-matched block rule": "has_port_matched_block_rule"},
        columns=("Firewalls", "Vsys", "Rulebase read answered", "Logged catch-all deny",
                 "Default rules log at session end", "Application block above the permits",
                 "Hostile-list directions unblocked", "Geography expressed",
                 "Pre-staged blocklist rule", "Port-matched block rule"),
        base_queryset=lambda: (VsysRulePosture.objects
                               .select_related("enforcement_point__appliance",
                                               "enforcement_point__appliance_group")
                               .prefetch_related("enforcement_point__appliance_group__appliances")
                               .order_by("enforcement_point__appliance_group__name",
                                         "enforcement_point__appliance__hostname",
                                         "enforcement_point__vsys_name")),
        row=lambda p: (
            _enforced_by(p.enforcement_point),
            p.enforcement_point.vsys_name or "-",
            _yes_no(p.rules_collected),
            _yes_no(p.has_logged_catch_all_deny),
            _yes_no(p.default_rules_log_session_end),
            _yes_no(p.has_application_block_rule_above_permits),
            # A count of two, printed as the number: 0 is healthy and 2 is the default and the
            # worst band. `_nothing` would print "Nothing" for the healthy end, which on a
            # column named for what is MISSING reads as "not counted".
            str(p.vendor_hostile_list_block_directions_missing),
            _yes_no(p.expresses_geographic_boundary),
            # NO CONTROL CLAUSES ON THIS ONE, so it is a column with no `query_fields` entry
            # rather than an omission: the model carries it, no shipped query reads it, and
            # showing it is how an assessor can see the answer before a control exists for it.
            _yes_no(p.has_prestaged_blocklist_rule),
            _yes_no(p.has_port_matched_block_rule),
        ),
    ),
    # --- Policies > Security, third rail item: the same rule set read for ONE dimension, which
    # is whether any rule that permits traffic matches on what the connecting device is.
    # PAN-IOT-004. Laid out on `rule-posture`'s pattern above because it is the same shape.
    #
    # `Firewalls` has no `query_fields` entry for the reason that entry gives: it lists the HA
    # pair, and a clause over one hostname would not select the row it was read from.
    #
    # NEITHER COUNT IS QUERYABLE and both are on the row. Only `has_no_rule_matching_on_device`
    # is registered in the search compiler - the repo's rule is that a column a control asks for
    # is registered and no other - so the two counts are display columns, the `rule-posture`
    # precedent for a presented-but-unqueried column. They are what makes the verdict
    # ACTIONABLE: zero visible device objects means no rule COULD name a device even if somebody
    # wrote one, so the work is to define the objects; a non-zero count means the objects exist
    # and the policy does not use them. Two different pieces of work behind one verdict.
    "rulebase-device-match": ResultsSpec(
        query_fields={
            "Vsys": "vsys_name",
            # NAMED IN THE FIELD'S OWN POLARITY, deliberately. True is the default AND the
            # firing side, so a heading like "Policy matches on a device" would put the word
            # "No" in the firing cell and "Yes" in the healthy one - and a reader scanning a
            # column of Yes/No beside a finding must not be able to read the firing cell as a
            # pass. This way the firing cell reads Yes to a question whose Yes is plainly bad.
            "Device dimension absent from the rule set": "has_no_rule_matching_on_device"},
        columns=("Firewalls", "Vsys", "Device dimension absent from the rule set",
                 "Rules matching on a device", "Device objects visible here"),
        base_queryset=lambda: (RulebaseDeviceMatchVerdict.objects
                               .select_related("enforcement_point__appliance",
                                               "enforcement_point__appliance_group")
                               .prefetch_related("enforcement_point__appliance_group__appliances")
                               .order_by("enforcement_point__appliance_group__name",
                                         "enforcement_point__appliance__hostname",
                                         "enforcement_point__vsys_name")),
        row=lambda v: (
            _enforced_by(v.enforcement_point),
            v.enforcement_point.vsys_name or "-",
            _yes_no(v.has_no_rule_matching_on_device),
            # Printed as the number, on `rule-posture`'s ruling for a count column.
            device_id.rules_matching_count(v),
            device_id.device_objects_visible(v),
        ),
    ),
    # --- Network > Zones. THE PAGE THREE DOMAINS SHARE, and the columns are the union of what
    # all three ask: PAN-IOT-002 over the Device-ID switch and its narrowing, `user-id` (PAN-UID)
    # over the User-ID switch, and `zone-dos-protection` (PAN-ZON) over the protection-profile
    # attachment. Both later domains run after this one and reuse this entry; a column either of
    # them needs and this page lacks is theirs to add, and the rail item will not have to move.
    #
    # THE TWO DEVICE-ID LISTS ARE DISPLAY-ONLY AND CANNOT BE OTHERWISE. They are JSON columns, a
    # JSON column is reachable from no query in this language, and a consumer test compiles every
    # registered field to assert that no JSON column is reachable - so stage 5 marks them
    # `not_searchable` and the verdict is taken on the derived `device_identification_is_narrowed`
    # beside them. They are here so a reviewer can read the members they have to go and look at.
    #
    # AND THEY READ `Any` / `None` WHEN EMPTY RATHER THAN BLANK. Stage 4 measured the vendor's own
    # grid on two platforms: with no `device-acl` node INCLUDED NETWORKS renders `any` and
    # EXCLUDED renders `none`, so an empty include list means identification applies to EVERY
    # address in the zone - the most permissive state and the COMPLIANT one for this control. A
    # blank cell here is the first of this stage's three recorded presentation failures verbatim.
    #
    # `zone_protection_profile` IS SHOWN AND NOT QUERYABLE, and that is the compiler's standing
    # decision rather than an omission here: a clause on the name PASSES exactly the dangling-name
    # case the column exists to catch, so `zone_protection_unresolved` is the registered one.
    "zones": ResultsSpec(
        query_fields={
            "Appliance": "hostname",
            "Vsys": "vsys_name",
            "Zone": "name",
            "Type": "zone_type",
            "Carries traffic": "can_receive_traffic",
            "Device identification on": "enable_device_identification",
            "Device identification narrowed": "device_identification_is_narrowed",
            "Device-ID lists read": "device_acl_lists_computed",
            "User identification on": "enable_user_identification",
            "Zone protection unresolved": "zone_protection_unresolved"},
        columns=("Appliance", "Vsys", "Zone", "Type", "Carries traffic",
                 "Device identification on", "Device identification narrowed",
                 "Device-ID address list (include)", "Device-ID address list (exclude)",
                 "Device-ID lists read", "User identification on",
                 "Zone protection profile", "Zone protection unresolved"),
        base_queryset=lambda: (Zone.objects
                               .select_related("enforcement_point__appliance",
                                               "enforcement_point__appliance_group")
                               .order_by("enforcement_point__appliance__hostname",
                                         "enforcement_point__vsys_name", "name")),
        row=lambda z: (
            # THE PAIR, NOT ONE MEMBER, and `Appliance` IS still queryable here - which departs
            # from `rule-posture`'s ruling above for a measured reason. That entry gives its
            # `Firewalls` column no `query_fields` entry because a clause over one hostname would
            # not select the row it was read from. The zone compiler's `hostname` field is built
            # over BOTH `enforcement_point__appliance__hostname` AND
            # `enforcement_point__appliance_group__appliances__hostname`, so a clause naming
            # either member of a pair does select the pair's row.
            _enforced_by(z.enforcement_point),
            z.enforcement_point.vsys_name or "-",
            z.name or "-",
            z.get_zone_type_display(),
            _yes_no(z.can_receive_traffic),
            _yes_no(z.enable_device_identification),
            _yes_no(z.device_identification_is_narrowed),
            device_id.device_include_members(z),
            device_id.device_exclude_members(z),
            _yes_no(z.device_acl_lists_computed),
            _yes_no(z.enable_user_identification),
            # The attachment as written. Its WORDING belongs to `zone-dos-protection`, whose
            # controls are about this column and which runs after this domain; "-" is the repo's
            # convention for an absent text value and is left for that run to improve. The
            # verdict beside it is what any control reads, because the name alone is the naive
            # reading: a zone naming a profile that does not exist reads as configured.
            z.zone_protection_profile or "-",
            _yes_no(z.zone_protection_unresolved),
        ),
    ),
    # --- Device > Licenses: one appliance's whole device-identification service state.
    # PAN-IOT-001 and PAN-IOT-003.
    #
    # THREE UNRELATED INSTRUMENTS LAND ON THIS ROW and a reader has to be able to tell which one
    # answered, which is what the column order is for: the entitlement first, then whether the
    # licence listing was even taken, then the wiring, then the content. Four of the model's
    # columns are not registered in the search compiler and are display-only - the version, the
    # release date as written, and the two `show iot icd version` build columns.
    #
    # THE TWO CONTENT INSTRUMENTS RANK THIS ESTATE IN OPPOSITE ORDERS and both are on the row on
    # purpose. `Device dictionary version` and its release date are what PAN-IOT-003 grades;
    # `Classification data build` is the one it must NOT grade, because build dates are
    # 2026-02-06 on the two PA-5220s against 2024-07-22 on pan-fw-111 while the content versions
    # are 82-406 against 249-772 - a gap of 167 releases the other way. A reader shown only the
    # build date would call the two most stale appliances the freshest in the estate.
    #
    # `Content age (days)` READS AN EM DASH where no release date was reported, not a blank and
    # not a zero: the comparison was not made, and the column beside it says why.
    "iot-security": ResultsSpec(
        query_fields={
            "Appliance": "hostname",
            "Serial": "serial_number",
            "IoT Security subscription in force": "device_id_licensed",
            "Licence listing answered": "licence_read_taken",
            "Edge service address": "edge_service_address",
            "Content release date reported": "device_dictionary_release_date_known",
            "Content age (days)": "device_dictionary_age_days"},
        columns=("Appliance", "Serial", "IoT Security subscription in force",
                 "Licence listing answered", "Edge service address",
                 "Device dictionary version", "Content release date (as written)",
                 "Content release date reported", "Content age (days)",
                 "Classification data build", "Classification data built"),
        base_queryset=_ordered(DeviceIdentificationState, "appliance__hostname"),
        row=lambda s: (
            str(s.appliance),
            s.appliance.serial_number or "-",
            _yes_no(s.device_id_licensed),
            _yes_no(s.licence_read_taken),
            # EMPTY IS THE FIRING STATE of PAN-IOT-001's second half and the measured state of
            # every appliance in the lab - the node is absent on all four - so the cell says the
            # wiring is absent rather than leaving a blank that reads as unfilled.
            #
            # IT DIFFERS FROM THE FINDINGS TAB ON PURPOSE. There the same field reads
            # `display_value`'s `(empty)`, because giving it a `value_readers` entry would
            # discard the field's own `FieldProvenance` row and whether the key was absent,
            # explicitly blank or template-supplied is half of what the control is about. This
            # page has no provenance column to protect, so it can say the plainer thing.
            #
            # NOT `_nothing`, which is a COUNT helper taking (count, unit) and reads "Nothing"
            # for a falsy count. Called with one text argument it raises TypeError - caught here
            # by `test_device_id_tabs`, because the shipped squareness check has fixtures for one
            # model and never calls a new page's lambda.
            s.edge_service_address or "Not configured",
            device_id.dictionary_version(s),
            device_id.release_date(s),
            _yes_no(s.device_dictionary_release_date_known),
            device_id.content_age_days(s),
            device_id.icd_build(s),
            device_id.icd_built_at(s),
        ),
    ),
    # --- Device > User Identification > User Mapping ---------------------------------------
    # The two User-ID objects, 2026-11-02, for the PAN-UID controls: the agent's own setup and
    # the list that bounds where it looks. Both subjects are VSYS-SCOPED - they hang off an
    # EnforcementPoint - so neither can use `_ordered`, whose default `related=("appliance",)`
    # names a field neither model has.
    #
    # `Appliance` IS QUERYABLE ON BOTH, on the `zones` entry's measured reasoning above and not
    # on `rule-posture`'s: both compilers build `hostname` over BOTH
    # `enforcement_point__appliance__hostname` AND
    # `enforcement_point__appliance_group__appliances__hostname`, so a clause naming either
    # member of a pair selects the pair's row.
    "user-id-collector": ResultsSpec(
        query_fields={"Appliance": "hostname", "Vsys": "vsys_name",
                      "Client probing": "enable_probing",
                      "Server monitor account": "wmi_account",
                      "Session reading": "enable_session",
                      "Mappings expire": "enable_mapping_timeout",
                      "Mapping lifetime (min)": "ip_user_mapping_timeout",
                      "Syslog TLS profile": "syslog_service_profile"},
        columns=("Appliance", "Vsys", "Client probing", "Server monitor account",
                 "Session reading", "Mappings expire", "Mapping lifetime (min)",
                 "Syslog TLS profile"),
        base_queryset=lambda: (UserIdCollectorSettings.objects
                               .select_related("enforcement_point__appliance",
                                               "enforcement_point__appliance_group")
                               .order_by("enforcement_point__appliance__hostname",
                                         "enforcement_point__vsys_name")),
        row=lambda c: (
            _enforced_by(c.enforcement_point),
            c.enforcement_point.vsys_name or "-",
            _yes_no(c.enable_probing),
            # THE BARE STRING AND NOT A YES/NO, because the firing direction is NON-empty and the
            # name is what an engineer needs in order to go and ask the directory what the
            # account may do - which is the half of this control no firewall read can answer.
            c.wmi_account or "-",
            _yes_no(c.enable_session),
            # THE COLUMN A READER IS MOST LIKELY TO INVERT, and the heading says `expire` for
            # that reason: TRUE is the compliant side here where it is the firing side on the two
            # columns above it.
            _yes_no(c.enable_mapping_timeout),
            # Printed as a number: a word here would read as "not counted". It bounds nothing at
            # all where the column before it is No, which is why the two sit side by side.
            c.ip_user_mapping_timeout,
            c.syslog_service_profile or "-",
        ),
    ),
    "user-id-discovery": ResultsSpec(
        query_fields={"Appliance": "hostname", "Vsys": "vsys_name",
                      "Discovery list shape": "list_shape",
                      "Include entries in force": "include_entry_count",
                      "Exclude entries in force": "exclude_entry_count"},
        # `Included ranges` HAS NO `query_fields` ENTRY, deliberately. `include_networks` is a
        # JSONField and is NOT registered in the compiler - a JSON lookup is unindexed and
        # matches nothing when the vendor renames a key, so a control resting on one stops
        # finding anything instead of failing. Mapping the heading to it would point the "build a
        # query from these rows" button at a lookup that silently selects nothing. The verdict
        # column beside it is what a query should carry.
        columns=("Appliance", "Vsys", "Discovery list shape", "Include entries in force",
                 "Exclude entries in force", "Included ranges"),
        base_queryset=lambda: (UserIdDiscoveryBound.objects
                               .select_related("enforcement_point__appliance",
                                               "enforcement_point__appliance_group")
                               .order_by("enforcement_point__appliance__hostname",
                                         "enforcement_point__vsys_name")),
        row=lambda b: (
            _enforced_by(b.enforcement_point),
            b.enforcement_point.vsys_name or "-",
            # SHARED WITH THE WORKBOOK TAB rather than spelled again here, which is what keeps
            # the two surfaces from disagreeing about one object. The blank fifth state is why
            # this is not `b.get_list_shape_display()`: see `user_id_presentation.list_shape`.
            user_id.list_shape(b),
            b.include_entry_count,
            b.exclude_entry_count,
            user_id.include_networks(b),
        ),
    ),
    "logging-and-reporting": ResultsSpec(
        query_fields={"Appliance": "hostname",
                      "Log on High DP Load": "log_on_high_dp_load"},
        columns=("Appliance", "Log on High DP Load"),
        base_queryset=_ordered(LoggingSettings, "appliance__hostname"),
        row=lambda p: (str(p.appliance), _yes_no(p.log_on_high_dp_load)),
    ),
    # --- Device > Setup > Management > Policy Rulebase Settings, 2026-11-01. Both columns are
    # NULLABLE and `_tri` is used rather than `_yes_no`, because NULL here is the firing side:
    # the key is absent and nobody has established what an absent key does.
    #
    # THE SHADOW COLUMN KEEPS THE DEVICE'S POLARITY, so the heading names the SUPPRESSION. A
    # heading reading "Shadow-rule check" above a cell reading "yes" would say the opposite of
    # what the device means by the key.
    "policy-rule-settings": ResultsSpec(
        query_fields={"Appliance": "hostname",
                      "Rule hit count enabled": "rule_hit_count_enabled",
                      "Shadow-rule check suppressed": "disable_shadow_rule_check"},
        columns=("Appliance", "Rule hit count enabled", "Shadow-rule check suppressed"),
        base_queryset=_ordered(PolicyRuleSettings, "appliance__hostname"),
        row=lambda s: (str(s.appliance), _tri(s.rule_hit_count_enabled),
                       _tri(s.disable_shadow_rule_check)),
    ),
    "interfaces": ResultsSpec(
        query_fields={"Appliance": "hostname", "Plane": "plane",
                      "Interface": "interface_name", "Interface Profile": "profile_name"},
        columns=("Appliance", "Plane", "Interface", "Interface Profile"),
        base_queryset=_ordered(ManagementInterface, "appliance__hostname", "plane",
                               "interface_name"),
        row=lambda s: (
            str(s.appliance),
            s.plane or "-",
            s.interface_name or "-",
            # A data-plane surface with no profile permits nothing, which is the safe end of
            # this column and must not read as missing data.
            s.profile_name or "None",
        ),
    ),
    # --- Device, top-level rail items -----------------------------------------------------
    # --- Objects > Security Profiles. Two rail items over ONE model, split by kind the way PAN-OS
    # splits them; each page's base queryset is its own kind.
    "anti-spyware": ResultsSpec(
        query_fields={
            "Profile": "name", "Scope": "namespace_type", "Critical": "critical_blocked",
            "High": "high_blocked", "Medium": "medium_blocked", "Used by": "referrer_count"},
        columns=("Owner", "Profile", "Scope", "Critical", "High", "Medium", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("spyware"),
        row=lambda p: _security_profile_row(p),
    ),
    "vulnerability-protection": ResultsSpec(
        query_fields={
            "Profile": "name", "Scope": "namespace_type", "Critical": "critical_blocked",
            "High": "high_blocked", "Medium": "medium_blocked", "Used by": "referrer_count"},
        columns=("Owner", "Profile", "Scope", "Critical", "High", "Medium", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("vulnerability"),
        row=lambda p: _security_profile_row(p),
    ),
    # Antivirus is the third kind and it does NOT get the severity columns: it has no severity
    # rules, so critical/high/medium read n/a for every row. What it has instead is a decoder
    # per protocol, and the action that matters is the RESOLVED one - the configuration says
    # `default` on every decoder of every unedited profile, including the shipped one.
    "antivirus": ResultsSpec(
        query_fields={
            "Profile": "name", "Scope": "namespace_type",
            "Signature action allows": "has_non_blocking_decoder",
            "WildFire signature action allows": "has_non_blocking_wildfire_decoder",
            "WildFire inline ML action allows": "has_non_blocking_mlav_decoder",
            "Inline ML models not blocking": "has_non_blocking_ml_model",
            # PAN-OS calls this tab Application Exceptions. The column follows the vendor's
            # words, because the audit text sends an assessor to that tab by name.
            "Application exceptions": "has_non_blocking_application_override",
            "Used by": "referrer_count"},
        columns=("Owner", "Profile", "Scope", "Decoders", "Signature action allows",
                 "WildFire signature action allows", "WildFire inline ML action allows",
                 "Inline ML models not blocking", "Application exceptions", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("virus"),
        row=lambda p: (
            p.appliance_group.name if p.appliance_group_id else str(p.enforcement_point),
            p.name,
            p.get_namespace_type_display(),
            _decoder_actions(p),
            _lines(p.non_blocking_decoders) if p.non_blocking_decoders else "none",
            (_lines(p.non_blocking_wildfire_decoders)
             if p.non_blocking_wildfire_decoders else "none"),
            (_lines(p.non_blocking_mlav_decoders)
             if p.non_blocking_mlav_decoders else "none"),
            _lines(p.non_blocking_ml_models) if p.non_blocking_ml_models else "none",
            # "none" rather than a blank: almost every profile has no override at all, and a
            # blank cell would not say whether that was looked at.
            (_lines(p.non_blocking_application_overrides)
             if p.non_blocking_application_overrides else "none"),
            p.referrer_count,
        ),
    ),
    # WildFire analysis profiles decide which files go to the sandbox. No decoders, no ML
    # models and no severity verdict - their content is a rule list, which PAN-AVW-003 will
    # assess. This page exists so they are visible and so PAN-AVW-006 has somewhere to send an
    # assessor once it covers them.
    "wildfire-analysis": ResultsSpec(
        query_fields={"Profile": "name", "Scope": "namespace_type",
                      "Rules": "rule_count", "Used by": "referrer_count"},
        columns=("Owner", "Profile", "Scope", "Rules", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("wildfire-analysis"),
        row=lambda p: (
            p.appliance_group.name if p.appliance_group_id else str(p.enforcement_point),
            p.name,
            p.get_namespace_type_display(),
            p.rule_count,
            p.referrer_count,
        ),
    ),
    # --- Objects > Security Profiles > File Blocking and > Data Filtering, 2026-11-02, for
    # PAN-FIL-001 to -004. The SIXTH and SEVENTH pages over `SecurityProfile` and the first time
    # one domain added two: this domain spans TWO kinds, so each gets its own page scoped by its
    # own single `kind eq` clause, exactly as the five above are.
    #
    # EVERY HEADING BELOW IS A PROPOSAL, on `artifacts/sheets/objects.py`'s own terms - Jason
    # takes the heading pass once across many domains (P399). Each is sourced in its comment:
    # where the vendor's own help has the word this uses it, and WHERE THE VENDOR HAS NO WORD the
    # comment says so rather than implying one.
    #
    # Objects > Security Profiles > URL Filtering, 2026-11-02, for PAN-URL-001 to -005 - the
    # EIGHTH page over `integrations.SecurityProfile`, and ONE page for five controls because all
    # five carry `kind eq "url-filtering"` and nothing else.
    #
    # EVERY HEADING HERE IS A PROPOSAL. Report content is Jason's and he takes the heading pass
    # once across many domains (P399). Each is sourced below to the vendor's own words where the
    # vendor has them, and SAYS SO WHERE IT DOES NOT.
    #
    # WHAT THE VENDOR CALLS THESE THINGS, measured across three Help versions rather than assumed.
    # PAN-OS Web Interface Help 11.2 p.296-299 (Objects > Security Profiles > URL Filtering) gives
    # `Category`, `Site Access`, `User Credential Submission` and `Log container page only`
    # verbatim, and names the six Site Access actions - alert, allow, block, continue, override,
    # and `none` for a custom category only. BUT `probe.corpus --all` returns NOTHING for
    # `Inline Categorization`, `User Credential Detection` or `HTTP Header Logging` in help 11.1,
    # 11.2 OR 12.2 - a complete count, so that is silence worth citing: the Web Interface Help has
    # no label for those three screens at all. The URL Filtering admin guide p.59 and p.61 do, and
    # the headings below take them from there: `Advanced URL Inline Categorization`, `Enable local
    # Inline Categorization`, `Enable cloud Inline Categorization`, `HTTP Header Logging`,
    # `User Credential Detection` and its methods `Use IP User Mapping`, `Use Domain Credential
    # Filter` and `Use Group Mapping`, and `URL exceptions` for the exemption list.
    #
    # THE TWO COMPANION COLUMNS SIT BESIDE THE VERDICT THEY QUALIFY, and on this page that is
    # load-bearing rather than tidy. `worst_reachable_unlogged_category` is NULL FOR TWO DIFFERENT
    # REASONS - the category list was never read, or every reachable category IS logged - and the
    # cell cannot tell them apart on its own. `category_catalogue_collected` is the only thing
    # that resolves it, so it is drawn immediately before the pair it qualifies rather than at the
    # end of the row. Same for the exemption list and `inline_analysis_exemptions_computed`.
    #
    # `log_http_header_user_agent` IS DELIBERATELY ABSENT FROM `query_fields`, and that is measured
    # rather than an oversight: the search compiler registers `log_http_header_referer` and
    # `log_http_header_xff` and NOT the user-agent key, so a heading mapped to it would point the
    # "build a query from these rows" button at a lookup that refuses itself. The three headers are
    # presented through `records_all_request_headers` and `worst_unrecorded_request_header`, both
    # registered. `category_catalogue_size` is likewise unregistered and has no entry here.
    "url-filtering": ResultsSpec(
        query_fields={
            "Profile": "name", "Scope": "namespace_type",
            # INHERITED, not chosen: set by stage 9 of `file-data-filtering` on 2026-11-02 and
            # kept character for character so one column does not read two ways on two surfaces.
            "Vendor-shipped": "is_predefined",
            # OURS. The vendor's p.297 instruction is "Block all known dangerous URL categories"
            # over a list of ELEVEN; this column is over the THREE the model calls confirmed
            # hostile (`HOSTILE_URL_CATEGORIES`), so "dangerous categories" would overstate the
            # question by eight categories. The heading is built from the vendor's own three
            # category NAMES instead, which is the one wording that cannot be read too widely.
            "Malware, phishing and command-and-control blocked":
                "all_hostile_categories_blocked",
            # "Site Access" is the vendor's own column name, p.297. "Weakest" is ours, and is the
            # same convention `file-blocking` uses above: the column stores the weakest action in
            # force across the three, because a profile that blocks two of them and warns on the
            # third is not protected by the two.
            "Weakest Site Access on those categories": "weakest_hostile_category_action",
            # OURS. The vendor has the verb and not a label: p.297, "allow—...Because allow
            # doesn't log unblocked traffic, set alert as the Action for categories of traffic you
            # don't block if you want to log the access attempts". "Reachable" is ours and names
            # the denominator - a category the profile blocks outright is not reachable, and one at
            # the inert action matches nothing, so neither is counted as unlogged.
            "Every reachable category logged": "all_reachable_categories_logged",
            "Worst unlogged category": "worst_reachable_unlogged_category",
            # A COMPANION COLUMN, headed as the QUESTION IT ANSWERS rather than as a setting,
            # because a `no` here means this assessment never established the category population
            # and NOT that the device is set a particular way. Phrased as a question for the
            # reason `device-id-iot` gave: a reader meets "was this established?" and only then
            # "what did it establish?".
            "Category list read from the device?": "category_catalogue_collected",
            # THE VENDOR'S OWN LABEL, exactly: the drop-down is called "User Credential Detection"
            # (URL Filtering admin guide p.61, p.132). Note the Web Interface Help is silent on it
            # in all three versions, so this one is sourced to the admin guide alone.
            "User Credential Detection": "credential_detection_mode",
            # "User Credential Submission" is the vendor's column, p.298. "Restricted" is ours and
            # is deliberately weaker than "blocked": the column is satisfied by `block` OR by the
            # category being unreachable, which is not the same claim as the one below it.
            "Every reachable category restricts credential submission":
                "all_reachable_categories_credential_restricted",
            "Credential submission blocked on every category":
                "credential_submission_blocked_for_every_category",
            "Worst category accepting credentials": "worst_credential_permissive_category",
            # "HTTP Header Logging" is the vendor's own label (admin guide p.59, "Enabling HTTP
            # Header Logging provides visibility into the attributes in the HTTP request sent to a
            # server"), and the three header names are the vendor's: X-Forwarded-For, User-Agent,
            # Referer. "All three" is ours and is a fact about the device - the object offers these
            # three and no more on all four lab appliances.
            "All three HTTP headers logged": "records_all_request_headers",
            "Worst HTTP header not logged": "worst_unrecorded_request_header",
            # THE VENDOR'S OWN LABELS from the admin guide p.59, minus its "Enable " prefix, which
            # names the checkbox rather than the state: "Enable cloud Inline Categorization" and
            # "Enable local Inline Categorization". The screen they live on the vendor calls
            # "Advanced URL Inline Categorization".
            "Cloud Inline Categorization": "cloud_inline_categorization",
            "Local Inline Categorization": "local_inline_categorization_on",
            # "URL exceptions" is the vendor's noun, admin guide p.59: "Use the Advanced URL
            # Inline Categorization to enable and configure real-time web page analysis and manage
            # URL exceptions." "Broadest" is ours and ranks the two stored category types.
            "URL exceptions": "inline_analysis_exemption_count",
            "Broadest URL exception": "broadest_inline_analysis_exemption_type",
            # THE SECOND COMPANION COLUMN. See the first.
            "Exception list read from the device?": "inline_analysis_exemptions_computed",
            "Used by": "referrer_count"},
        columns=("Owner", "Profile", "Scope", "Vendor-shipped",
                 "Malware, phishing and command-and-control blocked",
                 "Weakest Site Access on those categories",
                 "Category list read from the device?",
                 "Every reachable category logged", "Worst unlogged category",
                 "User Credential Detection",
                 "Every reachable category restricts credential submission",
                 "Credential submission blocked on every category",
                 "Worst category accepting credentials",
                 "All three HTTP headers logged", "Worst HTTP header not logged",
                 "Cloud Inline Categorization", "Local Inline Categorization",
                 "Exception list read from the device?",
                 "URL exceptions", "Broadest URL exception", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("url-filtering"),
        row=lambda p: (
            p.appliance_group.name if p.appliance_group_id else str(p.enforcement_point),
            p.name,
            p.get_namespace_type_display(),
            _yes_no(p.is_predefined),
            _yes_no(p.all_hostile_categories_blocked),
            _url_action(p.weakest_hostile_category_action),
            _yes_no(p.category_catalogue_collected),
            _yes_no(p.all_reachable_categories_logged),
            _worst_category(p.worst_reachable_unlogged_category,
                            p.category_catalogue_collected),
            _credential_mode(p.credential_detection_mode),
            _yes_no(p.all_reachable_categories_credential_restricted),
            _yes_no(p.credential_submission_blocked_for_every_category),
            _worst_category(p.worst_credential_permissive_category,
                            p.category_catalogue_collected),
            _yes_no(p.records_all_request_headers),
            # The store holds "" when every header IS logged, which is the passing state - so an
            # empty cell here would be the most reassuring thing on the row and would read as
            # missing data. Named instead.
            p.worst_unrecorded_request_header or "None missing",
            _yes_no(p.cloud_inline_categorization),
            # THREE-STATE AND NOT TWO. `local_inline_categorization` is nullable and NULL is the
            # firing side: on a PA-VM an absent key means the engine is ON, and on other platforms
            # nobody established what it means, so `local_inline_categorization_on` is False for
            # both "switched off" and "never established". The undetermined flag is what separates
            # them and this cell reads it rather than printing a bare "no".
            "not read" if p.local_inline_categorization_undetermined
            else _yes_no(p.local_inline_categorization_on),
            _yes_no(p.inline_analysis_exemptions_computed),
            _nothing(p.inline_analysis_exemption_count, "exception(s)"),
            # NULL here is not "none": an exemption whose target category row is missing resolves
            # to no type at all, so the column is null both for "no exemptions" and for "the
            # exemption names something this assessment never read".
            p.broadest_inline_analysis_exemption_type
            or ("Nothing exempted" if not p.inline_analysis_exemption_count
                else "Exempted category not read"),
            _nothing(p.referrer_count, "referrer(s)"),
        ),
    ),
    # Objects > Custom Objects > URL Category, 2026-11-02, for PAN-URL-006 - the first page over
    # `integrations.CustomUrlCategory`, which stage 7 minted for this domain and which had never
    # been queried from this repository at all.
    #
    # NO `scope`, and that is required rather than tidy: its model has exactly ONE page, so
    # `object_for_canonical_query` short-circuits on the single candidate and a scope would be
    # dead weight a later second page would have to reckon with. Same call as
    # `data-filtering-posture`.
    #
    # EVERY HEADING IS A PROPOSAL (P399). The vendor's own labels are from Web Interface Help 11.2
    # p.270-271 (Objects > Custom Objects > URL Category): `Name`, `Description`, `Type` with the
    # two values `Category Match` and `URL List`, `Shared`, and `Sites` for the member list.
    #
    # ONLY ELEVEN FIELDS OF THIS MODEL ARE REGISTERED IN THE SEARCH COMPILER and the headings here
    # are held to them: `match_entries` and `reference_surfaces_searched` are JSONFields that the
    # compiler deliberately does not register, so the two columns presenting them carry NO
    # `query_fields` entry and their scalar neighbours `match_entry_count` and `referrer_count`
    # stand in for them. A heading mapped to an unregistered field would point the "build a query
    # from these rows" button at a lookup that refuses itself.
    "custom-url-categories": ResultsSpec(
        query_fields={
            # "Name" is the vendor's label, p.270.
            "Category": "name", "Scope": "namespace_type", "Defined in": "namespace_value",
            # THE VENDOR'S OWN LABEL, exactly, p.270. The two stored values ARE the vendor's two
            # strings, so no reader and no gloss is needed.
            "Type": "category_type",
            # OURS. See the sheet spec: the vendor's word for the member list is "Sites" (p.271)
            # and it is correct for a `URL List` entry and WRONG for a `Category Match` one, whose
            # list holds predefined category names. "Members" is true of both.
            "Members": "match_entry_count",
            "Member list read?": "match_entry_count_computed",
            # OURS, no vendor word - whether anything else on the firewall names the object is not
            # a setting on the object. "This assessment read" is load-bearing and not hedging: the
            # walk reads twelve surfaces, and the vendor documents four rulebases that can match
            # on a URL category of which this project's normalizer collects two.
            "Named by anything this assessment read": "is_used",
            "Referring surfaces": "referrer_count"},
        columns=("Owner", "Category", "Scope", "Defined in", "Type", "Members",
                 "Member list read?", "Named by anything this assessment read",
                 "Referring surfaces", "Referring surfaces searched"),
        base_queryset=_custom_url_categories,
        row=lambda c: (
            c.appliance_group.name if c.appliance_group_id else str(c.enforcement_point),
            c.name,
            c.get_namespace_type_display(),
            c.namespace_value or "shared",
            # BLANK IS A REAL STATE AND IS NOT "unset". The `type` leaf is MANDATORY at commit
            # validation, so it has no absent state on a committed entry - but on a PUSHED entry
            # the value reads as a DICT (`{"@loc": "shared", "#text": "URL List"}`), and blank
            # here means the row came from somewhere that read that dict as a bare string. So an
            # empty cell is a collection fault worth naming rather than a configuration state.
            c.category_type or "not read (pushed-value shape)",
            # NULLABLE FOR ONE REASON: the list was never read. That is different from a category
            # whose list is empty, which stores 0.
            c.match_entry_count if c.match_entry_count_computed else "not read",
            _yes_no(c.match_entry_count_computed),
            _yes_no(c.is_used),
            _nothing(c.referrer_count, "referrer(s)"),
            # THE DENOMINATOR, beside the verdict, because stage 5 requires that `unreferenced` is
            # never printed without it. TWELVE surfaces, and two of the vendor's four rulebases.
            _nothing(len(c.reference_surfaces_searched or []), "surface(s)"),
        ),
    ),
    # WHAT THE VENDOR CALLS THESE THINGS, from PAN-OS Web Interface Help 11.2 p.305-306 (Objects >
    # Security Profiles > File Blocking): a rule carries a Name, Applications, File Types,
    # Direction and Action, and the three actions are `alert`, `continue` and `block`. There is NO
    # vendor label for "the dangerous file types", for "multi-level encoding" or for "the files the
    # firewall cannot open" - those are this assessment's own groupings over the device's file-type
    # catalogue - so those three headings are ours and are marked as such.
    "file-blocking": ResultsSpec(
        query_fields={
            "Profile": "name", "Scope": "namespace_type",
            # p.305: "apply the predefined strict profile". The vendor's word for the state is
            # `predefined`; "Vendor-shipped" is ours, because `predefined` reads as a synonym for
            # `default` to anyone who has not met the namespace vocabulary.
            "Vendor-shipped": "is_predefined",
            "Rules": "rule_count",
            # NO VENDOR WORD. The vendor has "File Types", "Direction" and "Action" separately;
            # the conjunction of all three over a named floor set is this control's question, and
            # "both ways" is the Direction value `both` spelled for a reader.
            "Dangerous file types blocked both ways": "stops_floor_file_types",
            # "Action" is the vendor's word (p.306). "Weakest" because the column stores the
            # weakest action in force across the profile's rules, which is what the assessment
            # grades - a profile whose second rule only alerts is not protected by its first.
            "Weakest action on those file types": "floor_file_type_action",
            # NO VENDOR WORD AT ALL, and that was measured rather than assumed: `probe.corpus`
            # over all eleven indexes returns NOTHING for `Multi-Level-Encoding`, the spelling
            # /config/predefined/tdb/file-type uses and the device accepts. So the heading is the
            # device catalogue's own member name in plain English.
            "Multi-level encoding blocked both ways": "stops_nested_encoding",
            "Weakest action on multi-level encoding": "nested_encoding_action",
            # NO VENDOR WORD. "Expressed" and not "made": the column tests whether a decision
            # about files the firewall cannot look inside is VISIBLE in the configuration, and
            # says nothing about which way it went.
            "Decision expressed on unopenable files": "expresses_unopenable_file_decision",
            # THE VENDOR HAS THE SENTENCE BUT NOT A LABEL, p.306 verbatim: "When you create a file
            # blocking profile with the action continue, you can only choose the application
            # web-browsing. If you choose any other application, traffic that matches the Security
            # policy rule will not flow through the firewall." `continue` is the vendor's word and
            # `web-browsing` is the vendor's application name, so the heading is built from both.
            "Continue rule beyond web-browsing": "confirm_rule_beyond_web_browsing",
            # INHERITED, not chosen: both headings were set for two domains at once by
            # `zone-dos-protection` on 2026-11-02, because `reference_reach` is asserted by exactly
            # PAN-ZON-008 and PAN-FIL-004. Kept character for character so one column does not
            # read two ways on two surfaces.
            "Reference reach": "reference_reach",
            "Reference walk completed": "reference_reach_resolved",
            "Used by": "referrer_count"},
        columns=("Owner", "Profile", "Scope", "Vendor-shipped", "Rules",
                 "Dangerous file types blocked both ways", "Weakest action on those file types",
                 "Multi-level encoding blocked both ways",
                 "Weakest action on multi-level encoding",
                 "Decision expressed on unopenable files", "Continue rule beyond web-browsing",
                 "Reference reach", "Reference walk completed", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("file-blocking"),
        row=lambda p: (
            p.appliance_group.name if p.appliance_group_id else str(p.enforcement_point),
            p.name,
            p.get_namespace_type_display(),
            _yes_no(p.is_predefined),
            _nothing(p.rule_count, "rule(s)"),
            _yes_no(p.stops_floor_file_types),
            _action(p.floor_file_type_action),
            _yes_no(p.stops_nested_encoding),
            _action(p.nested_encoding_action),
            _yes_no(p.expresses_unopenable_file_decision),
            _yes_no(p.confirm_rule_beyond_web_browsing),
            p.get_reference_reach_display(),
            _yes_no(p.reference_reach_resolved),
            _nothing(p.referrer_count, "referrer(s)"),
        ),
    ),
    "data-filtering": ResultsSpec(
        query_fields={
            "Profile": "name", "Scope": "namespace_type", "Vendor-shipped": "is_predefined",
            "Rules": "rule_count",
            # "Alert Threshold" and "Block Threshold" are both the vendor's own words, help p.310.
            # The conjunction over every rule of the profile is this control's question and the
            # vendor has no word for it, so the heading names the two thresholds the vendor does
            # name. The universal quantifier is the point: stage 3 warned that a per-profile answer
            # "would pass a profile whose second rule stops nothing".
            "Every rule sets both thresholds": "every_rule_carries_both_counts",
            "Reference reach": "reference_reach",
            "Reference walk completed": "reference_reach_resolved",
            "Used by": "referrer_count"},
        # "Block Threshold" HAS NO `query_fields` ENTRY and that is deliberate rather than
        # missed: `lowest_block_threshold` is one of exactly two columns of this domain that the
        # search compiler does NOT register - stage 8 declined it on the repo's own narrow rule,
        # that a field earns registration by a control needing it, and no clause of this domain
        # compares it. A heading mapped to an unregistered field would point the "build a query
        # from these rows" button at a lookup that refuses itself. The column stays because it is
        # the number an assessor reads beside the verdict; only the query entry is withheld.
        columns=("Owner", "Profile", "Scope", "Vendor-shipped", "Rules",
                 "Every rule sets both thresholds", "Block Threshold",
                 "Reference reach", "Reference walk completed", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("data-filtering"),
        row=lambda p: (
            p.appliance_group.name if p.appliance_group_id else str(p.enforcement_point),
            p.name,
            p.get_namespace_type_display(),
            _yes_no(p.is_predefined),
            _nothing(p.rule_count, "rule(s)"),
            _yes_no(p.every_rule_carries_both_counts),
            # NULL AND ZERO ARE DIFFERENT ANSWERS AND NEITHER IS A BLANK. Null means no rule of
            # the profile carries a block count at all; 0 is a count stage 4 could not settle -
            # the vendor's gloss makes it either "block every matching file" or "block nothing" -
            # so it is printed with that said rather than as a bare 0 a reader would read as
            # strictest.
            ("no rule sets one" if p.lowest_block_threshold is None
             else "0 (vendor meaning unsettled)" if p.lowest_block_threshold == 0
             else str(p.lowest_block_threshold)),
            p.get_reference_reach_display(),
            _yes_no(p.reference_reach_resolved),
            _nothing(p.referrer_count, "referrer(s)"),
        ),
    ),
    # Objects > Security Profiles > Data Filtering, the SECOND page at that vendor address and
    # over a different model - see the rail item's own block in `configuration_navigation` for why
    # it is on the rail and why it is a second item rather than a second model on the page above.
    #
    # ONE ROW PER ENFORCEMENT POINT, including the points that hold NO data-filtering profile at
    # all - which is the whole reason this model exists, and the state of three of the four lab
    # appliances. A profile-keyed page shows nothing on exactly the devices that fail.
    "data-filtering-posture": ResultsSpec(
        query_fields={
            "Firewall": "hostname", "Vsys": "vsys_name",
            # NO VENDOR WORD for any of these three: the vendor describes the MECHANISM (help
            # p.309, "prevent this data from leaving a secure network") and names no state. The
            # verdict's heading is written as the thing that should be true, so "No" is the
            # finding on every one of the three.
            "Outbound data watched": "outward_data_filtering_effective",
            "A profile with rules reaches this traffic": "data_filtering_in_force",
            # "Data Pattern" is the vendor's own word, help p.309.
            "Every named data pattern defines one": "named_patterns_defined"},
        columns=("Firewall", "Vsys", "Outbound data watched",
                 "A profile with rules reaches this traffic",
                 "Every named data pattern defines one", "Profiles behind the verdict"),
        base_queryset=lambda: (
            DataFilteringPosture.objects
            .select_related("appliance", "enforcement_point")
            .order_by("appliance__hostname", "enforcement_point__vsys_name")),
        row=lambda p: (
            p.appliance.hostname or "-",
            p.enforcement_point.vsys_name or "-",
            _yes_no(p.outward_data_filtering_effective),
            _yes_no(p.data_filtering_in_force),
            _yes_no(p.named_patterns_defined),
            # `profiles_in_force` is a JSONField and MUST NOT be registered in the compiler, so
            # this column has no `query_fields` entry either. "Nothing reaches this traffic"
            # rather than a blank: an empty list beside a firing verdict is the honest pair the
            # model's own docstring names, and a blank cell would not say whether anyone looked.
            _lines([f"{e.get('name')} ({e.get('route')})" for e in p.profiles_in_force])
            if p.profiles_in_force else "Nothing reaches this traffic",
        ),
    ),
    "password-profiles": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Profile": "name", "Expires": "expiration_period",
            "Global Policy": "global_expiration_period",
            "Weakens Global": "weakens_global_expiration"},
        columns=("Appliance", "Profile", "Expires", "Global Policy", "Weakens Global"),
        base_queryset=_ordered(PasswordProfile, "appliance__hostname", "name"),
        row=lambda p: (
            str(p.appliance),
            p.name,
            "never" if not p.expiration_period else f"{p.expiration_period} days",
            "never" if not p.global_expiration_period else f"{p.global_expiration_period} days",
            _yes_no(p.weakens_global_expiration),
        ),
    ),
    "administrators": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Account": "name", "Role": "role_type",
            "Authentication": "authentication_binding", "Password": "has_password",
            "MFA": "admin_mfa_enabled"},
        columns=("Appliance", "Account", "Role", "Authentication", "Password", "MFA"),
        base_queryset=_ordered(AdminUser, "appliance__hostname", "name"),
        row=lambda u: (
            str(u.appliance),
            u.name,
            u.role_type + (f" ({u.role_scope})" if u.role_scope else ""),
            # The BINDING and the profile it resolves to, because "external" is a property of
            # the profile and the account row is where a person asks about the person.
            f"{u.authentication_binding}"
            + (f": {u.effective_authentication_profile}"
               if u.effective_authentication_profile else ""),
            _yes_no(u.has_password),
            _yes_no(u.admin_mfa_enabled),
        ),
    ),
    "authentication-profile": ResultsSpec(
        query_fields={
            # "Scope" reads the vsys where there is one and falls back to the scope word; the
            # clause carries `vsys_name`, which is empty on a shared object and therefore
            # produces nothing rather than saying something the cell did not.
            "Appliance": "hostname", "Scope": "vsys_name", "Profile": "name",
            "Method": "method", "Lockout": "lockout_failed_attempts", "MFA": "mfa_enabled",
            "Referenced By": "referrer_count"},
        columns=("Appliance", "Scope", "Profile", "Method", "Lockout", "MFA", "Referenced By"),
        base_queryset=_ordered(AuthenticationProfile, "appliance__hostname", "scope", "name"),
        row=lambda p: (
            str(p.appliance),
            _where(p),
            p.name,
            p.method or "none",
            ("unlimited attempts" if not p.lockout_failed_attempts
             else f"after {p.lockout_failed_attempts}"),
            # A factor list on an administrator-bound profile is not a second factor for that
            # administrator - PAN-OS invokes vendor-API MFA through Authentication Policy only.
            # The column says how many, and PAN-AAA-011 is where the consequence is stated.
            _nothing(p.mfa_factor_count, "factor(s)") if p.mfa_enabled else "off",
            _nothing(p.referrer_count, "place(s)"),
        ),
    ),
    "authentication-sequence": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Scope": "vsys_name", "Sequence": "name",
            "Local Member": "has_local_member", "Administrator-Bound": "is_administrative",
            "Referenced By": "referrer_count"},
        columns=("Appliance", "Scope", "Sequence", "Profiles, In Order", "Local Member",
                 "Administrator-Bound", "Referenced By"),
        base_queryset=_ordered(AuthenticationSequence, "appliance__hostname", "scope", "name"),
        row=lambda q: (
            str(q.appliance),
            _where(q),
            q.name,
            # In order, with the method, because the order is the meaning.
            "\n> ".join(f"{n} ({m or 'not found'})"
                        for n, m in zip(q.member_names, q.member_methods)) or "Nothing",
            _yes_no(q.has_local_member),
            _yes_no(q.is_administrative),
            _nothing(q.referrer_count, "place(s)"),
        ),
    ),
    # --- Device > Certificate Management --------------------------------------------------
    "certificates": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Scope": "vsys_name", "Certificate": "name",
            "Signature": "signature_algorithm"},
        columns=("Appliance", "Scope", "Certificate", "Key", "Signature", "Type"),
        base_queryset=_ordered(Certificate, "appliance__hostname", "scope", "name"),
        row=lambda c: (
            str(c.appliance),
            _where(c),
            c.name,
            f"{c.key_algorithm} {c.key_size_bits}" if c.key_algorithm else "-",
            c.signature_algorithm or "-",
            ("CA" if c.is_ca else "leaf") + (", self-signed" if c.is_self_signed else ""),
        ),
    ),
    "certificate-profile": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Scope": "vsys_name", "Profile": "name"},
        columns=("Appliance", "Scope", "Profile", "Revocation Checks", "CA Certificates"),
        base_queryset=_ordered(CertificateProfile, "appliance__hostname", "scope", "name"),
        row=lambda p: (
            str(p.appliance),
            _where(p),
            p.name,
            # "none" is the finding, so it is spelled rather than left as an empty cell.
            "\n".join(filter(None, ["CRL" if p.use_crl else "", "OCSP" if p.use_ocsp else ""]))
            or "none",
            _nothing(len(p.ca_certificate_names or []), "certificate(s)"),
        ),
    ),
    "ssl-tls-service-profile": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Scope": "vsys_name", "Profile": "name",
            "Certificate": "certificate_name", "SHA-1": "allows_sha1"},
        columns=("Appliance", "Scope", "Profile", "Protocol Range", "Certificate", "SHA-1"),
        base_queryset=_ordered(SslTlsServiceProfile, "appliance__hostname", "scope", "name"),
        row=lambda p: (
            str(p.appliance),
            _where(p),
            p.name,
            f"{p.min_version or '?'} - {p.max_version or '?'}",
            p.certificate_name or "None",
            _yes_no(p.allows_sha1),
        ),
    ),
    # --- Device > Server Profiles ---------------------------------------------------------
    "aaa-server-profiles": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Scope": "vsys_name", "Profile": "name",
            "Type": "kind", "Servers": "server_count", "Referenced By": "referrer_count"},
        columns=("Appliance", "Scope", "Profile", "Type", "Servers", "Referenced By"),
        base_queryset=_ordered(ServerProfile, "appliance__hostname", "scope", "kind", "name"),
        row=lambda p: (
            str(p.appliance),
            _where(p),
            p.name,
            # `raw_kind` when the kind did not classify: a container we have not met yet must
            # show its real name rather than the word "unknown".
            p.kind if p.kind != "unknown" else f"unknown ({p.raw_kind})",
            _nothing(p.server_count, "server(s)"),
            _nothing(p.referrer_count, "place(s)"),
        ),
    ),
    # --- Network > IPSec Tunnels ----------------------------------------------------------
    # 2026-11-02, for PAN-IPS-006 to -009. A TOP-LEVEL Network item and not a Network Profile,
    # because the vendor keeps the phase-2 BINDING a tab away from the reusable proposals it
    # consumes - see the rail item's own comment.
    #
    # THREE OF THE EIGHT HEADINGS HAVE NO `query_fields` ENTRY AND THAT IS NOT AN OMISSION.
    # `crypto_profile_name`, `crypto_profile_found`, `tunnel_monitor_destination_ip`,
    # `tunnel_monitor_profile_name` and `monitor_action_effective` are stored and are NOT
    # registered with the compiler - the repo's rule is that only a column a control asks for is
    # registered, and no clause in this domain reads any of the five. Mapping a heading to an
    # unregistered field would point the "build a query from these rows" button at a lookup that
    # refuses itself.
    #
    # `Running on a chosen profile` IS registered and no shipped control asserts on it:
    # PAN-IPS-009's tunnel-side stage 5 record was never built, because a `Control` is one model
    # per control type and stage 8 could ship only the profile half. So the field is queryable
    # here and reports nowhere, which is worth being able to ask about from this page.
    "ipsec-tunnels": ResultsSpec(
        query_fields={"Appliance": "hostname", "Tunnel": "tunnel_name",
                      "Switched off": "is_disabled", "Replay protection": "anti_replay",
                      "Far-end monitoring": "tunnel_monitor_enable",
                      "Running on a chosen profile": "effective_crypto_profile_chosen"},
        columns=("Appliance", "Tunnel", "Switched off", "Replay protection",
                 "Far-end monitoring", "Monitoring", "IPSec crypto profile",
                 "Running on a chosen profile"),
        base_queryset=_ordered(IpsecTunnel, "appliance__hostname", "tunnel_name"),
        row=lambda t: (
            str(t.appliance),
            t.tunnel_name,
            _yes_no(t.is_disabled),
            ipsec.replay_protection(t),
            ipsec.far_end_monitoring(t),
            # One cell for the monitoring binding here, where the workbook's wider row splits
            # the target, the profile and the resolved action into three: this page answers
            # "which tunnels look like this" and has eight columns to do it in.
            f"{ipsec.monitor_probe(t)}\n{ipsec.monitor_profile_named(t)}\n"
            f"{ipsec.monitor_action(t)}",
            # WITHOUT `provenance_of`, so this page cannot say that an absent reference was
            # INFERRED as `default`. It has no provenance index and building one per row would
            # cost a query per row for a column nothing queries. The findings tab does say it.
            ipsec.crypto_profile_named(t),
            ipsec.running_on_a_chosen_profile(t),
        ),
    ),
    # --- Network > Network Profiles -------------------------------------------------------
    # The two IKE objects, 2026-10-28, for the nine PAN-IKE controls. In the rail's order, which
    # is the product's: IKE Gateways above IKE Crypto above Interface Mgmt.
    #
    # EACH ALGORITHM CELL IS ITS VERDICT FIELD, the way the management-SSH page's are: the cell
    # shows the offer set and marks the member being graded, and `query_fields` points the
    # "build a query from these rows" button at the verdict column the controls actually assert
    # on. The member lists are JSONFields and are deliberately unreachable from a query, so
    # mapping a heading to one would be mapping it to a lookup that silently matches nothing.
    "ike-gateways": ResultsSpec(
        query_fields={"Appliance": "hostname", "Gateway": "entry_name",
                      "Status": "gateway_is_active", "Version": "ike_version",
                      "Peer Authentication": "peer_authentication",
                      "Exchange Mode": "ikev1_exchange_mode"},
        columns=("Appliance", "Gateway", "Status", "Version", "Peer Authentication",
                 "Exchange Mode", "Dead Peer Detection", "IKE Crypto Profile"),
        base_queryset=_ordered(IkeGateway, "appliance__hostname", "entry_name"),
        row=lambda g: (
            str(g.appliance),
            g.entry_name,
            ike.gateway_status(g),
            g.get_ike_version_display() or ike.NOT_READ,
            g.get_peer_authentication_display() or "Not established",
            ike.exchange_mode(g),
            # One cell for the pair here, where the workbook's wider row splits them: this page
            # answers "which gateways look like this" and has eight columns to do it in.
            ike.dead_peer_detection(g),
            ike.named_crypto_profiles(g),
        ),
    ),
    # 2026-11-02, for PAN-IPS-001 to -005 and -009. BETWEEN the two IKE items, which is the
    # group's own rail order and the vendor's: Network Profiles runs GlobalProtect IPSec Crypto,
    # IKE Gateways, IPSec Crypto, IKE Crypto, Monitor, Interface Mgmt.
    #
    # The algorithm cells are the offer set with the graded member marked, the way the phase-1
    # page's are, and `query_fields` points at the `weakest_*` verdict column rather than at the
    # list: all three lists are JSONFields, deliberately unregistered, so a heading mapped to one
    # would be mapped to a lookup that silently matches nothing.
    #
    # `Key lifetime` maps to `lifetime_hours` and NOT to the unit beside it: `lifetime_unit` is
    # stored and searchable and is deliberately unregistered, because no clause in this domain
    # reads it. The cell shows both, because the number alone is this control's best state in one
    # unit and its worst in another.
    "ipsec-crypto": ResultsSpec(
        query_fields={"Appliance": "hostname", "Profile": "profile_name",
                      "IPSec protocol": "protocol_branch",
                      "Encryption": "weakest_encryption_offered",
                      "Integrity": "weakest_integrity_offered",
                      "Key agreement": "dh_group", "Key lifetime": "lifetime_hours",
                      "Named by a tunnel": "referencing_tunnel_count"},
        columns=("Appliance", "Profile", "IPSec protocol", "Encryption", "Integrity",
                 "Key agreement", "Key lifetime", "Named by a tunnel"),
        base_queryset=_ordered(IpsecCryptoProfile, "appliance__hostname", "profile_name"),
        row=lambda p: (
            str(p.appliance),
            p.profile_name,
            ipsec.protocol_branch(p),
            ipsec.esp_encryption_offered(p),
            ipsec.integrity_offered(p),
            # RAW, and both of its odd tokens are real values rather than absences: `no-pfs`
            # means the key already agreed is reused and `none` is a writable member, so neither
            # may be softened into a word about missing data. The absent key materialises
            # `group2`, which is a 1024-bit group and not an absence either.
            p.dh_group,
            ipsec.key_lifetime(p),
            ipsec.referencing_tunnels(p),
        ),
    ),
    "ike-crypto": ResultsSpec(
        query_fields={"Appliance": "hostname", "Profile": "entry_name",
                      "DH Group": "dh_group_floor_met", "Encryption": "encryption_floor_met",
                      "Authentication": "hash_floor_met",
                      "Key Lifetime": "key_lifetime_hours",
                      "Named by a gateway": "referenced_by_gateway_on_this_appliance"},
        columns=("Appliance", "Profile", "DH Group", "Encryption", "Authentication",
                 "Key Lifetime", "IKEv2 Re-authentication", "Named by a gateway"),
        base_queryset=_ordered(IkeCryptoProfile, "appliance__hostname", "entry_name"),
        row=lambda p: (
            str(p.appliance),
            p.entry_name,
            ike.offer_set(p.dh_groups, p.weakest_dh_group),
            ike.offer_set(p.encryption_ciphers, p.weakest_encryption_cipher),
            ike.integrity_offer(p),
            ike.key_lifetime(p),
            ike.reauth_interval(p),
            # NARROWER THAN "Referenced", which is what the addresses page calls its own
            # version of this question - hence the heading. This says whether a gateway ON THIS
            # APPLIANCE names the profile from one of its two explicit pointer leaves. A
            # gateway with NEITHER pointer set still consumes a profile, so the entry
            # named `default` reads "no" on exactly the estates where every unpointed gateway
            # uses it.
            _yes_no(p.referenced_by_gateway_on_this_appliance),
        ),
    ),
    "interface-mgmt": ResultsSpec(
        query_fields={"Appliance": "hostname", "Profile": "name",
                      "Bound To": "binding_count"},
        columns=("Appliance", "Profile", "Bound To"),
        base_queryset=_ordered(InterfaceManagementProfile, "appliance__hostname", "name"),
        row=lambda p: (
            str(p.appliance),
            p.name,
            _nothing(p.bound_interface_count, "interface(s)"),
        ),
    ),
    # Network > Network Profiles > Zone Protection, 2026-11-02, for PAN-ZON-002 to -006.
    #
    # THE OWNER IS THE APPLIANCE AND NOT A VSYS, which stage 4 measured: this collection has
    # exactly one scope on a firewall - `action=complete` answers code=6 Invalid sequence at
    # both the shared and the vsys spelling of `network/profiles/zone-protection-profile` - so
    # there is no `_where` to print and `str(p.appliance)` is the whole owner.
    #
    # "Zones attached" HAS NO `query_fields` ENTRY AND PRESENTS ONE FIELD, which is the one
    # column here that breaks this spec's own pattern. `attached_zone_count` is not in
    # `search/zone_protection_profile/compiler.py`'s registry - no control asserts on it, and
    # this repo registers only what a control asks for - so mapping it would point the "build a
    # query from these rows" button at a lookup that refuses itself. It is shown because it is
    # the evidence behind "In force": a reader who sees `no` needs the count to know whether the
    # sweep found nothing or never ran.
    "zone-protection": ResultsSpec(
        query_fields={"Appliance": "hostname", "Profile": "profile_name",
                      "In force": "is_in_force",
                      "SYN flood enabled": "syn_flood_enabled",
                      "Volumetric flood gap": "volumetric_flood_gap",
                      "Discards spoofed IP": "discard_ip_spoof",
                      "Packet drop gap": "packet_drop_gap",
                      "Non-SYN reject (resolved)": "non_syn_reject_effective",
                      "Scan detection gap": "scan_detection_gap",
                      "Weakest scan action": "scan_weakest_action",
                      "Exempted sources": "scan_white_list_count",
                      "Unreferenced": "is_unreferenced"},
        columns=("Appliance", "Profile", "In force", "Zones attached", "SYN flood enabled",
                 "Volumetric flood gap", "Discards spoofed IP", "Packet drop gap",
                 "Non-SYN reject (resolved)", "Scan detection gap", "Weakest scan action",
                 "Exempted sources", "Unreferenced"),
        base_queryset=_ordered(ZoneProtectionProfile, "appliance__hostname", "profile_name"),
        row=lambda p: (
            str(p.appliance),
            p.profile_name,
            _yes_no(p.is_in_force),
            # "Nothing" rather than 0, for `_nothing`'s own reason: a bare zero here reads as
            # "not counted" exactly where it means "counted, and no zone names this profile".
            _nothing(p.attached_zone_count, "zone(s)"),
            _yes_no(p.syn_flood_enabled),
            _yes_no(p.volumetric_flood_gap),
            _yes_no(p.discard_ip_spoof),
            _yes_no(p.packet_drop_gap),
            # The RESOLVED value, not the profile's own leaf. The leaf is a three-valued
            # pointer whose commonest state is `global` - a deferral to a device-wide setting
            # read separately - so printing the leaf would read as an answer where there is
            # none. The leaf itself is the next column.
            p.non_syn_reject_effective or NOT_APPLICABLE,
            _yes_no(p.scan_detection_gap),
            # An em dash, not "(empty)": a profile carrying no scan entry at all has no weakest
            # action BY STRUCTURE rather than by choice, and `layout.NONE` is the vocabulary
            # for that. The shared `display_value` has no way to say it.
            p.scan_weakest_action or "—",
            _nothing(p.scan_white_list_count, "address(es)"),
            _yes_no(p.is_unreferenced),
        ),
    ),
    # Network > GlobalProtect > Portals, 2026-11-02, for PAN-GPP-001, -003, -004 and -005. The
    # FIRST page over `integrations.GlobalProtectPortal`, which stage 7 minted for this domain and
    # which had never been queried from this repository at all.
    #
    # EVERY HEADING THAT ALSO HEADS A FINDINGS COLUMN IS THE SAME WORD, character for character,
    # so one column does not read two ways on two surfaces. The sourcing is written once, in
    # `globalprotect_portal_presentation.PORTAL_SETTING_LABELS`, against PAN-OS Web Interface Help
    # 11.2 `Network > GlobalProtect > Portals` (p.999-1039).
    #
    # EVERY `query_fields` ENTRY WAS CHECKED AGAINST THE COMPILER'S OWN REGISTRY rather than
    # assumed, because stored, searchable and registered are three different things: all eleven
    # below are keys of `search/globalprotect_portal/compiler.py`'s `FIELD_OPERATOR_REGISTRY`.
    # THE TWO WITHOUT AN ENTRY ARE DELIBERATE. "SSL/TLS service profile" presents
    # `ssl_tls_service_profile`, which is NOT registered - the controls ask the verdict beside it
    # instead, and the repo's rule is that only a column a control asks for is registered - and
    # "Authentication rows" presents `client_auth_row_count`, which is not registered either and
    # is here because zero is the one portal state no control on this domain can report.
    #
    # THE THREE CLIENTLESS COLUMNS ARE REGISTERED FOR A HALF NOBODY SHIPPED, and that is why they
    # are on this page and draw no findings column. `clientless_vpn_state`,
    # `clientless_vpn_min_version` and `clientless_vpn_floor_known` are in the registry because
    # PAN-GPP-006's SECOND half - the portal's own clientless transport floor - asked for them;
    # stage 8 built only the first half and recorded the second in `subjects_in_two_models`. No
    # shipped query clauses on any of the three, so `tested_fields` derives nothing for them, and
    # an assessor can still ask the question here while the control is unbuilt.
    "globalprotect-portals": ResultsSpec(
        query_fields={"Appliance": "hostname", "Vsys": "vsys_name", "Portal": "portal_name",
                      "No SSL/TLS service profile is bound": "tls_profile_binding_missing",
                      "Portal Login Page": "custom_login_page",
                      "Allow User to Upgrade GlobalProtect App": "upgrade_posture",
                      "Save User Credentials": "saved_credentials_posture",
                      "All four keys the device requires were read": "mandatory_keys_present",
                      "Clientless VPN branch": "clientless_vpn_state",
                      "Clientless transport floor": "clientless_vpn_min_version",
                      "Transport floor was written": "clientless_vpn_floor_known"},
        columns=("Appliance", "Vsys", "Portal", "SSL/TLS service profile", "Certificate Profile",
                 "No SSL/TLS service profile is bound", "Portal Login Page",
                 "Allow User to Upgrade GlobalProtect App", "Save User Credentials",
                 "Authentication rows", "All four keys the device requires were read",
                 "Clientless VPN branch", "Clientless transport floor",
                 "Transport floor was written"),
        base_queryset=_ordered(
            GlobalProtectPortal, "appliance__hostname", "vsys_name", "name"),
        row=lambda p: (
            str(p.appliance),
            p.vsys_name or "-",
            p.portal_name,
            # "(empty)" and not a blank or an em dash: the key is MANDATORY at commit validation,
            # so a portal that carries it and holds nothing is a real observed state - it is what
            # this estate's PA-5220 portal reads - and a blank cell would read as a gap in the
            # collection. The verdict column beside it is what says that is the firing state.
            p.ssl_tls_service_profile or "(empty)",
            # VENDOR'S OWN WORD, help 11.2 p.1003: "Certificate Profile - (Optional) Select the
            # Certificate Profile the portal uses to match those client certificates that come
            # from user endpoints." HERE AND NOWHERE ELSE, which is worth stating: stage 5 marks
            # this column `presented: true` and no shipped query clauses on it, so it draws no
            # findings column - and the verdict that DOES reach a findings row is
            # `certificate_profile_bound` on the client-auth tab, which says Yes or No and not
            # WHICH. A reader following a PAN-GPP-002 finding to the portal's Authentication tab
            # needs the name, and this is the only cell in the report that carries it.
            #
            # `(none)` RATHER THAN `(empty)`: the key is OPTIONAL on a committed portal, so a
            # null is a portal that binds no certificate profile - which is the permissive state
            # measured on this estate's one PA-5220 portal - and not a reading nobody took.
            p.certificate_profile or "(none)",
            _yes_no(p.tls_profile_binding_missing),
            # The device's own token, DELIBERATELY UNTRANSLATED, and the findings tab makes the
            # same call for the same reason: `factory-default` and `Disable` are this screen's own
            # two words (help 11.2 p.1001), not Django's, so there is nothing to translate.
            p.custom_login_page or "(empty)",
            # THE CHOICE LABEL AND NOT THE TOKEN on both of these, because the stored values are
            # `0`/`1`/`2`/`3` and `no_agent_configuration`, and a `0` under "Save User Credentials"
            # reads as a count. The findings tab reaches the same words through a `value_readers`
            # entry, because the shared `display_value` behind that surface is choices-unaware.
            p.get_upgrade_posture_display(),
            p.get_saved_credentials_posture_display(),
            # A number and not `_nothing`: zero is the reportable end here - a portal that demands
            # nothing of any endpoint - and "Nothing" on a column named for a count would read as
            # "not counted" rather than "none found".
            str(p.client_auth_row_count),
            _yes_no(p.mandatory_keys_present),
            p.get_clientless_vpn_state_display(),
            # `(empty)` rather than an em dash: an OPTIONAL key, so a portal that configured
            # Clientless VPN and wrote no floor is a real state, and the column beside it is what
            # reports whether it was written at all.
            p.clientless_vpn_min_version or "(empty)",
            _yes_no(p.clientless_vpn_floor_known),
        ),
    ),
    # Network > GlobalProtect > Portals > <portal-config> > Authentication, 2026-11-02, for
    # PAN-GPP-002. The FIRST page over `integrations.GlobalProtectPortalClientAuthRow`.
    #
    # ALL NINE HEADINGS HAVE A `query_fields` ENTRY, which is unusual on this rail and is a
    # property of the model rather than of this page: every column of it except the FK is in
    # `search/globalprotect_portal_client_auth/compiler.py`'s registry, because every one of them
    # is either part of the row's identity or one of the two leaves PAN-GPP-002's verdict is
    # computed from.
    #
    # THE ROW NAME IS NOT WHAT A READER GOES BY and the column order says so: Portal, then Row,
    # then the endpoint class. Stage 5 measured that the row's own name is operator-chosen and
    # carries no meaning, so it is here to tell two rows apart and `os` is the key the table is
    # actually keyed by (help 11.2 p.1002: "The OS is the primary differentiator between
    # configurations").
    "globalprotect-portal-authentication": ResultsSpec(
        query_fields={"Appliance": "hostname", "Vsys": "vsys_name", "Portal": "portal_name",
                      "Row": "row_name", "Endpoint class (OS)": "os",
                      "Authentication Profile": "authentication_profile",
                      "Credentials OR certificate": "user_credential_or_client_cert_required",
                      "Certificate profile bound": "certificate_profile_bound",
                      "What this row demands before admitting an endpoint": "admission_demand"},
        columns=("Appliance", "Vsys", "Portal", "Row", "Endpoint class (OS)",
                 "Authentication Profile", "Credentials OR certificate",
                 "Certificate profile bound",
                 "What this row demands before admitting an endpoint"),
        base_queryset=_ordered(
            GlobalProtectPortalClientAuthRow, "appliance__hostname", "vsys_name", "portal_name",
            "name"),
        row=lambda r: (
            str(r.appliance),
            r.vsys_name or "-",
            r.portal_name,
            r.row_name,
            # `(empty)` rather than an em dash on these two: each key is mandatory on a committed
            # row, so an empty one is a reading nobody took rather than a branch that does not
            # exist, and stage 5 reads both as firing for that reason.
            r.os or "(empty)",
            r.authentication_profile or "(empty)",
            # THE DEVICE'S OWN `yes`/`no` AND NOT `_yes_no`, which would give the same two words
            # by accident and the wrong one in the third state. This leaf is a CharField whose
            # NULL is two states at once - the key absent on a committed row, or a row the
            # collector did not carry - and stage 5 says neither is safe, so it must not print as
            # "no". "no" is the HARDENED answer on this switch (help 11.2 p.1003), which is the
            # reverse of nearly every other switch in this report.
            r.user_credential_or_client_cert_required or "not read",
            _yes_no(r.certificate_profile_bound),
            # The choice label, which is a sentence. The raw token is `password_and_certificate`.
            r.get_admission_demand_display(),
        ),
    ),
    # Network > GlobalProtect, 2026-11-02, for PAN-GPP-006. The FIRST page over
    # `integrations.GlobalProtectEnforcementPoint` - and the page `globalprotect-gateway` inherits
    # for PAN-GPG-005, which reports on the same model.
    #
    # NO `scope` ON ANY OF THE THREE PAGES THIS DOMAIN ADDS: each names a model of its own, so
    # `object_for_canonical_query` short-circuits on the single candidate and a scope would be
    # dead weight. That is the same call `decryption-rules` and `decryption-coverage` made.
    #
    # THE THREE CLIENTLESS COUNTS ARE THREE COLUMNS HERE AND ONE CELL ON THE FINDINGS TAB, which
    # is a deliberate difference between the two surfaces rather than a drift. This page's job is
    # to be QUERIED, and each of the three is separately registered and separately askable; the
    # findings tab's job is to be READ, and the three are never read apart - they are the evidence
    # behind one verdict, so they are one cell there and the tab stays narrow enough to read.
    #
    # `hip_objects_testing_client_version` IS REGISTERED AND IS A COLUMN AND NO SHIPPED QUERY
    # CLAUSES ON IT. It is PAN-GPP-003's SECOND half - whether an out-of-date agent is refused
    # rather than merely invited to upgrade - which stage 8 did not build: stage 5 discharged the
    # enforcement half as unclausable, because a HIP object no security rule references refuses
    # nobody and the attachment point is a security rule's `hip-profiles`. So the number is here
    # for an assessor to ask about while the control is unbuilt, and it draws no findings column.
    "globalprotect-coverage": ResultsSpec(
        query_fields={"Appliance": "hostname", "Vsys": "vsys_name", "Portals": "portal_count",
                      "Clientless apps": "clientless_app_count",
                      "Clientless app groups": "clientless_app_group_count",
                      "Portals publishing": "portals_publishing_clientless_apps",
                      "Clientless VPN surface": "clientless_vpn_feature_state",
                      "GlobalProtect Portal licence": "globalprotect_portal_licensed",
                      "Licensing rules GlobalProtect out": "licence_excludes_globalprotect",
                      "Licence entries read": "licence_entry_count",
                      "Licence reply collected": "licence_reply_collected",
                      "HIP objects testing client version":
                          "hip_objects_testing_client_version"},
        columns=("Appliance", "Vsys", "Portals", "Clientless apps", "Clientless app groups",
                 "Portals publishing", "Clientless VPN surface",
                 "GlobalProtect Portal licence", "Licensing rules GlobalProtect out",
                 "Licence reply collected", "Licence entries read",
                 "HIP objects testing client version"),
        base_queryset=_ordered(
            GlobalProtectEnforcementPoint, "appliance__hostname", "vsys_name"),
        row=lambda v: (
            str(v.appliance),
            v.vsys_name or "-",
            # Numbers and not `_nothing` on all five counts: zero is the reportable end of every
            # one of them, and the model's own docstring is why a zero here is a real reading -
            # "NODE PRESENCE IS THE WRONG TEST AND AN ENTRY COUNT IS THE RIGHT ONE", measured,
            # because deleting the last entry leaves the container present and empty.
            str(v.portal_count),
            str(v.clientless_app_count),
            str(v.clientless_app_group_count),
            str(v.portals_publishing_clientless_apps),
            # Choice labels on both: the tokens are `latent` and `unknown`, and `latent` is the
            # rank this whole subject exists for.
            v.get_clientless_vpn_feature_state_display(),
            v.get_globalprotect_portal_licensed_display(),
            _yes_no(v.licence_excludes_globalprotect),
            # OURS, AND THE COLUMN THAT MAKES THE TWO BESIDE IT HONEST. The licence reply cannot
            # tell "holds nothing" from "nobody asked" - the model's own comment records that
            # `{'licenses': None}` arrives with status=success - so this boolean is what says
            # whether the question was put at all. Stage 5 marks it `presented: true` and no
            # shipped query clauses on it, so it draws no findings column; it is here because
            # without it a reader cannot tell which of the two states a `No` in the applicability
            # column covers.
            _yes_no(v.licence_reply_collected),
            str(v.licence_entry_count),
            str(v.hip_objects_testing_client_version),
        ),
    ),
    # Policies > DoS Protection, 2026-11-02, for PAN-ZON-007.
    #
    # THE POSITION IS PART OF THE ROW'S IDENTITY and is printed first among the rule's own
    # columns for that reason: a DoS rulebase resolves by ORDER, not by name, and stage 4
    # recorded `name_resolution` as unmeasured on this object because the collision question
    # that field asks is the wrong shape for a rulebase. It has no `query_fields` entry -
    # `rule_position` is not registered, and no control asserts on it.
    #
    # "Disabled" IS A STRING AND NOT A BOOLEAN on this model, so it is printed as it was read
    # rather than through `_yes_no`. Every DoS rule in the measured estate carries
    # `disabled: yes` - stage 6 could not commit an enabled one - and PAN-ZON-007 deliberately
    # fires regardless, because no implicit was measured for that key and taking an absence for
    # "disabled" would silently suppress every rule in an estate. The column is here so a
    # reader can see that is what happened.
    "dos-protection-rules": ResultsSpec(
        query_fields={"Appliance": "hostname", "Vsys": "vsys_name", "Rule": "rule_name",
                      "Action": "rule_action", "Names a profile": "names_a_profile"},
        columns=("Appliance", "Vsys", "Position", "Rule", "Action", "Names a profile",
                 "Aggregate profile", "Classified profile", "Classification", "Disabled"),
        base_queryset=_ordered(
            DosPolicyRule, "enforcement_point__vsys_name", "rule_position",
            related=("enforcement_point__appliance", "enforcement_point__appliance_group")),
        row=lambda r: (
            _rule_appliance(r),
            r.enforcement_point.vsys_name or "-",
            r.rule_position,
            r.rule_name,
            # An em dash where the rule expresses no action at all: the three actions are CHILD
            # NODES rather than values - stage 4 measured the stored shape as
            # `action: {'protect': None}` - so an empty string here is a rule with no action
            # branch, which is a different thing from an action we failed to read.
            r.rule_action or "—",
            _yes_no(r.names_a_profile),
            r.aggregate_profile or "None",
            r.classified_profile or "None",
            r.classification_address or "—",
            r.rule_disabled or "—",
        ),
    ),
    # Objects > Security Profiles > DoS Protection, 2026-11-02, for PAN-ZON-008. THE FIFTH page
    # over `SecurityProfile`, and its `scope` is what makes the resolver answer for this kind -
    # see the rail entry in `configuration_navigation` for the measurement.
    #
    # NOT `_security_profile_row`, which the anti-spyware and vulnerability pages share: that row
    # prints the critical/high/medium severity verdicts, and a DoS protection profile answers no
    # severity question at all - no severity verdict row, no DNS tree, no category verdict - so
    # all three would read `n/a` on every row. What this kind IS assessed for is whether anything
    # references it, so the reach columns take that space instead.
    #
    # TWO COLUMNS FOR ONE QUESTION, deliberately. "Reference reach" is the walk's answer and
    # "Walk completed" says whether the walk had the whole picture. They are different in kind:
    # an incomplete set of reads can only hide a REFERRER, so it can turn "nothing names this"
    # into a wrong answer and can never turn "a rule names this" into one. A reader who sees
    # "Nothing on this firewall names it" beside a "no" in the second column is being told the
    # first cell is not established, and PAN-ZON-008 reports those two states through two
    # different queries at the SAME severity - so the sentence, not the severity, is what tells
    # them apart.
    "dos-protection": ResultsSpec(
        query_fields={"Profile": "name", "Scope": "namespace_type",
                      "Reference reach": "reference_reach",
                      "Walk completed": "reference_reach_resolved",
                      "Used by": "referrer_count"},
        columns=("Owner", "Profile", "Scope", "Reference reach", "Walk completed", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("dos-protection"),
        row=lambda p: (
            p.appliance_group.name if p.appliance_group_id else str(p.enforcement_point),
            p.name,
            p.get_namespace_type_display(),
            p.get_reference_reach_display(),
            _yes_no(p.reference_reach_resolved),
            _nothing(p.referrer_count, "referrer(s)"),
        ),
    ),
    # Policies > Decryption, 2026-11-02, for PAN-DEC-002, -003, -005, -006, -007, -008 and -010.
    # The FIRST page over `integrations.DecryptionPolicyRule`, which stage 7 minted for this
    # domain and which had never been queried from this repository at all.
    #
    # EVERY HEADING IS A PROPOSAL (P399) and each is the SAME WORD the Decryption Rules findings
    # sheet uses, character for character, so one column does not read two ways on two surfaces.
    # The sourcing is written once, in `decryption_policy_presentation.RULE_SETTING_LABELS`,
    # against PAN-OS Web Interface Help 11.2 p.170-175.
    #
    # EVERY `query_fields` ENTRY WAS CHECKED AGAINST THE COMPILER'S OWN REGISTRY rather than
    # assumed, because stored, searchable and registered are three different things: all twelve
    # below are keys of `search/decryption_policy_rule/compiler.py`'s `FIELD_OPERATOR_REGISTRY`.
    # THE TWO WITHOUT AN ENTRY ARE DELIBERATE: "Position" presents `rule_position`, which is not
    # registered - and should not be, because the stored number is the configuration rank and not
    # the evaluation index, so a clause on it would ask a question the column cannot answer - and
    # "Record of a successful session" IS registered but is a three-state verdict over two
    # device leaves, which is fine to clause on and is therefore included.
    "decryption-rules": ResultsSpec(
        query_fields={"Appliance": "hostname", "Vsys": "vsys_name", "Object": "rule_name",
                      "Action": "action", "URL Category": "category",
                      "Source Address": "source", "Destination Address": "destination",
                      "Source User": "source_user", "Service": "service",
                      "Decryption Profile": "profile_name", "Description": "description",
                      "Source match is inverted": "negate_source",
                      "Log Unsuccessful SSL Handshake": "log_fail",
                      "Record of a successful session": "success_record_disposition",
                      "Disabled": "disabled"},
        columns=("Appliance", "Vsys", "Rulebase", "Position", "Object", "Action", "URL Category",
                 "Source Address", "Destination Address", "Source User", "Service",
                 "Decryption Profile", "Description", "Source match is inverted",
                 "Log Unsuccessful SSL Handshake", "Record of a successful session", "Disabled"),
        base_queryset=_ordered(
            DecryptionPolicyRule, "enforcement_point__vsys_name", "config_source",
            "rule_position",
            related=("enforcement_point__appliance", "enforcement_point__appliance_group")),
        row=lambda r: (
            _rule_appliance(r),
            r.enforcement_point.vsys_name or "-",
            r.get_config_source_display(),
            r.rule_position,
            r.rule_name,
            # An em dash where the rule expresses no action at all. `action` is mandatory at
            # commit validation, so blank is a CANDIDATE-only rule and not a default anybody
            # applied - a different thing from an action we failed to read, and the schema's own
            # @default=yes on `no-decrypt` is not an implicit value for the same reason.
            r.action or "—",
            # THE FIVE CRITERIA LIVE ON CHILD ROWS, one per line in the device's own order. The
            # same readers the findings sheet uses, so the two surfaces cannot disagree about
            # what a criterion says.
            decryption_policy.joined(r.decryptionpolicyrulecategorys.all()),
            decryption_policy.joined(r.decryptionpolicyrulesources.all()),
            decryption_policy.joined(r.decryptionpolicyruledestinations.all()),
            decryption_policy.joined(r.decryptionpolicyrulesourceusers.all()),
            decryption_policy.joined(r.decryptionpolicyruleservices.all()),
            # "Nothing named" and not a blank, and NOT "nothing applied": stage 4 measured the
            # same absent key resolving to the predefined `default` profile under some conditions
            # and to nothing under others, so this cell can only report what the rule SAYS.
            r.profile_name or "Nothing named",
            r.description or "—",
            _yes_no(r.negate_source),
            _yes_no(r.log_fail),
            r.success_record_disposition,
            _yes_no(r.disabled),
        ),
    ),
    # Policies > Decryption, SECOND page at that address, 2026-11-02, for PAN-DEC-001 and -009.
    # The FIRST page over `integrations.DecryptionRulebaseVerdict`.
    #
    # NO `scope` ON EITHER OF THE TWO: each names a model of its own, so
    # `object_for_canonical_query` short-circuits on the single candidate and a scope would be
    # dead weight. That is the same call `rule-posture` and `rulebase-device-match` made at
    # Policies > Security, where three items share one address over three models.
    #
    # `rule_count` HAS NO `query_fields` ENTRY AND IS A COLUMN, measured: it is not in
    # `search/decryption_rulebase_coverage/compiler.py`'s registry, and the repo's rule is that
    # only a column a control asks for is registered. No PAN-DEC query clauses on it. It is here
    # as the evidence that tells the two failing states of the verdict beside it apart - zero
    # means there is no rulebase to change.
    "decryption-coverage": ResultsSpec(
        query_fields={"Appliance": "hostname", "Vsys": "vsys_name",
                      "Any rule opens an outbound web session": "opens_outbound_web",
                      "What any outbound web session meets": "outbound_web_disposition",
                      "Inbound TLS inspection": "inbound_inspection_posture"},
        columns=("Appliance", "Vsys", "Rules in force",
                 "Any rule opens an outbound web session",
                 "What any outbound web session meets", "Inbound TLS inspection"),
        base_queryset=_ordered(
            DecryptionRulebaseVerdict, "enforcement_point__vsys_name",
            related=("enforcement_point__appliance", "enforcement_point__appliance_group")),
        row=lambda v: (
            _rule_appliance(v),
            v.enforcement_point.vsys_name or "-",
            # A number and not `_nothing`: zero is the reportable end here, and a word like
            # "Nothing" on a column named for a count reads as "not counted" rather than "none
            # found". Same ruling the two existing count columns in this repository took.
            v.rule_count,
            _yes_no(v.opens_outbound_web),
            v.outbound_web_disposition,
            v.inbound_inspection_posture,
        ),
    ),
    # Device > Certificate Management > SSL Decryption Exclusion, 2026-11-02, for PAN-DEC-004's
    # first record. The FIRST page over `integrations.SslDecryptionExclusion`.
    #
    # `exclude` HAS NO `query_fields` ENTRY AND IS A COLUMN, measured: it is not in
    # `search/ssl_decryption_exclusion/compiler.py`'s registry, because no shipped control asks
    # for it. It is here because an exclusion carrying no reason is a different thing depending on
    # whether it is in force.
    "ssl-decryption-exclusion": ResultsSpec(
        query_fields={"Appliance": "hostname", "Where": "vsys_name", "Scope": "scope",
                      "Object": "exclusion_name", "Description": "description"},
        columns=("Appliance", "Scope", "Where", "Object", "Exclude", "Description"),
        base_queryset=_ordered(
            SslDecryptionExclusion, "appliance__hostname", "scope", "vsys_name", "name"),
        row=lambda e: (
            str(e.appliance),
            e.scope,
            _where(e),
            e.name,
            _yes_no(e.exclude),
            # An em dash and not a blank: an exclusion with no reason written on it is the whole
            # of PAN-DEC-004's first record, and a blank cell would read as a gap in the report.
            e.description or "—",
        ),
    ),
    # Objects > Decryption Profile, 2026-11-02, for PAN-DCP-001 to -005 and -007 - the NINTH page
    # over `integrations.SecurityProfile`. See that rail item for why it is not under Security
    # Profiles and why its scope is exactly one `kind eq` clause.
    #
    # EVERY HEADING HERE IS A PROPOSAL (P399) and each is the SAME WORD the Security Profile
    # findings sheet's `setting_labels` uses, character for character, so one column does not read
    # two ways on two surfaces. The sourcing is written once, in that sheet, against PAN-OS Web
    # Interface Help 11.2 p.339-346.
    #
    # THE CELLS DIFFER FROM THE FINDINGS TAB ON THE TWO VERSION COLUMNS, and that is a decision
    # rather than drift. The store holds the DEVICE's spelling - `tls1-0`, `tls1-2`, `max` - and
    # the model's own docstring requires that (the two leaves do not share a value set and `max`
    # sorts first while meaning the strongest setting there is). Here the lambda maps them to the
    # vendor's own UI values, which help 11.2 p.341 and p.345 give verbatim: "PAN-OS supports
    # SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and TLSv1.3" and "You can choose the option Max". On the
    # findings tab those two columns keep `display_value`'s raw token, because a `value_readers`
    # entry there would make `build_rows` hand the field `stored=False` and discard the column's
    # `FieldProvenance` row - and that row is the only thing separating a floor the operator typed
    # from one nobody ever set. Recorded rather than unified: it is the same split the
    # `url-filtering` run accepted for `credential_detection_mode`.
    "decryption-profile": ResultsSpec(
        query_fields={
            "Profile": "name", "Scope": "namespace_type",
            # INHERITED, not chosen: set by stage 9 of `file-data-filtering` and kept character
            # for character.
            "Vendor-shipped": "is_predefined",
            "Min Version": "ssl_min_version",
            "Max Version": "ssl_max_version",
            "Min Version below TLSv1.2": "ssl_min_version_below_tls12",
            "Max Version caps below what the appliance supports": "ssl_max_version_restrictive",
            "Weakest broken algorithm still negotiable": "weakest_broken_primitive_permitted",
            "Weakest algorithm lacking forward secrecy or authenticated encryption":
                "weakest_non_pfs_or_unauthenticated_permitted",
            # THE SEVEN INDIVIDUAL ALGORITHM SWITCHES HAVE NO `query_fields` ENTRY and are
            # COLUMNS, measured: none of the seven is in
            # `search/security_profile/compiler.py`'s registry, and the repo's rule is that only
            # a column a control asks for is registered. The two weakest-* verdicts above are
            # what a clause rests on; these are the evidence beside them.
            "Forward proxy: Block sessions with expired certificates":
                "fwd_block_expired_certificate",
            "Forward proxy: Block sessions with untrusted issuers": "fwd_block_untrusted_issuer",
            "Forward proxy: Block sessions with unsupported versions":
                "fwd_block_unsupported_version",
            "Forward proxy: Block sessions with unsupported cipher suites":
                "fwd_block_unsupported_cipher",
            "Forward proxy: Block sessions if resources not available": "fwd_block_if_no_resource",
            "Forward proxy: Block sessions if HSM not available": "fwd_block_if_hsm_unavailable",
            "Forward proxy: Block downgrade on no resources":
                "fwd_block_tls13_downgrade_no_resource",
            "Inbound inspection: Block sessions with unsupported versions":
                "inb_block_unsupported_version",
            "Inbound inspection: Block sessions with unsupported cipher suites":
                "inb_block_unsupported_cipher",
            "Inbound inspection: Block sessions if resources not available":
                "inb_block_if_no_resource",
            "Inbound inspection: Block sessions if HSM not available":
                "inb_block_if_hsm_unavailable",
            "Inbound inspection: Block downgrade on no resources":
                "inb_block_tls13_downgrade_no_resource",
            "No decryption rule narrows its destination": "rule_destination_unrestricted",
            "Decryption rulebase read from the device?": "decryption_rulebase_collected",
            "Named by a rule or profile group": "is_used",
            "Used by": "referrer_count",
            # `Max Version in force` HAS NO ENTRY ON PURPOSE. `ssl_max_version_resolved` is NOT in
            # `search/security_profile/compiler.py`'s registry - measured, not assumed - and a
            # heading mapped to an unregistered field points the "build a query from these rows"
            # button at a lookup that refuses itself. The column stays, because it is the evidence
            # the control's own `audit` text promises ("prints what the ceiling resolved to on that
            # appliance where the stored value is the no-maximum literal"); only the clause is
            # withheld.
        },
        columns=("Owner", "Profile", "Scope", "Vendor-shipped",
                 "Min Version", "Max Version", "Max Version in force",
                 "Min Version below TLSv1.2",
                 "Max Version caps below what the appliance supports",
                 "Weakest broken algorithm still negotiable",
                 "Weakest algorithm lacking forward secrecy or authenticated encryption",
                 # THE SEVEN SWITCHES BEHIND THOSE TWO VERDICTS, and STAGE 5 REQUIRES THEM. Its
                 # own words on the model: "COLLAPSING COSTS SOMETHING AND IT IS NAMED: where two
                 # broken primitives are permitted this holds only the worse, so a report naming
                 # RC4 is silent about SHA-1 on the same profile. The seven booleans above are all
                 # presented for exactly that reason." They cannot go on the FINDINGS tab: no
                 # shipped query clauses on any of them, so `setting_columns` derives nothing, and
                 # adding them as subject columns to the SHARED Security Profile sheet would put
                 # seven decryption columns on every one of the other eight kinds' rows. This page
                 # is scoped to `kind eq "decryption"`, so it is where they belong.
                 #
                 # THE VENDOR'S OWN GROUP AND ALGORITHM NAMES, help 11.2 p.345-346: "Key Exchange
                 # Algorithms ... All three algorithms (RSA, DHE, and ECDHE)", "Encryption
                 # Algorithms ... the weak 3DES or RC4", "Authentication Algorithms ... the old,
                 # weak MD5 algorithm ... SHA1". The group prefix is the vendor's heading and is
                 # kept because it is what an assessor reads down the left of that tab.
                 "Key Exchange Algorithms: RSA",
                 "Encryption Algorithms: 3DES",
                 "Encryption Algorithms: RC4",
                 "Encryption Algorithms: AES-128-CBC",
                 "Encryption Algorithms: AES-256-CBC",
                 "Authentication Algorithms: MD5",
                 "Authentication Algorithms: SHA1",
                 "Forward proxy: Block sessions with expired certificates",
                 "Forward proxy: Block sessions with untrusted issuers",
                 "Forward proxy: Block sessions with unsupported versions",
                 "Forward proxy: Block sessions with unsupported cipher suites",
                 "Forward proxy: Block sessions if resources not available",
                 "Forward proxy: Block sessions if HSM not available",
                 "Forward proxy: Block downgrade on no resources",
                 "Inbound inspection: Block sessions with unsupported versions",
                 "Inbound inspection: Block sessions with unsupported cipher suites",
                 "Inbound inspection: Block sessions if resources not available",
                 "Inbound inspection: Block sessions if HSM not available",
                 "Inbound inspection: Block downgrade on no resources",
                 "No decryption rule narrows its destination",
                 "Decryption rulebase read from the device?",
                 "Named by a rule or profile group", "Used by"),
        base_queryset=_security_profiles,
        scope=_kind_scope("decryption"),
        row=lambda p: (
            p.appliance_group.name if p.appliance_group_id else str(p.enforcement_point),
            p.name,
            p.get_namespace_type_display(),
            _yes_no(p.is_predefined),
            _tls_version(p.ssl_min_version),
            _tls_version(p.ssl_max_version),
            _resolved_ceiling(p),
            _yes_no(p.ssl_min_version_below_tls12),
            _yes_no(p.ssl_max_version_restrictive),
            _weakest_primitive(p.weakest_broken_primitive_permitted),
            _weakest_primitive(p.weakest_non_pfs_or_unauthenticated_permitted),
            _permitted(p.keyxchg_algo_rsa),
            _permitted(p.enc_algo_3des),
            _permitted(p.enc_algo_rc4),
            _permitted(p.enc_algo_aes_128_cbc),
            _permitted(p.enc_algo_aes_256_cbc),
            _permitted(p.auth_algo_md5),
            _permitted(p.auth_algo_sha1),
            _yes_no(p.fwd_block_expired_certificate),
            _yes_no(p.fwd_block_untrusted_issuer),
            _yes_no(p.fwd_block_unsupported_version),
            _yes_no(p.fwd_block_unsupported_cipher),
            _yes_no(p.fwd_block_if_no_resource),
            _yes_no(p.fwd_block_if_hsm_unavailable),
            _yes_no(p.fwd_block_tls13_downgrade_no_resource),
            _yes_no(p.inb_block_unsupported_version),
            _yes_no(p.inb_block_unsupported_cipher),
            _yes_no(p.inb_block_if_no_resource),
            _yes_no(p.inb_block_if_hsm_unavailable),
            _yes_no(p.inb_block_tls13_downgrade_no_resource),
            _yes_no(p.rule_destination_unrestricted),
            _yes_no(p.decryption_rulebase_collected),
            _yes_no(p.is_used),
            _nothing(p.referrer_count, "referrer(s)"),
        ),
    ),
    # Device > Certificate Management > Certificates, 2026-11-02, for PAN-DCP-006 - a SECOND page
    # at one vendor address over a different model. See that rail item.
    #
    # THE FOUR DESIGNATION SLOTS ARE COLUMNS AND NOT `query_fields`, and the compiler says why in
    # its own words: they are "deliberately not registered ... They are what a READER is shown so
    # a finding can name WHICH slot is empty, which is stage 9's business, and registering them
    # would ship a search surface no control asks for". So they are shown and not clauseable, and
    # that is the division of labour rather than a gap.
    #
    # ONE ROW PER APPLIANCE, which is the grain the model takes and the reason it can report at
    # all: the commonest failing state is that NO certificate is designated, and a per-slot grain
    # has no row in exactly that state.
    "forward-proxy-signing": ResultsSpec(
        query_fields={
            "Appliance": "hostname", "Serial": "serial_number",
            "Trust certificate is a local self-signed CA":
                "forward_trust_is_designated_local_ca",
            "Untrust authority differs from trust": "untrust_distinct_from_trust"},
        columns=("Appliance", "Serial", "Forward Trust Certificate (RSA)",
                 "Forward Trust Certificate (ECDSA)", "Forward Untrust Certificate (RSA)",
                 "Forward Untrust Certificate (ECDSA)",
                 "Trust certificate is a local self-signed CA",
                 "Untrust authority differs from trust"),
        base_queryset=_ordered(DecryptionSettings, "appliance__hostname"),
        row=lambda d: (
            str(d.appliance),
            d.appliance.serial_number or "-",
            # "Nothing designated" and not a blank. An empty slot is the whole finding
            # PAN-DCP-006 makes, and an empty cell reads as missing data - which is the same
            # argument the NTP page's "None" makes one screen over.
            d.forward_trust_cert_rsa or "Nothing designated",
            d.forward_trust_cert_ecdsa or "Nothing designated",
            d.forward_untrust_cert_rsa or "Nothing designated",
            d.forward_untrust_cert_ecdsa or "Nothing designated",
            _yes_no(d.forward_trust_is_designated_local_ca),
            _yes_no(d.untrust_distinct_from_trust),
        ),
    ),
}


#: Models whose object has no rail item yet, and the page that presents it in the meantime.
#: EMPTY since 2026-09-18, when `Policies > Security` landed and security rules - the only entry
#: this ever held - got a rail item like every other object. Kept rather than deleted because
#: the next object to be presented before it is placed will need it, and because an empty map
#: states that nothing is currently in that position.
LEGACY_SURFACE: dict[str, str] = {}


#: Control id prefixes whose domain has reached stage 8 and not yet stage 9, so their queries are
#: OWED a results page rather than missing one. Each entry is a debt with a name on it.
#:
#: WHY THIS IS NOT THE SAME HOLE THE TEST EXISTS TO CLOSE. A control whose link goes nowhere is
#: one an assessor cannot check, and that is true whoever's fault it is. What changed is that the
#: pipeline now builds the control and the page in SEPARATE stages, by Jason's decision of
#: 2026-10-22 - stage 8 writes the control seed and its queries, stage 9 writes the live view -
#: and stage 8's contract forbids it to build a page. So between the two, a homeless query is the
#: correct state of a domain in flight, and a suite that is red for every such domain stops being
#: a signal: over 28 domains that is most of the time.
#:
#: WHAT KEEPS IT HONEST, because a declared exemption can rot into a permanent one:
#:   - an entry names the stage 9 artifact that removes it, so the debt has an owner
#:   - `probe/validate_stage9.py` refuses a stage 9 artifact that gives a model no page, so the
#:     obligation is enforced from the other side rather than merely waived here
#:   - `test_no_prefix_outlives_its_stage_9_artifact` fails once that artifact exists, so an
#:     entry cannot survive the work that was supposed to clear it
#:
#: `LEGACY_SURFACE` above is the precedent for the shape and for the lifecycle: it held one entry,
#: the entry was cleared when the rail item landed, and the empty map now states that nothing is
#: in that position.
#:
#: It was EMPTY from 2026-10-28, when the first stage 9 run presented `ike-crypto` and cleared
#: the `PAN-IKE` entry - the only one it had ever held - until stage 8 of `ha-panorama` on
#: 2026-10-30 put the second one in. So the lifecycle has now run a full cycle: filled by a
#: stage 8, emptied by the stage 9 it named, filled again.
AWAITING_PRESENTATION: dict[str, str] = {
    # `management-services` reached stage 8 on 2026-11-01. THIRTEEN controls over ten models,
    # and this is ONE line rather than two because the map is keyed by CONTROL-ID PREFIX and not
    # by model - `_awaiting` prefix-matches the control id, so a single `PAN-MGT` entry covers
    # every control of the domain and is consulted only where `query_results_url` returns
    # nothing. Measured with a canonical-query DICT, which is the only way to measure it: a bare
    # label string takes the `else` arm and returns "" for every model, which reads as all of
    # them needing a line.
    #
    # SIX OF THE EIGHT MODELS CARRYING THESE CONTROLS ALREADY RESOLVE and were never homeless -
    # ManagementInterface, LoginBanner, UpdateServerSettings, LoggingSettings,
    # ManagementTlsBinding and InterfaceManagementProfile each answer a real page. This entry is
    # load-bearing for exactly TWO of the thirteen controls, PAN-MGT-004 and PAN-MGT-012, whose
    # models `ManagementPlaneAddressing` and `ApplianceOperationalMode` were minted by this
    # stage and have no rail item. It is harmless for the other eleven. Stage 9 for this domain
    # is what gives the two models a page, and stage 8's contract forbids building one.
    "PAN-MGT": "stage9-management-services.json",
    # `logging` reached stage 8 on 2026-11-01. TWO of its three models have no rail item:
    # `LogServerTarget` and `VsysLogForwarding` were both created by stage 7 for this domain and
    # had never been queried from this repository at all. The third, `LoggingSettings`, DOES
    # have a page - `Device > Setup > Management > Logging and Reporting Settings` - which it
    # has had since PAN-MGT-011, so this entry is load-bearing for exactly TWO of the ten
    # PAN-LOG controls (002 and 005) and harmless for the other eight: `_awaiting` is consulted
    # only where `query_results_url` returns nothing, and the eight logging-settings controls
    # resolve on their own. NOTE that PAN-MGT-011 has no entry here and never needed one, for
    # the same reason. Stage 9 for this domain is what gives the two models a page, and stage
    # 8's contract forbids building one.
    "PAN-LOG": "stage9-logging.json",
    # `PAN-POL` WAS HERE AND IS GONE, removed by stage 9 of `security-policy` on 2026-11-01,
    # which is the work the entry was waiting for. The two models it covered -
    # `integrations.VsysRulePosture` and `integrations.PolicyRuleSettings` - now have rail items
    # and results specs above, so every PAN-POL query resolves on its own and
    # `test_no_prefix_outlives_its_stage_9_artifact` passes. Removing it is part of that stage's
    # job rather than a side effect of it: an exemption that survives the work it was waiting
    # for is a permanent hole.
    # `PAN-IPS` CAME OUT ON 2026-11-02, which is stage 9 of `ipsec-crypto` doing the thing the
    # entry was waiting for. Both models - `integrations.IpsecCryptoProfile` and
    # `integrations.IpsecTunnel` - now have rail items and results specs above, so all 33 of the
    # domain's shipped queries resolve on their own and
    # `test_no_prefix_outlives_its_stage_9_artifact` passes. Removing it is part of that stage's
    # job rather than a side effect of it: an exemption that survives the work it was waiting for
    # is a permanent hole.
    # `PAN-UID` CAME OUT ON 2026-11-02, which is stage 9 of `user-id` doing the thing the entry
    # was waiting for. The two models that were still homeless -
    # `integrations.UserIdCollectorSettings` and `integrations.UserIdDiscoveryBound` - now have
    # rail items and results specs above, so all 14 of the domain's shipped queries resolve on
    # their own and `test_no_prefix_outlives_its_stage_9_artifact` passes. Removing it is part of
    # that stage's job rather than a side effect of it: an exemption that survives the work it was
    # waiting for is a permanent hole.
    #
    # ON THE WAY OUT, A CORRECTION TO THE RECORD rather than to anything that still runs. The
    # comment deleted here opened "FOUR models carry its six controls and none of the four has a
    # rail item" and then named `integrations.ManagementInterface`, "which DOES have a page", two
    # clauses later - so the sentence contradicted itself on the day it was written and was never
    # true. `device-id-iot` appended a correcting paragraph on 2026-11-02 saying two models were
    # homeless rather than three, which was right, but left the false opening sentence standing
    # above it. Measured before deleting: two of the four were homeless, and the Zone and
    # ManagementInterface halves both resolved on their own. Noted because appending a correction
    # under a wrong sentence leaves a reader to work out which half to believe.
    # PAN-HAP-001 to 005 target two device-wide management-plane models that no rail item
    # reaches yet. PAN-HAP-006 and 007 have no entry in the catalog at all - they assert over
    # Panorama's own configuration, which is out of assessment scope - so this debt is for five
    # controls and not seven.
    "PAN-HAP": "stage9-ha-panorama.json",
    "PAN-NET": "stage9-network-hardening.json",
    # `saas-security` reached stage 8 on 2026-10-30. FOUR of its models had never been queried
    # from this repository at all, so none of them has a rail item: the three enforcement-point
    # verdicts and the device-wide App-ID Cloud Engine. Stage 9 for this domain is what gives
    # them a page, and stage 8's contract forbids building one.
    "PAN-SAS-": "stage9-saas-security.json",
    # `PAN-IOT` WAS HERE AND IS GONE, 2026-11-02, cleared by stage 9 of `device-id-iot`. Its
    # three models - `integrations.DeviceIdentificationState`, `integrations.Zone` and
    # `integrations.RulebaseDeviceMatchVerdict` - now have rail items and results specs above, so
    # all ten of the domain's shipped queries resolve on their own and
    # `test_no_prefix_outlives_its_stage_9_artifact` passes. Removing it is part of that stage's
    # job rather than a side effect of it: an exemption that survives the work it was waiting for
    # is a permanent hole.
    #
    # `integrations.Zone` IS NOW PRESENTED AND TWO LATER DOMAINS INHERIT IT. The `zones` rail
    # item and its page were written to be shared - see that `ResultsSpec` - so the Zone half of
    # the `PAN-UID` and `PAN-ZON` debts below is already discharged and only their other models
    # keep those entries alive. Both comments were corrected to say so.
    # `PAN-FIL` WAS HERE AND IS GONE, cleared 2026-11-02 by stage 9 of `file-data-filtering`,
    # which is the work the entry was waiting for. Its own words were: "Two models and neither has
    # a rail item: `DataFilteringPosture` did not exist before stage 7 for this domain, and
    # `SecurityProfile`'s pages are per profile KIND, mirroring PAN-OS's own tabs, so the two kinds
    # this domain adds - File Blocking and Data Filtering - have no page either."
    #
    # ALL THREE NOW HAVE ONE: `file-blocking` and `data-filtering`, the sixth and seventh pages
    # over `integrations.SecurityProfile` each scoped by one `kind eq` clause, and
    # `data-filtering-posture` over `integrations.DataFilteringPosture`. So all fifteen shipped
    # PAN-FIL queries resolve on their own and `test_no_prefix_outlives_its_stage_9_artifact`
    # passes. Removing it is part of that stage's job rather than a side effect: an exemption that
    # survives the work it was waiting for is a permanent hole.
    # `PAN-GPP` WAS HERE AND IS GONE, cleared 2026-11-02 by stage 9 of `globalprotect-portal`,
    # which is the work the entry was waiting for. Its own words were: "`globalprotect-portal`
    # reached stage 8 on 2026-10-31. THREE models and none of them has a rail item: all three were
    # created by stage 7 for this domain and had never been queried from this repository at all.
    # Stage 9 for this domain is what gives them a page, and stage 8's contract forbids building
    # one. The portal and its client-auth ROW will want two pages rather than one, because the row
    # is the grain a PAN-GPP-002 finding names."
    #
    # ALL THREE NOW HAVE ONE, in a NEW rail group - `Network > GlobalProtect`, the vendor's own
    # group, enumerated verbatim at help 11.2 p.997: `globalprotect-portals` over
    # `integrations.GlobalProtectPortal`, `globalprotect-portal-authentication` over
    # `integrations.GlobalProtectPortalClientAuthRow`, and `globalprotect-coverage` over
    # `integrations.GlobalProtectEnforcementPoint`. So all TWENTY-FOUR shipped PAN-GPP queries
    # resolve on their own and `test_no_prefix_outlives_its_stage_9_artifact` passes. Removing it
    # is part of that stage's job rather than a side effect: an exemption that survives the work
    # it was waiting for is a permanent hole.
    #
    # THE ENTRY WAS RIGHT ABOUT THE TWO PAGES AND RIGHT THAT THE DEBT COVERED ALL SIX CONTROLS,
    # and `probe.surface_for` confirmed the harder half: all six reached NO SHEET AT ALL, so every
    # one of them needed both surfaces rather than only a results destination. That is the
    # opposite of `PAN-URL` and `PAN-DCP` above, where most controls already had a tab.
    #
    # `PAN-GPG` BELOW STILL NEEDS ITS OWN ENTRY AND IS NOW SMALLER BY ONE MODEL.
    # `integrations.GlobalProtectEnforcementPoint` is shared between the two domains and is the
    # one this run gave a page to, so that entry's remaining debt is the three models
    # `globalprotect-gateway`'s own stage 7 created. Its text is left exactly as it stands,
    # because an entry is the debt its own stage 9 clears.
    # `platform-lifecycle` reached stage 8 on 2026-11-01. THREE models and none of them has a
    # rail item: all three were created by stage 7 for this domain and had never been queried from
    # this repository at all. Stage 9 for this domain is what gives them a page, and stage 8's
    # contract forbids building one. THIS DEBT IS FOR THREE OF THE DOMAIN'S SIX CONTROLS, not six:
    # PAN-PLT-001, -003 and -005 are discharged `engineer_answers` by stage 5, owe no query and
    # have no catalog entry at all, so they have no link to go nowhere.
    "PAN-PLT": "stage9-platform-lifecycle.json",
    # `updates` reached stage 8 on 2026-11-01. `integrations.ContentUpdateSchedule` was created
    # by stage 7 for this domain and had never been queried from this repository, so it has no
    # rail item; stage 9 for this domain is what gives it a page and stage 8's contract forbids
    # building one. THIS DEBT IS FOR FOUR OF THE DOMAIN'S SIX CONTROLS, not six: PAN-UPD-003 is
    # discharged `engineer_answers` and PAN-UPD-006 `not_in_configuration` plus
    # `engineer_answers`, so neither owes a query, neither has a catalog entry, and neither has a
    # link to go nowhere.
    "PAN-UPD": "stage9-updates.json",
    # `PAN-URL` WAS HERE AND IS GONE, cleared 2026-11-02 by stage 9 of `url-filtering`, which is
    # the work the entry was waiting for. Its own words were: "ONE PREFIX COVERS BOTH OF THIS
    # DOMAIN'S MODELS, and that is not a shortcut: `integrations.CustomUrlCategory` was created by
    # stage 7 for this domain and has never been queried from this repository, so it has no rail
    # item - and `SecurityProfile`'s results pages are per profile KIND, mirroring PAN-OS's own
    # tabs, so the `url-filtering` kind that PAN-URL-001 to -005 query has no page either."
    #
    # BOTH NOW HAVE ONE: `url-filtering`, the EIGHTH page over `integrations.SecurityProfile`
    # scoped by one `kind eq` clause, and `custom-url-categories` over
    # `integrations.CustomUrlCategory`. So all THIRTY-TWO shipped PAN-URL queries - the largest
    # query count of any domain in this batch - resolve on their own and
    # `test_no_prefix_outlives_its_stage_9_artifact` passes. Removing it is part of that stage's
    # job rather than a side effect: an exemption that survives the work it was waiting for is a
    # permanent hole.
    #
    # THE ENTRY WAS RIGHT THAT THE DEBT COVERED ALL SIX CONTROLS, and it is worth recording that
    # only FIVE of the six needed a new findings tab's worth of work: PAN-URL-001 to -005 already
    # reached the shared `Security Profile` tab and needed only this results destination, while
    # PAN-URL-006 needed both. The results destination and the findings tab are two different
    # surfaces and this entry was only ever a debt against the first.
    # `PAN-DCP` WAS HERE AND IS GONE, cleared 2026-11-02 by stage 9 of `decryption-profiles`,
    # which is the work the entry was waiting for. Its own words were: "ONE PREFIX COVERS BOTH OF
    # THIS DOMAIN's MODELS. `integrations.DecryptionSettings` was created by stage 7 for this
    # domain and has never been queried from this repository, so it has no rail item - and
    # `SecurityProfile`'s results pages are per profile KIND, mirroring PAN-OS's own tabs, so the
    # `decryption` kind that PAN-DCP-001 to -005 and -007 query has no page either."
    #
    # BOTH NOW HAVE ONE: `decryption-profile`, the NINTH page over `integrations.SecurityProfile`
    # scoped by one `kind eq` clause, and `forward-proxy-signing` over
    # `integrations.DecryptionSettings`. So all TWENTY-FIVE shipped PAN-DCP queries - twenty-three
    # over the profile model and two over the signing model - resolve on their own and
    # `test_no_prefix_outlives_its_stage_9_artifact` passes. Removing it is part of that stage's
    # job rather than a side effect: an exemption that survives the work it was waiting for is a
    # permanent hole.
    #
    # THE ENTRY WAS RIGHT THAT THE DEBT COVERED ALL SEVEN CONTROLS, and only ONE of the seven
    # needed a new findings tab's worth of work: `probe.surface_for` reports PAN-DCP-001 to -005
    # and -007 already reaching the shared `Security Profile` tab and needing only this results
    # destination, while PAN-DCP-006 reached NO SHEET AT ALL and needed both. The results
    # destination and the findings tab are two different surfaces and this entry was only ever a
    # debt against the first.
    # `globalprotect-gateway` reached stage 8 on 2026-11-01. FOUR models carry its seven controls
    # and none of the four has a rail item: the three this domain's stage 7 created - the gateway
    # entry, its client-authentication row and its agent client-settings row - plus
    # `integrations.GlobalProtectEnforcementPoint`, whose own debt the `PAN-GPP` entry above
    # already names. So this entry is load-bearing for six of the seven controls and harmless for
    # PAN-GPG-005, whose model is already declared: `_awaiting` is consulted only where
    # `query_results_url` returns nothing.
    #
    # ONE LINE CLEARS TWENTY-FIVE FAILURES, because `test_configuration_links` fails ONCE PER
    # CATALOG QUERY of a new type rather than once per type, and this domain seeds 25 queries.
    # Stage 9 for this domain is what gives the three new models a page, and stage 8's contract
    # forbids building one.
    "PAN-GPG": "stage9-globalprotect-gateway.json",
    # `PAN-ZON` WAS HERE AND IS GONE, cleared 2026-11-02 by stage 9 of `zone-dos-protection`,
    # which is the artifact the entry named. Its comment was checked against the code before the
    # line was deleted and it read true: `integrations.Zone` already had the shared `zones` rail
    # item (so PAN-ZON-001's queries already resolved), and the other three models were homeless.
    # All three now have a rail item of their own - `zone-protection` over
    # `integrations.ZoneProtectionProfile`, `dos-protection-rules` over
    # `integrations.DosPolicyRule`, and `dos-protection`, the FIFTH page over
    # `integrations.SecurityProfile`, scoped by `kind eq "dos-protection"`.
    # `PAN-DEC` WAS HERE AND IS GONE, cleared 2026-11-02 by stage 9 of `decryption-policy`, which
    # is the artifact the entry named. All 21 of the domain's shipped queries now resolve on their
    # own through three new rail items and results specs above - `decryption-rules` over
    # `integrations.DecryptionPolicyRule` and `decryption-coverage` over
    # `integrations.DecryptionRulebaseVerdict`, both at Policies > Decryption, and
    # `ssl-decryption-exclusion` over `integrations.SslDecryptionExclusion` at Device >
    # Certificate Management > SSL Decryption Exclusion - so
    # `test_no_prefix_outlives_its_stage_9_artifact` passes. Removing it is part of that stage's
    # job rather than a side effect of it: an exemption that survives the work it was waiting for
    # is a permanent hole.
    #
    # ON THE WAY OUT, A CORRECTION TO THE RECORD rather than to anything that still runs. The
    # comment deleted here opened "FOUR models carry its ten controls and NONE of the four has a
    # rail item". THREE models carry queries, measured over the seed payload before the line was
    # deleted: 16 against `DecryptionPolicyRule`, 4 against `DecryptionRulebaseVerdict` and 1
    # against `SslDecryptionExclusion`, 21 in all. The fourth model,
    # `integrations.SslDecryptionVendorExclusionOptOut`, is named by NO query at all - it carries
    # PAN-DEC-004's second assertion record, which no catalogue id could hold because
    # `_CONTROL_TYPE_TARGET_MODEL` maps one type to one model - so it was never homeless in the
    # sense this map is about, because `query_results_url` is never asked about it. It is given no
    # rail item and no findings tab, deliberately; its generator's docstring carries the three
    # reasons, and splitting PAN-DEC-004 into two catalogue ids is Jason's decision.
    #
    # The rest of that comment read true and is left on the record by this paragraph: the debt was
    # for nine of the ten controls by count of controls and for all 21 by count of QUERIES, which
    # is what `test_configuration_links` fails once per.
    # `device-services` reached stage 8 on 2026-11-01. TWO models and neither has a rail item:
    # `integrations.DnsSettings` and `integrations.ServiceRoute` were both created by stage 7 for
    # this domain and had never been queried from this repository at all. The entry is keyed on
    # the whole `PAN-SVC` prefix and is therefore wider than the debt - the seven controls this
    # domain already shipped target NTP, SNMP and system identity, all three of which have a
    # rail item and resolve on their own - and that is harmless, because `_awaiting` is consulted
    # only where `query_results_url` returns nothing. So this is load-bearing for the seven
    # queries of PAN-SVC-003 and PAN-SVC-006 and inert for the other twenty-five. Stage 9 for
    # this domain is what gives the two models a page, and stage 8's contract forbids building
    # one.
    "PAN-SVC": "stage9-device-services.json",
}



def _clause_key(clause):
    """A clause's IDENTITY for containment, ignoring the defaults the validator fills in.

    `case_sensitive` and `include_any` are normalization, not meaning: a scope written without
    them and a control query that has been through `validate_search_payload` describe the same
    clause and must compare equal.
    """
    return (clause.get("field"), clause.get("op"),
            clause.get("value"), bool(clause.get("negated", False)))


def object_for_canonical_query(canonical_query):
    """The rail item whose page ANSWERS this query, or None when no page does.

    One model usually means one page. Where it means two - anti-spyware and vulnerability
    protection over `SecurityProfile` - the page is the one whose `scope` the query already
    carries: a scope is applied to the rows before the query is, so sending an anti-spyware
    query to the vulnerability page returns nothing and reads as "no profile is like this"
    rather than as "wrong page".

    Returns None rather than guessing when the model has several pages and the query names
    neither scope. A link that goes somewhere plausible and wrong is worse than no link, and
    `test_configuration_links` asserts that no control in the shipped catalog lands here.
    """
    if not isinstance(canonical_query, dict):
        return None
    candidates = config_nav.objects_for_model(canonical_query.get("model") or "")
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        return None

    clauses = {_clause_key(c) for c in canonical_query.get("clauses", []) if "field" in c}
    matched = [
        obj for obj in candidates
        if (scope := RESULTS[obj.slug].scope)
        and {_clause_key(c) for c in scope.get("clauses", [])} <= clauses
    ]
    return matched[0] if len(matched) == 1 else None


def control_results_url(target_model, baseline_query, *, control_pk) -> str:
    """Where "what would this CONTROL report" goes. "" when nothing can answer it.

    Keyed on the control's DECLARED target rather than on its query's model, and the difference
    is not pedantic: findings are generated per control TYPE, so a control declaring no target
    produces no findings at all, and offering to preview what it would report is offering an
    answer that cannot exist. A query carrying a model it can run against is a different
    question - `query_results_url` answers that one, and a query is previewable wherever it runs.

    The baseline query still comes in, for the one thing the target model cannot settle on its
    own: which of two pages over a shared model (anti-spyware, vulnerability protection) the
    control belongs to.
    """
    if not target_model:
        return ""
    if not isinstance(baseline_query, dict) or baseline_query.get("model") != target_model:
        baseline_query = {"model": target_model, "clauses": []}
    return query_results_url(baseline_query, control_pk=control_pk)


def query_results_url(canonical_query, *, control_query_pk=None, control_pk=None) -> str:
    """Where "view query results" goes for a query over ANY model. "" when nowhere does.

    The destination follows the query's own model, which is the whole point: this used to be
    hard-coded to the security rules page on the control detail page, so every control that was
    not about rules opened a builder that then refused its own query.
    """
    obj = object_for_canonical_query(canonical_query)
    if obj is not None:
        url = reverse("assessment_configuration_object",
                      args=[config_nav.category_slug(obj.category), obj.slug])
    elif isinstance(canonical_query, dict) and canonical_query.get("model") in LEGACY_SURFACE:
        url = reverse(LEGACY_SURFACE[canonical_query["model"]])
    else:
        return ""
    if control_query_pk is not None:
        return f"{url}?control_query={control_query_pk}"
    if control_pk is not None:
        return f"{url}?control={control_pk}"
    return url
