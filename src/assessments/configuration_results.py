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
from assessments import ike_presentation as ike
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
    IkeCryptoProfile,
    IkeGateway,
    InterfaceManagementProfile,
    ManagementInterface,
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
    SecurityProfile,
    ServerProfile,
    SslTlsServiceProfile,
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


def _ordered(model, *fields, related=("appliance",)):
    def rows():
        return model.objects.select_related(*related).order_by(*fields)
    return rows


_security_profiles = _ordered(
    SecurityProfile, "is_predefined", "name", "appliance_group__name", "enforcement_point__vsys_name",
    related=("enforcement_point__appliance_group", "appliance_group"))


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
    return (obj.securityrulesourceaddressref_set.exists()
            if hasattr(obj, "securityrulesourceaddressref_set")
            else obj.source_address_refs.exists() or obj.destination_address_refs.exists())


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
            ("All (RSA + every ECDSA curve)" if s.host_key_type.lower() == "all"
             else f"{s.host_key_type} {s.host_key_bits}"),
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
    "logging-and-reporting": ResultsSpec(
        query_fields={"Appliance": "hostname",
                      "Log on High DP Load": "log_on_high_dp_load"},
        columns=("Appliance", "Log on High DP Load"),
        base_queryset=_ordered(LoggingSettings, "appliance__hostname"),
        row=lambda p: (str(p.appliance), _yes_no(p.log_on_high_dp_load)),
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
    # `ipsec-crypto` reached stage 8 on 2026-11-01. TWO models and neither has a rail item:
    # `IpsecCryptoProfile` and `IpsecTunnel` were both created by stage 7 for this domain and
    # had never been queried from this repository at all. The rail's two IKE entries are the
    # PHASE 1 objects at the adjacent xpath and reach neither of these. This entry is
    # load-bearing for all nine PAN-IPS controls, and it fails once per catalogue QUERY rather
    # than once per type - 33 queries ship here. Stage 9 for this domain is what gives the two
    # models a page, and stage 8's contract forbids building one.
    "PAN-IPS": "stage9-ipsec-crypto.json",
    # `user-id` reached stage 8 on 2026-11-01. FOUR models carry its six controls and none of
    # the four has a rail item: the two this domain created - the per-vsys User-ID collector
    # settings node and the per-vsys discovery bound - plus `integrations.Zone`, which has been
    # stored for months and whose own debt the `PAN-IOT` entry above already names, and
    # `integrations.ManagementInterface`, which DOES have a page. So this entry is load-bearing
    # for five of the six controls and harmless for the sixth: `_awaiting` is consulted only
    # where `query_results_url` returns nothing, and PAN-UID-005's management-interface queries
    # resolve on their own. Stage 9 for this domain is what gives the other three a page, and
    # stage 8's contract forbids building one.
    "PAN-UID": "stage9-user-id.json",
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
    # `device-id-iot` reached stage 8 on 2026-10-31. THREE models and none of them has a rail
    # item: the appliance's device-identification service state and the rulebase device-match
    # verdict had never been queried from this repository at all, and `Zone` had been stored for
    # months with no control, no page and no search surface over it. Stage 9 for this domain is
    # what gives all three a page, and stage 8's contract forbids building one.
    "PAN-IOT": "stage9-device-id-iot.json",
    # `file-data-filtering` reached stage 8 on 2026-10-31. Two models and neither has a rail
    # item: `DataFilteringPosture` did not exist before stage 7 for this domain, and
    # `SecurityProfile`'s pages are per profile KIND, mirroring PAN-OS's own tabs, so the two
    # kinds this domain adds - File Blocking and Data Filtering - have no page either. Stage 9
    # for this domain is what gives all of them one, and stage 8's contract forbids building it.
    "PAN-FIL": "stage9-file-data-filtering.json",
    # `globalprotect-portal` reached stage 8 on 2026-10-31. THREE models and none of them has a
    # rail item: all three were created by stage 7 for this domain and had never been queried from
    # this repository at all. Stage 9 for this domain is what gives them a page, and stage 8's
    # contract forbids building one. The portal and its client-auth ROW will want two pages rather
    # than one, because the row is the grain a PAN-GPP-002 finding names.
    "PAN-GPP": "stage9-globalprotect-portal.json",
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
    # `url-filtering` reached stage 8 on 2026-11-01. ONE PREFIX COVERS BOTH OF THIS DOMAIN'S
    # MODELS, and that is not a shortcut: `integrations.CustomUrlCategory` was created by stage 7
    # for this domain and has never been queried from this repository, so it has no rail item -
    # and `SecurityProfile`'s results pages are per profile KIND, mirroring PAN-OS's own tabs, so
    # the `url-filtering` kind that PAN-URL-001 to -005 query has no page either. Stage 9 for
    # this domain is what gives both of them one, and stage 8's contract forbids building it.
    #
    # THIS DEBT IS FOR ALL SIX OF THE DOMAIN'S CONTROLS. Every one of its eleven stage 5
    # assertion records is discharged `expression`, so every control owes at least one query and
    # none of them is engineer-answered.
    "PAN-URL": "stage9-url-filtering.json",
    # `decryption-profiles` reached stage 8 on 2026-11-01. ONE PREFIX COVERS BOTH OF THIS
    # DOMAIN's MODELS. `integrations.DecryptionSettings` was created by stage 7 for this domain
    # and has never been queried from this repository, so it has no rail item - and
    # `SecurityProfile`'s results pages are per profile KIND, mirroring PAN-OS's own tabs, so the
    # `decryption` kind that PAN-DCP-001 to -005 and -007 query has no page either. Stage 9 for
    # this domain is what gives both of them one, and stage 8's contract forbids building it.
    #
    # THIS DEBT IS FOR ALL SEVEN OF THE DOMAIN's CONTROLS, and it is worth saying that PAN-DCP-006
    # is included rather than exempt: two of its four stage 5 assertion records are discharged
    # `not_in_configuration` and `engineer_answers` and owe no query, but its other two are
    # `expression` over the signing model and carry three queries between them, so the control
    # has a catalog entry and links that go nowhere. The entry fails once per catalog QUERY
    # rather than once per control, which for this domain is twenty-five queries - twenty-three
    # over the profile model and two over the signing model.
    "PAN-DCP": "stage9-decryption-profiles.json",
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
    # `zone-dos-protection` reached stage 8 on 2026-11-01. FOUR models carry its eight controls
    # and NONE of the four has a rail item: the two this domain's stage 7 created - the zone
    # protection profile and the DoS policy rule - plus `integrations.Zone`, whose own debt the
    # `PAN-IOT` and `PAN-UID` entries above already name, plus `integrations.SecurityProfile`,
    # whose results pages are per profile KIND, mirroring PAN-OS's own tabs, so the
    # `dos-protection` kind that PAN-ZON-008 queries has no page either. Stage 9 for this domain
    # is what gives all four of them one, and stage 8's contract forbids building it.
    #
    # THIS DEBT IS FOR SEVEN OF THE DOMAIN'S EIGHT CONTROLS AND ONE LINE CLEARS TWENTY-FIVE
    # FAILURES, because `test_configuration_links` fails once per catalog QUERY of a homeless
    # model rather than once per model. The eighth control is PAN-ZON-007, whose queries are over
    # a model created by the same stage 7 and are therefore homeless too - so in practice all
    # eight are covered and none of this domain's twenty-five queries has anywhere to go until
    # stage 9 lands.
    "PAN-ZON": "stage9-zone-dos-protection.json",
    # `decryption-policy` reached stage 8 on 2026-11-01. FOUR models carry its ten controls and
    # NONE of the four has a rail item: all four were created by stage 7 for this domain and had
    # never been queried from this repository at all. Stage 9 for this domain is what gives them a
    # page, and stage 8's contract forbids building one. The two rule models will want two pages
    # rather than one, because a PAN-DEC-001 finding names a VIRTUAL SYSTEM and a PAN-DEC-002
    # finding names a RULE inside it.
    #
    # THIS DEBT IS FOR NINE OF THE DOMAIN'S TEN CONTROLS, and the tenth is worth naming rather than
    # leaving to arithmetic: every one of the ten has a catalog entry and at least one query, so
    # every one has links that would go nowhere - `_awaiting` is consulted only where
    # `query_results_url` returns nothing, and it returns nothing for all four of these models. The
    # count of QUERIES is what this clears, not the count of controls: `test_configuration_links`
    # fails once per catalog query of a homeless model, and this domain seeds 21.
    "PAN-DEC": "stage9-decryption-policy.json",
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
