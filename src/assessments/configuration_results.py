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
    InterfaceManagementProfile,
    ManagementInterface,
    AuthenticationSettings,
    LoggingSettings,
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


def _verdict(blocked, detail):
    """The reason on BOTH sides: which action blocks it, or why nothing does."""
    return f"blocked ({detail})" if blocked else detail


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
    groups = [value.value for value in rule.securityruleprofilegroups.all()]
    individual = [f"{profile.profile_type}: {profile.value}"
                  for profile in rule.securityruleprofiles.all()]
    return _lines(groups + individual)


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
            ("until released" if not p.lockout_time_minutes
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
