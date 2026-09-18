"""The configuration explorer's navigation, in one place, for the reason `navigation.py` is.

Two levels, both taken from the PAN-OS web interface rather than invented here:

  CATEGORIES    the product's own top-level tabs - Policies, Objects, Network, Device
  CONFIG_OBJECTS  one entry per object we can show, carrying WHERE PAN-OS keeps it

An engineer auditing a firewall already knows where an object lives in the vendor's UI. Making
them learn a second organisation to find the same object here is a cost with no return, so the
rail mirrors the product: same categories, same left-hand rail, same labels, same order. When a
grouping here looks wrong, the question to ask is what PAN-OS does, not what would be tidy.

`group` is the rail heading an object sits under - `Certificate Management`, `Server Profiles`
- and "" for the rail items PAN-OS shows with no heading at all. Groups render in the order
their first object appears, so ordering is one list rather than a list plus an index.

`findings_url_name` names this object's tab under Device Configuration. That tab is a SIBLING,
not a predecessor: it presents findings, and these pages are for building a query and reading
its results - the pair `/assessments/security-rules/` already has. Both surfaces stay. The link
is on the page so a reader can cross to the other view of the same object.

`search_model` decides whether an object gets the query view or the placeholder. Six rail items
once shared `DeviceConfigurationProfile`, each offering its own section's fields, which is why
`configuration_results.RESULTS` is keyed on the rail SLUG rather than the model. Since that model
was split along the control line and deleted on 2026-09-11, every item has a model of its own.

WHAT EARNS A RAIL ITEM. Jason's rule, 2026-09-10: an object that no COMPLETED control relates to
comes out of the view, and gets its item back when a control defines it. Not a control that
exists in the corpus - one that is built and reporting. The reason is that the rail is a promise
about what can be asked here, and an item backed by an unwritten control answers nothing.

Checked when the rule was set: all fifteen items clear it, and the split above is what that check
produced rather than a layout somebody chose. The tally per item was 2, 4, 2, 2, 4, 13, 1, 3, 4,
2, 1, 2, 7, 1, 1 - and PAN-AUTH-020, the one catalog control that generates no findings, sits
on Administrators, which has three others. It is COMPLETE as an interview question rather than a
query (Jason, 2026-09-14), so it neither earns a rail item nor takes one away.

The tally cannot be asserted from here: "completed" lives in OptivEdgeProbe's controls-status.csv
and this app must not read across repos for it. Re-run the check by hand when adding an item.

Deliberately free of Django imports, the same as `navigation.py`: `app_meta` reads it during
project composition, before the app registry is ready.
"""

from __future__ import annotations

from typing import NamedTuple


class ConfigObject(NamedTuple):
    #: URL segment. Stable and explicit rather than derived from `label`, because the label is
    #: the vendor's and can be renamed to follow a PAN-OS release without breaking a link.
    slug: str
    #: The label PAN-OS itself uses, where it has one for this object.
    label: str
    category: str
    #: The rail heading this sits under, or "" for a top-level rail item.
    group: str = ""
    #: Must exist in OptivEdge's vendored icon set - templates/components/icons/. Not lucide's
    #: full catalogue; a name that is not there renders a 500.
    icon: str = "list-checks"
    #: This object's FINDINGS tab, if it has one. A different surface over the same object,
    #: not the thing this page replaces. "" means no tab presents it yet.
    findings_url_name: str = ""
    #: The search registry's label for this object's model. Set means the page is a real query
    #: view; "" means it is still the placeholder. Objects are turned on one at a time, and the
    #: gate is deliberate: a label here with no results spec behind it renders a table with no
    #: columns, which reads as "nothing matched" rather than as "not built".
    search_model: str = ""
    #: Where this lives in the PAN-OS UI, shown on the page so a reader can go and look.
    where: str = ""


#: Left to right, in the product's own order.
CATEGORIES: tuple[str, ...] = ("Policies", "Objects", "Network", "Device")


#: Top to bottom within a category, in the product's own rail order.
#:
#: Policies was empty until 2026-09-18, deliberately: security rules had a query builder and a
#: results list of their own, and a rail item pointing at a different page would have been worse
#: than an empty category. Security is here now because the explorer gained what that page had
#: and it did not - applying a whole CONTROL and showing what it would report, at what severity.
#: The standalone page stays for what it still does better: plain-language search, and a row
#: detail no result table carries. Objects holds only what a completed control reads - security
#: profiles, from 2026-09-11.
CONFIG_OBJECTS: tuple[ConfigObject, ...] = (
    # Policies > Security. PAN-OS's first category and its first rail item, which is why this
    # sits at the top: the order here is the product's, not the order things were built in.
    ConfigObject("security", "Security", "Policies", "", "shield",
                 where="Policies > Security",
                 search_model="integrations.SecurityRule"),
    # Objects > Security Profiles - the first Objects items, 2026-09-11. PAN-OS lists each profile
    # type as its own rail child, and so does this: two items over one model, split by kind in
    # configuration_results, each backed by a completed control.
    ConfigObject("anti-spyware", "Anti-Spyware", "Objects", "Security Profiles", "shield",
                 where="Objects > Security Profiles > Anti-Spyware",
                 findings_url_name="assessment_security_profile_list",
                 search_model="integrations.SecurityProfile"),
    ConfigObject("vulnerability-protection", "Vulnerability Protection", "Objects",
                 "Security Profiles", "shield",
                 where="Objects > Security Profiles > Vulnerability Protection",
                 findings_url_name="assessment_security_profile_list",
                 search_model="integrations.SecurityProfile"),
    # Device > Setup. Six of our tabs are all one PAN-OS screen with sub-tabs; they sit under
    # Setup as rail children rather than being flattened, so the address stays the vendor's.
    # `management` came OUT on 2026-09-10. Every completed control that read
    # `DeviceConfigurationProfile` has moved to a model of its own, and what is left on that
    # row - permitted-IP count, NTP, HA, hostname, time zone - is read by nothing. Jason's rule:
    # an object no completed control relates to comes out of the view, and comes back when a
    # control defines it. No rail item reads `DeviceConfigurationProfile` any more.
    ConfigObject("services", "Services", "Device", "Setup", "server",
                 where="Device > Setup > Services",
                 search_model="integrations.UpdateServerSettings"),
    ConfigObject("interfaces", "Interfaces", "Device", "Setup", "shield",
                 where="Device > Setup > Interfaces",
                 findings_url_name="assessment_management_interface_list",
                 search_model="integrations.ManagementInterface"),
    ConfigObject("login-banner", "Login Banner", "Device", "Setup", "book-marked",
                 where="Device > Setup > Management > General Settings",
                 findings_url_name="assessment_login_banner_list",
                 search_model="integrations.LoginBanner"),
    ConfigObject("management-tls", "Management TLS", "Device", "Setup", "clipboard-check",
                 where="Device > Setup > Management > SSL/TLS Service Profile",
                 findings_url_name="assessment_management_tls_list",
                 search_model="integrations.ManagementTlsBinding"),
    ConfigObject("management-ssh", "SSH Management Profiles", "Device", "Setup", "shield",
                 where="Device > Setup > Management > SSH Management Profiles",
                 findings_url_name="assessment_management_ssh_list",
                 search_model="integrations.ManagementSshSettings"),
    # NTP shares the Services screen with the update server above, and is a rail item of its own
    # because it is a different question - where time comes from, not where software does.
    ConfigObject("ntp", "NTP", "Device", "Setup", "refresh-cw",
                 where="Device > Setup > Services > NTP",
                 findings_url_name="assessment_ntp_settings_list",
                 search_model="integrations.NtpSettings"),
    # SNMP Setup is reached from Operations rather than Setup > Management, which is why `where`
    # says so: an assessor following the address needs the vendor's path, not ours.
    ConfigObject("snmp", "SNMP", "Device", "Setup", "server",
                 where="Device > Setup > Operations > SNMP Setup",
                 findings_url_name="assessment_snmp_settings_list",
                 search_model="integrations.SnmpSettings"),
    ConfigObject("system-identity", "System Identity", "Device", "Setup", "settings",
                 where="Device > Setup > Management > General Settings, and Setup > Interfaces",
                 findings_url_name="assessment_system_identity_list",
                 search_model="integrations.SystemIdentity"),
    ConfigObject("authentication-settings", "Authentication Settings", "Device", "Setup",
                 "clipboard-check", where="Device > Setup > Management > Authentication Settings",
                 findings_url_name="assessment_authentication_settings_list",
                 search_model="integrations.AuthenticationSettings"),
    ConfigObject("logging-and-reporting", "Logging and Reporting", "Device", "Setup",
                 "clipboard-check",
                 where="Device > Setup > Management > Logging and Reporting Settings",
                 search_model="integrations.LoggingSettings"),
    ConfigObject("password-complexity", "Minimum Password Complexity", "Device", "Setup", "eye",
                 where="Device > Setup > Management > Minimum Password Complexity",
                 findings_url_name="assessment_password_complexity_list",
                 search_model="integrations.PasswordComplexityPolicy"),
    # Device, top-level rail items - no heading in the product either.
    ConfigObject("password-profiles", "Password Profiles", "Device", "", "book-marked",
                 where="Device > Password Profiles",
                 findings_url_name="assessment_password_profile_list",
                 search_model="integrations.PasswordProfile"),
    ConfigObject("administrators", "Administrators", "Device", "", "shield",
                 where="Device > Administrators",
                 findings_url_name="assessment_admin_user_list",
                 search_model="integrations.AdminUser"),
    ConfigObject("authentication-profile", "Authentication Profile", "Device", "", "shield",
                 where="Device > Authentication Profile",
                 findings_url_name="assessment_authentication_profile_list",
                 search_model="integrations.AuthenticationProfile"),
    ConfigObject("authentication-sequence", "Authentication Sequence", "Device", "",
                 "list-checks", where="Device > Authentication Sequence",
                 findings_url_name="assessment_authentication_sequence_list",
                 search_model="integrations.AuthenticationSequence"),
    # Device > Certificate Management.
    ConfigObject("certificates", "Certificates", "Device", "Certificate Management",
                 "clipboard-check", where="Device > Certificate Management > Certificates",
                 findings_url_name="assessment_certificate_list",
                 search_model="integrations.Certificate"),
    ConfigObject("certificate-profile", "Certificate Profile", "Device",
                 "Certificate Management", "server",
                 where="Device > Certificate Management > Certificate Profile",
                 findings_url_name="assessment_certificate_profile_list",
                 search_model="integrations.CertificateProfile"),
    ConfigObject("ssl-tls-service-profile", "SSL/TLS Service Profile", "Device",
                 "Certificate Management", "settings",
                 where="Device > Certificate Management > SSL/TLS Service Profile",
                 findings_url_name="assessment_ssl_tls_service_profile_list",
                 search_model="integrations.SslTlsServiceProfile"),
    # Device > Server Profiles. PAN-OS lists one rail child per protocol; we hold all the
    # authentication kinds on one object today, so it is one child until that splits.
    ConfigObject("aaa-server-profiles", "AAA Server Profiles", "Device", "Server Profiles",
                 "server", where="Device > Server Profiles > LDAP / RADIUS / TACACS+ / "
                                 "Kerberos / SAML / Multi Factor Authentication",
                 findings_url_name="assessment_server_profile_list",
                 search_model="integrations.ServerProfile"),
    # Device > Master Key and Diagnostics.
    ConfigObject("master-key", "Master Key", "Device", "", "refresh-cw",
                 where="Device > Master Key and Diagnostics",
                 findings_url_name="assessment_master_key_list",
                 search_model="integrations.MasterKey"),
    # Network > Network Profiles.
    ConfigObject("interface-mgmt", "Interface Mgmt", "Network", "Network Profiles",
                 "list-checks", where="Network > Network Profiles > Interface Mgmt",
                 findings_url_name="assessment_interface_management_profile_list",
                 search_model="integrations.InterfaceManagementProfile"),
)

CONFIG_OBJECTS_BY_KEY = {(o.category, o.slug): o for o in CONFIG_OBJECTS}


def category_slug(category: str) -> str:
    return category.lower()


CATEGORY_BY_SLUG = {category_slug(c): c for c in CATEGORIES}


def objects_in(category: str) -> tuple[ConfigObject, ...]:
    return tuple(o for o in CONFIG_OBJECTS if o.category == category)


def objects_for_model(model_label: str) -> tuple[ConfigObject, ...]:
    """Every rail item that queries this model. USUALLY one, never guaranteed to be.

    Anti-spyware and vulnerability protection are two rail items over `SecurityProfile`, because
    that is how PAN-OS lists them, so "the page for this model" is a question with two answers
    and the caller has to choose. `configuration_results.object_for_canonical_query` does the
    choosing, using the `scope` query that splits them - which lives there, not here, because
    this module must not reach a model.
    """
    return tuple(o for o in CONFIG_OBJECTS if o.search_model == model_label)


def groups_in(category: str) -> list[tuple[str, list[ConfigObject]]]:
    """The rail for one category: (heading, objects), headings in first-appearance order.

    A list of pairs rather than a dict keyed on heading, because "" is a real heading here -
    the items PAN-OS shows with no grouping - and it can appear between two named groups.
    """
    rail: list[tuple[str, list[ConfigObject]]] = []
    for obj in objects_in(category):
        if not rail or rail[-1][0] != obj.group:
            rail.append((obj.group, []))
        rail[-1][1].append(obj)
    return rail


def first_object(category: str) -> ConfigObject | None:
    found = objects_in(category)
    return found[0] if found else None


# There is no landing object any more. `/assessments/configuration/` was a redirect into the
# rail until 2026-09-18 and is now a page of its own, so `LANDING_CATEGORY` and `landing()` were
# deleted rather than left with no caller. What they encoded is worth keeping in words: category
# order here is the PRODUCT's, and a default must never be derived by taking "the first category
# that has anything in it" - that put the entry point on Network while Policies and Objects were
# empty, which is the rail describing our build order rather than the vendor's organisation.
