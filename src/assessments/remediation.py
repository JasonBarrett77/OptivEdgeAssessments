"""The findings of one security-rule control, folded to ONE ROW PER RULE DEFINITION.

WHAT A ROW IS. Where a rule is defined - the management plane and the container within it - plus
its name. The findings tabs draw one row per rule OBJECT, so a Panorama-shared rule pushed to
seven virtual systems is seven rows; this draws one row per DEFINITION, which is the thing an
engineer edits. Jason, 2026-11-03: *"For 'rule a', defined in a device group, the page should show
the rule values, and the count of the number of times that rule is used across all devices."*

WHY THE CELLS COME FROM THE RULES SHEET. The same object should not be described two ways, so
every value column reads through `artifacts.sheets.security_rules`' own readers. What differs
between the two surfaces is the KEY and the counting, not the vocabulary.

WHAT IS FOLDED AND WHAT IS NOT. Rows fold; findings never do. `Findings` on a row is the number
of findings the definition carries, and the sum over a page equals the control's finding count -
asserted in `fold_is_complete`, because a fold that loses a finding is the one failure this shape
can have and it would be invisible.

THE GRAIN IS A DEFINITION, NOT A PLACE. A Panorama-shared rule is one row with seven enforcement
points listed, not seven rows. The count beside it is what one edit costs and what it buys.
"""

from __future__ import annotations

import collections
import re

from dataclasses import dataclass

from django.contrib.contenttypes.models import ContentType
from django.db.models import Count

from assessments.control_queries import SEVERITY_RANK
from assessments import finding_registry
from assessments.models import Control

from optivedge_integrations.integrations.models.provenance import FieldProvenance

from assessments.artifacts import domains as artifact_domains
from assessments.artifacts.layout import category_of
from assessments.artifacts.sheets.findings import (as_column, provenance_index,
                                                    selected_controls, setting_columns)
from assessments import configuration_navigation as config_nav

#: COVERAGE IS LEFT OUT ON PURPOSE. `AddressObject` is a device-group subject and its only
#: findings are PAN-COV-001's, and Jason's standing ruling of 2026-10-02 is that the coverage
#: controls get a separate place: "I don't want them to disturb the highly structured, object
#: related findings." Four findings, and including them would put a control about OUR OWN
#: collection beside controls about the customer's configuration.
#:
#: NOT THE FINDINGS TABS' OWN SPLIT either: the five rule tabs divide the rule controls between
#: them and a reader asking "what do I change" does not care which tab a control draws on.

@dataclass(frozen=True)
class RemediationGroup:
    """Several controls over ONE OBJECT KIND, on one page.

    WHY A GROUP EXISTS. PAN-AVW-001 and PAN-AVW-002 draw the same profiles with the same five
    columns and differ only in which column is at fault - 001 reads four axes of the malware
    verdict, 002 the inline ML one - and PAN-AVW-006 asks a third question about the same object.
    Measured on the lab: three pages, 44 rows, and the TEN absence rows are identical on 001 and
    002, same boxes and same containers, so an engineer reads "attach an antivirus profile to
    these rules" twice and has no way to tell it is one job. Folded: 30 rows, one page, no
    finding lost.
    """

    slug: str
    label: str
    #: In catalogue order, which is the order the settings are listed in on a row.
    control_ids: tuple
    #: WHOSE OBJECT IT IS, which is not the controls' own `control_type`. PAN-AVW-001 is a
    #: `security_rule` control that reports on a PROFILE, so sectioning the index by control type
    #: files this page under the rulebase. The group states the object instead.
    subject_type: str
    summary: str
    #: WHICH PAN-OS CATEGORY the index files this page under - Policies, Objects, Network or
    #: Device. Left empty it is DERIVED from the subject model's place on the configuration
    #: rail, the way a findings tab derives its own (`views.findings_domain_category`), so the
    #: two surfaces cannot disagree about where an object lives. Named only for a subject the
    #: rail does not carry.
    category: str = ""
    #: `object` - a definition someone edits - or `posture`, where the subject is a VIRTUAL
    #: SYSTEM's rulebase and the finding is that no rule exists. A posture row has no object to
    #: name and no container to open: it is identified by the firewall and the virtual system,
    #: and the page lays the controls out as columns rather than as lines.
    shape: str = "object"
    #: Value columns this page does not draw, by heading. The prune drops a column that is
    #: both unmarked and uniform; this drops one that survives that test and still earns
    #: nothing - `Vendor-shipped` on the antivirus page is `Yes` on the single row whose
    #: `Edit on` already reads `PAN-OS (predefined)`.
    hide_columns: tuple = ()
    #: Build this page's rows in ONE PASS over its findings - `fold_group_rows` - rather than
    #: per control and merged. It was off by default while the two paths were compared page by
    #: page: the fast one is measurably identical on the group that declares it, and declaring
    #: that is how the claim got made deliberately rather than by a refactor nobody checked.
    #:
    #: EVERY GROUP DECLARES IT AS OF 2026-11-05. The last nine were compared together - both
    #: paths run, every row's stored form compared - and all nine agree exactly:
    #:
    #:     url-filtering-profile             0.40s -> 0.11s    30 rows
    #:     anti-spyware-profile              5.54s -> 1.41s    37 rows
    #:     vulnerability-protection-profile  1.76s -> 1.04s    19 rows
    #:     decryption-profile                0.21s -> 0.05s    22 rows
    #:     file-blocking-profile             0.04s -> 0.03s    27 rows
    #:     dos-protection-profile            0.01s -> 0.01s     2 rows
    #:     decryption-rule                   0.10s -> 0.02s    15 rows
    #:     security-rule                     5.09s -> 3.23s  1083 rows
    #:     custom-url-category               0.05s -> 0.03s    25 rows
    #:
    #: 13.2s to 5.9s over the nine, which is what Run Findings pays to prime them.
    #:
    #: THE DEFAULT STAYS FALSE. A group added tomorrow has not been compared, and inheriting
    #: the claim would be exactly the refactor-nobody-checked this flag exists to prevent.
    one_pass: bool = False


def group_category(group: "RemediationGroup") -> str:
    """The PAN-OS category this group's page belongs to.

    Derived rather than declared, for the reason `artifacts.layout.category_of` gives: the rail
    is the app's statement of where an object lives, and a surface that repeated the answer
    would eventually contradict it. Note it is read off the SUBJECT model and not the finding
    model - PAN-AVW-001 is a `security_rule` control reporting on a profile, and its page is
    about the profile.
    """
    if group.category:
        return group.category
    kind = _kind_for(group.subject_type)
    return category_of(kind.model._meta.get_field(kind.subject_field).related_model)


REMEDIATION_GROUPS = (
    RemediationGroup(
        slug="antivirus-profile",
        label="Antivirus profile",
        hide_columns=("Vendor-shipped",),
        one_pass=True,
        control_ids=("PAN-AVW-001", "PAN-AVW-002", "PAN-AVW-006"),
        subject_type=Control.ControlType.SECURITY_PROFILE,
        summary=("Every finding against an antivirus profile - none attached, decoders not "
                 "blocking, inline ML not blocking, or the profile unused - on one row per "
                 "profile."),
    ),
    RemediationGroup(
        slug="url-filtering-profile",
        label="URL filtering profile",
        control_ids=("PAN-URL-001", "PAN-URL-002", "PAN-URL-003", "PAN-URL-004",
                     "PAN-URL-005"),
        one_pass=True,
        subject_type=Control.ControlType.SECURITY_PROFILE,
        summary=("Every finding against a URL filtering profile - categories not blocked, "
                 "categories reachable without logging, credential submission, HTTP header "
                 "logging and inline categorization - on one row per profile."),
    ),
    RemediationGroup(
        slug="anti-spyware-profile",
        label="Anti-spyware profile",
        control_ids=("PAN-SPY-001", "PAN-SPY-002", "PAN-SPY-003", "PAN-SPY-004",
                     "PAN-SPY-005"),
        one_pass=True,
        subject_type=Control.ControlType.SECURITY_PROFILE,
        summary=("Every finding against an anti-spyware profile - none attached, severities "
                 "not blocked, DNS sinkhole, DNS security categories, inline cloud analysis "
                 "and threat exceptions - on one row per profile."),
    ),
    RemediationGroup(
        slug="vulnerability-protection-profile",
        label="Vulnerability protection profile",
        control_ids=("PAN-VLN-001", "PAN-VLN-002", "PAN-VLN-003", "PAN-VLN-004"),
        one_pass=True,
        subject_type=Control.ControlType.SECURITY_PROFILE,
        summary=("Every finding against a vulnerability protection profile - none attached, "
                 "severities not blocked, brute-force signatures, inline cloud analysis and "
                 "exceptions - on one row per profile."),
    ),
    RemediationGroup(
        slug="decryption-profile",
        label="Decryption profile",
        control_ids=("PAN-DCP-001", "PAN-DCP-002", "PAN-DCP-003", "PAN-DCP-004",
                     "PAN-DCP-005", "PAN-DCP-007"),
        one_pass=True,
        subject_type=Control.ControlType.SECURITY_PROFILE,
        summary=("Every finding against a decryption profile - protocol versions, negotiable "
                 "primitives, what it does with an expired or untrusted certificate, what it "
                 "does when it cannot inspect, and whether anything uses it - on one row per "
                 "profile."),
    ),
    RemediationGroup(
        slug="file-blocking-profile",
        label="File blocking profile",
        control_ids=("PAN-FIL-001", "PAN-FIL-002", "PAN-FIL-004"),
        one_pass=True,
        subject_type=Control.ControlType.SECURITY_PROFILE,
        summary=("Every finding against a file-blocking or data-filtering profile - dangerous "
                 "file types logged rather than blocked, nested encodings and unopenable "
                 "archives undecided, and profiles nothing references - on one row per "
                 "profile."),
    ),
    RemediationGroup(
        slug="dos-protection-profile",
        label="DoS protection profile",
        control_ids=("PAN-ZON-008",),
        one_pass=True,
        subject_type=Control.ControlType.SECURITY_PROFILE,
        summary="DoS protection profiles nothing references, on one row per profile.",
    ),
    RemediationGroup(
        slug="decryption-rule",
        label="Decryption rule",
        control_ids=("PAN-DEC-002", "PAN-DEC-003", "PAN-DEC-005", "PAN-DEC-006",
                     "PAN-DEC-007", "PAN-DEC-008", "PAN-DEC-010"),
        one_pass=True,
        subject_type=Control.ControlType.DECRYPTION_POLICY_RULE,
        summary=("Every finding against a decryption rule - how the rulebase is structured, "
                 "what each exception exempts, what a no-decrypt rule still enforces and "
                 "whether it is logged - on one row per rule definition."),
    ),
    RemediationGroup(
        slug="security-rule",
        label="Security rule",
        control_ids=("PAN-AVW-003", "PAN-POL-002", "PAN-POL-003", "PAN-POL-004",
                     "PAN-POL-005", "PAN-POL-006", "PAN-POL-008", "PAN-POL-009",
                     "PAN-POL-012", "PAN-POL-013", "PAN-POL-014", "PAN-POL-015",
                     "PAN-POL-020", "PAN-POL-021", "PAN-POL-022", "PAN-POL-024"),
        one_pass=True,
        subject_type=Control.ControlType.SECURITY_RULE,
        summary=("Every finding against a security rule - what it matches, what it allows, "
                 "what inspects it and whether it is logged - on one row per rule "
                 "definition."),
    ),
    # THE FIRST NETWORK PAGE. Three controls asking three different questions of one zone -
    # what protects it, whether it identifies devices, whether it identifies users - and a zone
    # is squarely a thing an engineer opens and edits. Measured on the lab: 73 findings over 42
    # zones, and every column the page draws is labelled by the zones sheet itself.
    RemediationGroup(
        slug="zone",
        label="Zone",
        one_pass=True,
        control_ids=("PAN-IOT-002", "PAN-UID-001", "PAN-ZON-001"),
        subject_type=Control.ControlType.ZONE,
        summary=("Every finding against a security zone - no zone protection profile resolved, "
                 "device identification off where IoT is hosted, or user identification on "
                 "where the zone is not trusted - on one row per zone."),
    ),
    # NETWORK AND DEVICE, built to the shape the zone page set - see
    # `scratch/remediation-network-device-build-guide-2026-11-04.md` in OptivEdgeProbe. Each of
    # these is several controls over ONE object an engineer opens and edits, and each declares
    # `one_pass` because none of them substitutes a profile for its finding's own subject.
    RemediationGroup(
        slug="interface",
        label="Interface",
        control_ids=("PAN-NET-001", "PAN-NET-003"),
        subject_type=Control.ControlType.FIREWALL_INTERFACE,
        one_pass=True,
        summary=("Every finding against a firewall interface - residue left on an "
                 "out-of-service port, and link-layer discovery announcing the estate - on one "
                 "row per interface."),
    ),
    RemediationGroup(
        slug="aaa-server-profile",
        label="AAA server profile",
        control_ids=("PAN-AAA-001", "PAN-AAA-002", "PAN-AAA-004", "PAN-AAA-006",
                     "PAN-AAA-008", "PAN-AAA-009", "PAN-AAA-013"),
        subject_type=Control.ControlType.SERVER_PROFILE,
        one_pass=True,
        summary=("Every finding against an LDAP, RADIUS, TACACS+ or SAML server profile - "
                 "transport, certificate validation, protocol strength and the ones nothing "
                 "references - on one row per profile."),
    ),
    RemediationGroup(
        slug="authentication-profile",
        label="Authentication profile",
        control_ids=("PAN-AAA-010", "PAN-AUTH-018", "PAN-AUTH-025"),
        subject_type=Control.ControlType.AUTHENTICATION_PROFILE,
        one_pass=True,
        summary=("Every finding against an authentication profile - allow list breadth, "
                 "failed-attempt lockout, and the ones nothing references - on one row per "
                 "profile."),
    ),
    RemediationGroup(
        slug="administrator",
        label="Administrator",
        control_ids=("PAN-AUTH-019", "PAN-AUTH-021", "PAN-AUTH-022"),
        subject_type=Control.ControlType.ADMIN_USER,
        one_pass=True,
        summary=("Every finding against an administrator account - local rather than external "
                 "authentication, the factory `admin`, and superuser breadth - on one row per "
                 "account."),
    ),
    RemediationGroup(
        slug="management-interface",
        label="Management interface",
        control_ids=("PAN-MGT-001", "PAN-MGT-002", "PAN-MGT-003", "PAN-MGT-006",
                     "PAN-UID-005"),
        subject_type=Control.ControlType.MANAGEMENT_INTERFACE,
        one_pass=True,
        summary=("Every finding against the management surface - telnet and HTTP still "
                 "offered, access not restricted to permitted addresses, administrative "
                 "services on data-plane interfaces, and unauthenticated syslog user mapping - "
                 "on one row per appliance."),
    ),
    RemediationGroup(
        slug="interface-management-profile",
        label="Interface management profile",
        control_ids=("PAN-MGT-013",),
        subject_type=Control.ControlType.INTERFACE_MANAGEMENT_PROFILE,
        one_pass=True,
        summary=("Interface management profiles nothing is bound to, on one row per profile - "
                 "each one an administrative surface waiting to be attached by mistake."),
    ),
    RemediationGroup(
        slug="globalprotect-portal",
        label="GlobalProtect portal",
        control_ids=("PAN-GPP-003", "PAN-GPP-004", "PAN-GPP-005"),
        subject_type=Control.ControlType.GLOBALPROTECT_PORTAL,
        one_pass=True,
        summary=("Every finding against a GlobalProtect portal - agents not driven to a "
                 "current version, saved user credentials, and a web login page nothing "
                 "needs - on one row per portal."),
    ),
    # AN APPLIANCE SINGLETON, and the first page whose rows split by where the FAILING VALUES
    # live rather than by an object: twelve controls over one `deviceconfig/system` subtree that
    # PAN-OS merges leaf by leaf from a template and the device's own config. See
    # `_field_placement`.
    RemediationGroup(
        slug="password-complexity",
        label="Password complexity",
        control_ids=("PAN-AUTH-002", "PAN-AUTH-003", "PAN-AUTH-004", "PAN-AUTH-005",
                     "PAN-AUTH-006", "PAN-AUTH-007", "PAN-AUTH-008", "PAN-AUTH-009",
                     "PAN-AUTH-010", "PAN-AUTH-011", "PAN-AUTH-012", "PAN-AUTH-013"),
        subject_type=Control.ControlType.PASSWORD_COMPLEXITY,
        one_pass=True,
        summary=("Every finding against the firewall-wide password policy - length, character "
                 "classes, reuse, expiry and what happens after it - on one row per place the "
                 "failing settings are authored."),
    ),
    RemediationGroup(
        slug="globalprotect-portal-authentication",
        label="Portal authentication",
        control_ids=("PAN-GPP-002",),
        subject_type=Control.ControlType.GLOBALPROTECT_PORTAL_CLIENT_AUTH,
        one_pass=True,
        summary=("Portal authentication rows that admit a user on a password alone, on one row "
                 "per configuration."),
    ),
    RemediationGroup(
        slug="logging-and-reporting",
        label="Logging and reporting",
        control_ids=("PAN-LOG-001", "PAN-LOG-003", "PAN-LOG-004", "PAN-LOG-006",
                     "PAN-LOG-007", "PAN-LOG-008", "PAN-LOG-009", "PAN-LOG-010",
                     "PAN-MGT-011"),
        subject_type=Control.ControlType.LOGGING_SETTINGS,
        one_pass=True,
        summary=("Every finding against the firewall's logging and reporting settings - what "
                 "is forwarded off the box, to where, what is kept and what raises an alarm - "
                 "on one row per place those settings are authored."),
    ),
    RemediationGroup(
        slug="management-ssh",
        label="SSH management",
        control_ids=("PAN-MCR-001", "PAN-MCR-002", "PAN-MCR-003", "PAN-MCR-004",
                     "PAN-MCR-005"),
        subject_type=Control.ControlType.MANAGEMENT_SSH,
        one_pass=True,
        summary=("Every finding against the management SSH service - ciphers, key exchange, "
                 "MACs, host key strength and rekeying - on one row per place those settings "
                 "are authored."),
    ),
    RemediationGroup(
        slug="ssl-tls-service-profile",
        label="SSL/TLS service profile",
        control_ids=("PAN-CRT-005", "PAN-CRT-009"),
        subject_type=Control.ControlType.SSL_TLS_SERVICE_PROFILE,
        one_pass=True,
        summary=("Every finding against an SSL/TLS service profile - the protocol floor and "
                 "the algorithms it still negotiates - on one row per profile."),
    ),
    RemediationGroup(
        slug="authentication-settings",
        label="Authentication settings",
        control_ids=("PAN-AUTH-014", "PAN-AUTH-015", "PAN-AUTH-016", "PAN-AUTH-017"),
        subject_type=Control.ControlType.AUTHENTICATION_SETTINGS,
        one_pass=True,
        summary=("Every finding against the firewall-wide administrator authentication "
                 "settings - lockout, idle timeout and API key lifetime - on one row per place "
                 "those settings are authored."),
    ),
    RemediationGroup(
        slug="content-update-schedule",
        label="Dynamic update schedule",
        control_ids=("PAN-UPD-001", "PAN-UPD-002", "PAN-UPD-004", "PAN-UPD-005"),
        subject_type=Control.ControlType.CONTENT_UPDATE_SCHEDULE,
        one_pass=True,
        summary=("Every finding against the dynamic update schedules - antivirus, "
                 "applications and threats, WildFire and GlobalProtect - on one row per place "
                 "the schedules are authored."),
    ),
    RemediationGroup(
        slug="globalprotect-coverage",
        label="GlobalProtect coverage",
        control_ids=("PAN-GPG-005", "PAN-GPP-006"),
        subject_type=Control.ControlType.GLOBALPROTECT_ENFORCEMENT_POINT,
        one_pass=True,
        summary=("Every finding against GlobalProtect's reach - host posture not deciding what an endpoint may do, and clientless VPN offered without a documented need - on one row per place it is deployed."),
    ),
    RemediationGroup(
        slug="virtual-router",
        label="Virtual router",
        control_ids=("PAN-NET-007",),
        subject_type=Control.ControlType.ROUTING_ADJACENCY,
        one_pass=True,
        summary=("Dynamic routing adjacencies that accept a neighbour without authentication, on one row per adjacency."),
    ),
    RemediationGroup(
        slug="dhcp-interface",
        label="DHCP interface",
        control_ids=("PAN-NET-004",),
        subject_type=Control.ControlType.DHCP_INTERFACE_CONFIG,
        one_pass=True,
        summary=("Interfaces offering DHCP on an untrusted-facing segment, on one row per interface."),
    ),
    RemediationGroup(
        slug="service-route",
        label="Service route",
        control_ids=("PAN-SVC-006",),
        subject_type=Control.ControlType.SERVICE_ROUTE,
        one_pass=True,
        summary=("Management services leaving by an unpinned route, on one row per service."),
    ),
    RemediationGroup(
        slug="certificate",
        label="Certificate",
        control_ids=("PAN-CRT-001", "PAN-CRT-002", "PAN-CRT-003"),
        subject_type=Control.ControlType.CERTIFICATE,
        one_pass=True,
        summary=("Every finding against a certificate the firewall holds - expired, too short a key, or signed with a weak algorithm - on one row per certificate."),
    ),
    RemediationGroup(
        slug="certificate-profile",
        label="Certificate profile",
        control_ids=("PAN-CRT-004",),
        subject_type=Control.ControlType.CERTIFICATE_PROFILE,
        one_pass=True,
        summary=("Certificate profiles that do not check revocation, on one row per profile."),
    ),
    RemediationGroup(
        slug="ssl-decryption-exclusion",
        label="SSL decryption exclusion",
        control_ids=("PAN-DEC-004",),
        subject_type=Control.ControlType.SSL_DECRYPTION_EXCLUSION,
        one_pass=True,
        summary=("Compatibility exclusions that are not tracked against the vendor's own list, on one row per exclusion."),
    ),
    RemediationGroup(
        slug="password-profile",
        label="Password profile",
        control_ids=("PAN-AUTH-026",),
        subject_type=Control.ControlType.PASSWORD_PROFILE,
        one_pass=True,
        summary=("Password profiles that weaken the firewall-wide policy for the accounts bound to them, on one row per profile."),
    ),
    RemediationGroup(
        slug="authentication-sequence",
        label="Authentication sequence",
        control_ids=("PAN-AAA-012",),
        subject_type=Control.ControlType.AUTHENTICATION_SEQUENCE,
        one_pass=True,
        summary=("Authentication sequences whose fallback order admits a weaker method, on one row per sequence."),
    ),
    RemediationGroup(
        slug="login-banner",
        label="Login banner",
        control_ids=("PAN-MGT-007", "PAN-MGT-008"),
        subject_type=Control.ControlType.LOGIN_BANNER,
        one_pass=True,
        summary=("Login banners missing or not acknowledged, on one row per place the setting is authored."),
    ),
    RemediationGroup(
        slug="management-tls",
        label="Management TLS",
        control_ids=("PAN-CRT-006", "PAN-MGT-010"),
        subject_type=Control.ControlType.MANAGEMENT_TLS,
        one_pass=True,
        summary=("The TLS the management interface presents - its certificate's issuer and its protocol floor - on one row per place those settings are authored."),
    ),
    RemediationGroup(
        slug="ntp",
        label="NTP",
        control_ids=("PAN-SVC-001", "PAN-SVC-002"),
        subject_type=Control.ControlType.NTP_SETTINGS,
        one_pass=True,
        summary=("Time sources without redundancy or authentication, on one row per place the setting is authored."),
    ),
    RemediationGroup(
        slug="dns",
        label="DNS",
        control_ids=("PAN-SVC-003",),
        subject_type=Control.ControlType.DNS_SETTINGS,
        one_pass=True,
        summary=("Management DNS resolvers left unset, on one row per place the setting is authored."),
    ),
    RemediationGroup(
        slug="snmp",
        label="SNMP",
        control_ids=("PAN-SVC-004", "PAN-SVC-005"),
        subject_type=Control.ControlType.SNMP_SETTINGS,
        one_pass=True,
        summary=("SNMP answering on an unauthenticated version or with a default community string, on one row per place the setting is authored."),
    ),
    RemediationGroup(
        slug="system-identity",
        label="System identity",
        control_ids=("PAN-SVC-007", "PAN-SVC-009", "PAN-SVC-010"),
        subject_type=Control.ControlType.SYSTEM_IDENTITY,
        one_pass=True,
        summary=("The firewall's own identity - hostname, timezone and management addressing - on one row per place those settings are authored."),
    ),
    RemediationGroup(
        slug="master-key",
        label="Master key",
        control_ids=("PAN-CRT-007",),
        subject_type=Control.ControlType.MASTER_KEY,
        one_pass=True,
        summary=("Appliances still encrypting their stored secrets with the factory master key, on one row per appliance."),
    ),
    RemediationGroup(
        slug="session-settings",
        label="Session settings",
        control_ids=("PAN-NET-002", "PAN-NET-005"),
        subject_type=Control.ControlType.SESSION_SETTINGS,
        one_pass=True,
        summary=("Session handling that leaves running sessions un-reevaluated or IPv6 uninspected, on one row per place those settings are authored."),
    ),
    RemediationGroup(
        slug="wildfire-settings",
        label="WildFire settings",
        control_ids=("PAN-AVW-004", "PAN-AVW-005"),
        subject_type=Control.ControlType.WILDFIRE_SETTINGS,
        one_pass=True,
        summary=("WildFire submission limits and session information sharing, on one row per place those settings are authored."),
    ),
    RemediationGroup(
        slug="iot-security",
        label="IoT security",
        control_ids=("PAN-IOT-001", "PAN-IOT-003"),
        subject_type=Control.ControlType.DEVICE_IDENTIFICATION,
        one_pass=True,
        summary=("IoT Security subscription and device dictionary currency, on one row per appliance."),
    ),
    RemediationGroup(
        slug="installed-content",
        label="Installed content",
        control_ids=("PAN-PLT-002",),
        subject_type=Control.ControlType.FIREWALL_CONTENT_STREAMS,
        one_pass=True,
        summary=("Appliances enforcing with content too old to recognize current threats, on one row per appliance."),
    ),
    RemediationGroup(
        slug="licenses",
        label="Licenses",
        control_ids=("PAN-PLT-004",),
        subject_type=Control.ControlType.LICENCE_INVENTORY,
        one_pass=True,
        summary=("Subscriptions and support entitlements that are not active, on one row per appliance."),
    ),
    RemediationGroup(
        slug="alarm-settings",
        label="Alarm settings",
        control_ids=("PAN-PLT-006",),
        subject_type=Control.ControlType.LOG_ALARM_SETTINGS,
        one_pass=True,
        summary=("A filling log database that raises no alarm anybody receives, on one row per appliance."),
    ),
    RemediationGroup(
        slug="log-server-target",
        label="Syslog and email destinations",
        control_ids=("PAN-LOG-002",),
        subject_type=Control.ControlType.LOG_SERVER_TARGET,
        one_pass=True,
        summary=("Syslog destinations receiving logs without TLS, on one row per destination."),
    ),
    RemediationGroup(
        slug="forward-proxy-signing",
        label="Forward proxy signing",
        control_ids=("PAN-DCP-006",),
        subject_type=Control.ControlType.DECRYPTION_SETTINGS,
        one_pass=True,
        summary=("The certificate authority the firewall signs forward-proxy sessions with, on one row per appliance."),
    ),
    RemediationGroup(
        slug="management-plane-addressing",
        label="Management plane addressing",
        control_ids=("PAN-MGT-004",),
        subject_type=Control.ControlType.MANAGEMENT_PLANE_ADDRESSING,
        one_pass=True,
        summary=("Management plane addressing and routing that exposes the control plane, on one row per appliance."),
    ),
    RemediationGroup(
        slug="operational-mode",
        label="Operational mode",
        control_ids=("PAN-MGT-012",),
        subject_type=Control.ControlType.APPLIANCE_OPERATIONAL_MODE,
        one_pass=True,
        summary=("Appliances not running the approved cryptographic mode, on one row per appliance."),
    ),
    RemediationGroup(
        slug="user-id-agent",
        label="User-ID agent setup",
        control_ids=("PAN-UID-003", "PAN-UID-004", "PAN-UID-006"),
        subject_type=Control.ControlType.USER_ID_COLLECTOR,
        one_pass=True,
        summary=("How user mappings are collected - client probing, the service account's privilege and the mapping timeout - on one row per collector."),
    ),
    RemediationGroup(
        slug="user-id-discovery",
        label="User mapping discovery",
        control_ids=("PAN-UID-002",),
        subject_type=Control.ControlType.USER_ID_DISCOVERY_BOUND,
        one_pass=True,
        summary=("User-ID discovery reaching networks it was never scoped to, on one row per boundary."),
    ),
    RemediationGroup(
        slug="update-server",
        label="Update server",
        control_ids=("PAN-MGT-009",),
        subject_type=Control.ControlType.UPDATE_SERVER,
        one_pass=True,
        summary=("Appliances not verifying the update server's identity, on one row per appliance."),
    ),
    RemediationGroup(
        slug="high-availability",
        label="High availability",
        control_ids=("PAN-HAP-001", "PAN-HAP-002", "PAN-HAP-003", "PAN-HAP-004"),
        subject_type=Control.ControlType.HIGH_AVAILABILITY,
        one_pass=True,
        summary=("Every finding against a firewall's high-availability configuration - no live "
                 "peer, an unencrypted control link, no second keepalive path, and monitoring "
                 "that watches nothing - on one row per place those settings are authored."),
    ),
    RemediationGroup(
        slug="panorama-settings",
        label="Panorama settings",
        control_ids=("PAN-HAP-005",),
        subject_type=Control.ControlType.PANORAMA_REGISTRATION,
        one_pass=True,
        summary=("Management channels to Panorama that are neither hardened nor redundant, on "
                 "one row per appliance."),
    ),
    # THE POSTURE PAGES. The subject is a virtual system's rulebase and the finding is that no
    # rule exists, so there is no definition to edit and no object to name - see
    # `scratch/remediation-policies-objects-build-guide-2026-11-04.md`. They lay their controls
    # out as columns against one row per virtual system.
    RemediationGroup(
        slug="rulebase-posture",
        label="Security rulebase posture",
        control_ids=("PAN-POL-007", "PAN-POL-010", "PAN-POL-017", "PAN-POL-018", "PAN-POL-019"),
        subject_type=Control.ControlType.VSYS_RULE_POSTURE,
        shape="posture",
        one_pass=True,
        summary=("What a virtual system's security rulebase does not have - no explicit application block, no logged catch-all deny, no EDL, geography or port blocking - on one row per virtual system."),
    ),
    RemediationGroup(
        slug="decryption-coverage",
        label="Decryption coverage",
        control_ids=("PAN-DEC-001", "PAN-DEC-009"),
        subject_type=Control.ControlType.DECRYPTION_RULEBASE_COVERAGE,
        shape="posture",
        one_pass=True,
        summary=("Virtual systems whose decryption rulebase inspects neither outbound sessions nor published services, on one row per virtual system."),
    ),
    RemediationGroup(
        slug="saas-url-filtering",
        label="SaaS URL filtering",
        control_ids=("PAN-SAS-002", "PAN-SAS-004"),
        subject_type=Control.ControlType.SAAS_URL_FILTERING_POSTURE,
        shape="posture",
        one_pass=True,
        summary=("Virtual systems where tenant restrictions are not inserted and unsanctioned SaaS is not restricted by category, on one row per virtual system."),
    ),
    RemediationGroup(
        slug="saas-application-policy",
        label="SaaS application policy",
        control_ids=("PAN-SAS-003",),
        subject_type=Control.ControlType.SAAS_APPLICATION_POLICY_POSTURE,
        shape="posture",
        one_pass=True,
        summary=("Virtual systems whose policy does not control SaaS upload, download and sharing functions, on one row per virtual system."),
    ),
    RemediationGroup(
        slug="sanctioned-applications",
        label="Sanctioned applications",
        control_ids=("PAN-SAS-001",),
        subject_type=Control.ControlType.SANCTIONED_APPLICATION_MARKING,
        shape="posture",
        one_pass=True,
        summary=("Virtual systems where no application is tagged sanctioned, on one row per virtual system."),
    ),
    RemediationGroup(
        slug="device-id-policy",
        label="Device-ID policy match",
        control_ids=("PAN-IOT-004",),
        subject_type=Control.ControlType.RULEBASE_DEVICE_MATCH,
        shape="posture",
        one_pass=True,
        summary=("Virtual systems whose rules never match on a device, on one row per virtual system."),
    ),
    RemediationGroup(
        slug="data-filtering-posture",
        label="Data filtering posture",
        control_ids=("PAN-FIL-003",),
        subject_type=Control.ControlType.DATA_FILTERING_POSTURE,
        shape="posture",
        one_pass=True,
        summary=("Virtual systems with no outward data filtering in force, on one row per virtual system."),
    ),
    RemediationGroup(
        slug="tunnel-inspection",
        label="Tunnel inspection",
        control_ids=("PAN-NET-006",),
        subject_type=Control.ControlType.TUNNEL_INSPECTION,
        shape="posture",
        one_pass=True,
        summary=("Virtual systems where tunnelled traffic passes uninspected, on one row per virtual system."),
    ),
    RemediationGroup(
        slug="vsys-log-forwarding",
        label="Log forwarding",
        control_ids=("PAN-LOG-005",),
        subject_type=Control.ControlType.VSYS_LOG_FORWARDING,
        shape="posture",
        one_pass=True,
        summary=("Virtual systems with log types no profile sends off-box, on one row per virtual system."),
    ),
    RemediationGroup(
        slug="custom-url-category",
        label="Custom URL category",
        control_ids=("PAN-URL-006",),
        one_pass=True,
        subject_type=Control.ControlType.CUSTOM_URL_CATEGORY,
        summary="Custom URL categories nothing references, on one row per category.",
    ),
    # SITE-TO-SITE VPN, 2026-11-04. FOUR pages over four objects, because the remedy for each is
    # a different screen: the tunnel, the gateway, and the two proposal sets under Network
    # Profiles. An engineer fixes one of the four, never a mixture.
    #
    # THE NINE STRENGTH CONTROLS ARE NOT ON ANY OF THESE FOUR. PAN-IKE-002 to -005 and
    # PAN-IPS-001 to -005 are keyed on the IPSec tunnel PATH, so their finding is per tunnel
    # while their remedy is the one profile every one of those tunnels runs on - the place and
    # the subject are different objects by design. Jason, 2026-11-04: *"One row stops being one
    # place. Again, we are working on the Finding page first, the remediation pages are later and
    # will take a different shape."* They fold onto the two profile pages below through the
    # SUBSTITUTION path, the same mechanism the profile-on-rule eleven use.
    #
    # EVERY ONE OF THESE FOUR HAS ZERO FINDINGS ON THIS LAB TODAY. The five normalizers that fill
    # the four collections were wired into the collection flow on 2026-11-04 and the estate has
    # not been renormalized since, so these pages are declared and NOT verified against data.
    RemediationGroup(
        slug="ipsec-tunnel",
        label="IPSec tunnel",
        one_pass=True,
        control_ids=("PAN-IPS-006", "PAN-IPS-007", "PAN-IPS-008"),
        subject_type=Control.ControlType.IPSEC_TUNNEL,
        summary=("Every finding against an IPSec tunnel itself - replay protection off or never "
                 "read, far-end monitoring off or never read, and a tunnel left switched off - "
                 "on one row per tunnel."),
    ),
    RemediationGroup(
        slug="ike-gateway",
        label="IKE gateway",
        one_pass=True,
        control_ids=("PAN-IKE-001", "PAN-IKE-006", "PAN-IKE-007", "PAN-IKE-008",
                     "PAN-IKE-009"),
        subject_type=Control.ControlType.IKE_GATEWAY,
        summary=("Every finding against an IKE gateway - the protocol version it negotiates, how "
                 "it authenticates the peer, IKEv1 aggressive mode, dead-peer detection, and a "
                 "gateway running on a factory-named proposal - on one row per gateway."),
    ),
    RemediationGroup(
        slug="ike-crypto-profile",
        label="IKE crypto profile",
        one_pass=True,
        # PAN-IKE-010 IS THE ONLY ONE WHOSE FINDING IS ABOUT THIS OBJECT. The four strength
        # controls raise their findings against the tunnel PATH and fold onto this profile
        # through `PATH_SUBSTITUTION`, so one row carries both questions - is this proposal
        # weak, and does anything use it - and the finding count says how many tunnels the one
        # edit reaches.
        control_ids=("PAN-IKE-002", "PAN-IKE-003", "PAN-IKE-004", "PAN-IKE-005",
                     "PAN-IKE-010"),
        subject_type=Control.ControlType.IKE_CRYPTO_PROFILE,
        summary=("Every finding against an IKE crypto profile - a weak key-agreement group, "
                 "cipher, integrity algorithm or key lifetime, folded here from the tunnels that "
                 "run on it, and a profile no gateway names at all - on one row per profile."),
    ),
    RemediationGroup(
        slug="ipsec-crypto-profile",
        label="IPSec crypto profile",
        one_pass=True,
        control_ids=("PAN-IPS-001", "PAN-IPS-002", "PAN-IPS-003", "PAN-IPS-004",
                     "PAN-IPS-005", "PAN-IPS-009"),
        subject_type=Control.ControlType.IPSEC_CRYPTO_PROFILE,
        summary=("IPSec crypto profiles no tunnel on the firewall names, on one row per profile. "
                 "A candidate for removal rather than a confirmed leftover, for the same reason "
                 "as its IKE counterpart - and every finding against the payload proposal the "
                 "profile offers, folded here from the tunnels that run on it."),
    ),
)

GROUP_BY_SLUG = {group.slug: group for group in REMEDIATION_GROUPS}
GROUP_BY_CONTROL_ID = {control_id: group for group in REMEDIATION_GROUPS
                       for control_id in group.control_ids}



#: What a local definition's management plane is called when the appliance group names no
#: appliance. NINE of the lab's twenty enforcement points are in that state - they hang off a
#: second, empty group for a serial that is already a member of the HA pair - and they carry no
#: rules today, so this is a guard rather than a path anybody walks.
UNNAMED_APPLIANCE = "(appliance not recorded)"


def firewall_label(hostnames) -> str:
    """One label for the firewalls at an enforcement point, shared stem written once.

    An HA pair is almost always named by one trailing character - `fw-core-tpa-a` and
    `fw-core-tpa-b` - and writing the stem twice costs a third of the column to say nothing:

        ["fw-core-tpa-a", "fw-core-tpa-b"]   ->  "fw-core-tpa-a/b"
        ["pan-fw-111"]                       ->  "pan-fw-111"
        ["fw-core-tpa-a", "fw-edge-tpa-b"]   ->  "fw-core-tpa-a + fw-edge-tpa-b"

    IT COLLAPSES ONLY WHERE THE NAMES DIFFER IN THE LAST CHARACTER AND NOWHERE ELSE, which is the
    condition under which the short form is unambiguous: a reader can reconstruct both names from
    it exactly. Two hostnames that differ anywhere earlier are printed in full, because a reader
    who cannot rebuild the name cannot use it - and on a remediation surface the hostname is what
    they type into the device.

    Sorted first, so a pair reads the same way on every row whatever order the members arrive in.
    """
    names = sorted(hostnames)
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    if len({name[:-1] for name in names}) == 1:
        return names[0][:-1] + "/".join(name[-1] for name in names)
    return " + ".join(names)


def _firewalls_of(group):
    """The firewalls of a group as ONE label, named the way `Enforcement points` names them.

    `fw-core-tpa-a/b`, not two lines reading `fw-core-tpa-a (active)` and `fw-core-tpa-b`
    (Jason, 2026-11-03). Two reasons it changed. The pair is ONE place to a reader of this
    column - a profile defined on an HA pair is one definition and one trip - and the column
    beside it already collapses the same pair the same way, so printing it differently in two
    adjacent columns made one box look like two.

    AND THE HA STATE IS NOT PRINTED. Which node is active is true at the moment the
    configuration was read and not at the moment the change is made, and the standing rule -
    make a local change on the active member - is a rule about the bench, not a fact about this
    object. A stale `(active)` on a report is worse than no marker, because it reads as
    instruction.
    """
    if group is None:
        return []
    hosts = sorted(appliance.hostname for appliance in group.appliances.all())
    label = firewall_label(hosts)
    return [label] if label else []


def _point_label(point) -> str:
    """An enforcement point as an engineer knows it: the firewalls, then the virtual system.

    NOT the appliance group's name. That is `ha-pair-013201001085-013201001475` - this
    application's own bookkeeping, built from two serials, and nothing a customer would recognize.
    """
    group = point.appliance_group
    hosts = sorted(appliance.hostname for appliance in group.appliances.all()) if group else []
    label = firewall_label(hosts) or UNNAMED_APPLIANCE
    return f"{label} · {point.vsys_name}" if point.vsys_name else label


def _vsys_of(subject) -> str:
    """The virtual system a posture subject speaks for.

    Seven of the nine posture models hang off an enforcement point and two carry `vsys_name`
    themselves. Neither is in the sheet's own subject name, which reads
    `ha-pair-013201001085-013201001475 / vsys1 rule posture` - the appliance group's serial
    pair is this application's bookkeeping, which the surface refuses everywhere else.
    """
    point = getattr(subject, "enforcement_point", None)
    if point is not None and getattr(point, "vsys_name", ""):
        return point.vsys_name
    return getattr(subject, "vsys_name", "") or ""


def _reach_of(subject) -> list[str]:
    """WHERE THIS DEFINITION IS IN FORCE - the blast radius, as labels.

    The enforcement point when the object has one: a zone, a rule, a vsys-scoped profile. A
    SHARED OR DEVICE-WIDE object has none - `enforcement_point` is null on a Panorama-pushed
    profile, on a management interface, on NTP - and reading only that field left the column
    empty on 37 of the policy pages' rows and on every row of the first three Device pages. The
    firewalls behind the definition are the honest answer there: a device-wide setting is in
    force on the box it is read from, and a pushed definition on every firewall it reached.

    IT CAN REPEAT `Edit on` for a local device-wide setting, and that is correct rather than
    redundant - the two columns answer different questions and happen to have the same answer
    when the place you edit is the only place it applies.
    """
    point = getattr(subject, "enforcement_point", None)
    if point is not None:
        return [_point_label(point)]
    group = _group_of(subject)
    if group is None:
        # A DEVICE-WIDE SETTING HANGS OFF THE APPLIANCE, not off a group or a point - a
        # management interface, NTP, the login banner. `_group_of` answers None for those and
        # the column was empty on every row of the management-interface page; the box it is
        # read from is where it is in force.
        appliance = getattr(subject, "appliance", None)
        group = getattr(appliance, "appliance_group", None) if appliance is not None else None
        if group is None:
            return [appliance.hostname] if appliance is not None else []
    return _firewalls_of(group)


def _group_of(subject):
    """The appliance group behind a subject, whichever way it hangs off one.

    VSYS-SCOPED CONTENT HANGS OFF THE ENFORCEMENT POINT AND SHARED CONTENT OFF THE GROUP - a
    Panorama-shared or firewall-shared security profile has `enforcement_point` NULL, which is
    the shape recorded in the consumer notes as silently omitting shared and pushed profiles
    from an `enforcement_point__` traversal: "disproportionately the interesting rows, because a
    pushed definition is the one a customer cannot edit".
    """
    point = getattr(subject, "enforcement_point", None)
    if point is not None and getattr(point, "appliance_group", None) is not None:
        return point.appliance_group
    return getattr(subject, "appliance_group", None)


def _panorama_of(subject) -> list[str]:
    """The management station a pushed definition is edited on."""
    group = _group_of(subject)
    station = getattr(group, "management_station", None) if group is not None else None
    hostname = getattr(station, "hostname", "") if station is not None else ""
    return [hostname or "Panorama"]


#: `namespace_type` -> how to name the plane and the container. The six scoped policy models
#: carry it (AddressObject, AddressGroup, SecurityProfile, SecurityProfileGroup,
#: CustomUrlCategory, Region) and it is the only field that separates a firewall's own SHARED
#: scope from a vsys - provenance records both as `local` with an empty value. What it does NOT
#: carry is the device group: for a pushed object `namespace_value` is the VSYS the object ends
#: up in, and the group that authored it is in the `@loc` marker, so the pushed cases read
#: provenance for the container and fall back to the namespace value.
_PANORAMA_NAMESPACES = ("panorama_shared", "panorama_device_group", "pushed_vsys_effective")


def _where_by_namespace(subject, entry_row) -> tuple[list[str], str] | None:
    """(managed from, defined in) for a scoped policy object, or None if it carries no namespace."""
    namespace = getattr(subject, "namespace_type", None)
    if not namespace:
        return None
    point = getattr(subject, "enforcement_point", None)
    value = getattr(subject, "namespace_value", "") or ""
    if namespace in _PANORAMA_NAMESPACES:
        container = value
        if entry_row is not None and entry_row.provenance_type == "device_group":
            container = entry_row.raw_value or value
        elif namespace == "panorama_shared":
            container = "shared"
        return _panorama_of(subject), container
    if namespace == "predefined" or namespace == "builtin":
        # NO DESTINATION AT ALL, and the row has to say so rather than name a place. PAN-OS
        # ships these and nobody can edit them anywhere - 110 of the lab's security profiles.
        #
        # `predefined` IS WHERE IT LIVES, so this column uses the vendor's own word (Jason,
        # 2026-11-03): the object is read off `/config/predefined`. That is the opposite call
        # from the file-blocking tab's `Vendor-shipped` column, and for a reason - there the
        # cell is a yes/no about an object whose place is already named elsewhere, and
        # `predefined` would read as a synonym for `default`. Here the cell IS the place.
        #: NO CONTAINER: `Edit on` says PAN-OS shipped it and `Authority` says `Predefined`,
        #: so the container cell is an em dash rather than the words "not editable", which
        #: were a third way of saying the same thing (2026-11-04).
        return ["PAN-OS (predefined)"], ""
    if namespace == "local_shared":
        return _firewalls_of(_group_of(subject)) or [UNNAMED_APPLIANCE], "shared"
    return (_firewalls_of(_group_of(subject)) or [UNNAMED_APPLIANCE],
            getattr(point, "vsys_name", "") or value)


def _where_by_appliance(subject) -> tuple[list[str], str] | None:
    """(managed from, defined in) for a settings row that hangs off one appliance.

    NO CONTAINER, AND THE COLUMN SAYS SO WITH A DASH. `Location` names something a reader
    opens - a virtual system, a template, a device group, `shared` - and a device-wide setting
    sits in none of them: you select the firewall and edit it. This returned the words "the
    device itself" until 2026-11-04, which read as a container with a strange name on eight
    pages and appears nowhere on the zone page, whose Location column is the pattern. What that
    phrase was carrying is now said by the two columns either side of it: `Edit on` names the
    box and `Authority` says `Local`.
    """
    appliance = getattr(subject, "appliance", None)
    if appliance is None:
        return None
    group = getattr(appliance, "appliance_group", None)
    return _firewalls_of(group) or [appliance.hostname], ""


#: The entry marker's type, in the words a reader needs: who authored this definition, which is
#: the same question as *will my edit survive the next push*. `local` is the firewall's own
#: configuration and an edit there stands; a device group or a template is authored on Panorama
#: and an edit on the box is overwritten.
#: AN AUTHORITY IS A PLACE, so the three types that mean "nobody set this value" get an em
#: dash rather than a word (Jason, 2026-11-04: *"Not configured is not an authority value"*).
#: What was measured is in the value cell, which prints the default or says it is not set.
_NO_AUTHORITY = "\u2014"

_AUTHORITY_LABELS = {
    "local": "Local",
    "device_group": "Device group",
    "template": "Template",
    "panorama": "Panorama",
    "predefined": "Predefined",
    #: A COMPUTED COLUMN IS NOT A PLACE EITHER. `ProvenancedMixin.DERIVED_FIELDS` declares
    #: them and `_provenance_of` synthesises the row, which is worth reading - it is how the
    #: page tells a computed column from one nobody collected - but `Derived` answers neither
    #: question this column exists for, so it prints the same dash as an unset value and the
    #: two columns beside it say where to go (Jason, 2026-11-04).
    "derived": _NO_AUTHORITY,
    "pan_os_default": _NO_AUTHORITY,
    "not_configured": _NO_AUTHORITY,
    "assumed_default": _NO_AUTHORITY,
}

#: The authorities whose edits are made SOMEWHERE ELSE than the firewall - a page may want to
#: mark them, because an engineer who edits one of these on the box loses the change at the next
#: push.
PUSHED_AUTHORITIES = frozenset({"Device group", "Template", "Panorama"})

#: What the page says when NOTHING was collected about where a definition came from. Not
#: "local": measured on the lab, `Zone` has no provenance rows at all - 50 zones, zero markers -
#: so reading the absence as "the firewall's own" would be a claim this assessment never made.
#: The same distinction `not_configured` draws from `no` elsewhere in the application.
AUTHORITY_UNRECORDED = "Not recorded"

#: What a counted value stands as when the reader gave nothing back. A blank line carrying only
#: a count would read as a count with no value; the sheets already say `(empty)` for a member set
#: with no members, and this is the same statement about a cell.
NO_VALUE = "(nothing recorded)"


def _agreed_authority(seen) -> str:
    """One authority for a row, with `Not recorded` yielding to evidence.

    A row can hold findings whose asserted fields carry provenance and findings whose do not -
    a derived column has no row of its own - and mixing the two read `(differs)`, which says
    "two different places" when what happened is that one question had no evidence. Evidence
    wins; `Not recorded` survives only when nothing on the row had any.
    """
    answered = {value for value in seen if value and value != AUTHORITY_UNRECORDED}
    return _agreed(answered) if answered else _agreed(seen)


def _authority(subject, entry_row) -> str:
    """WHAT KIND OF PLACE authored this definition - `Local`, `Template`, `Device group`, ...

    THE KIND ONLY, never the container's name. It carried the name too until 2026-11-04 -
    `template creds_tpl` - and the page then printed `creds_tpl` twice, once as the location and
    once under it, which is what made the second line read as an afterthought rather than as a
    column (Jason, from the rendered page). `_where` already returns the name; this says what
    sort of thing it is, and the two sit side by side.

    Read off the same entry marker `_where` reads to decide the container, so the two cannot
    disagree about whether a definition was pushed.
    """
    namespace = getattr(subject, "namespace_type", None)
    if namespace in ("predefined", "builtin"):
        return _AUTHORITY_LABELS["predefined"]
    if entry_row is None:
        return AUTHORITY_UNRECORDED
    return _AUTHORITY_LABELS.get(entry_row.provenance_type, entry_row.provenance_type)


#: The provenance types that mean the value is authored somewhere other than this device.
_PUSHED_TYPES = frozenset({"template", "device_group", "panorama"})


def _field_placement(subject, provenance, content_type_id, fields):
    """Where the FIELDS AT FAULT are authored, for a subject with no entry of its own.

    AN APPLIANCE SINGLETON IS NOT AUTHORED IN ONE PLACE. PAN-OS merges a template into the
    device's tree LEAF BY LEAF, so `deviceconfig/system` on a managed firewall is part template
    and part local and there is no parent object to ask. Measured on the lab:
    `fw-core-tpa-a minimum password complexity` holds `minimum_length` and `history_count` from
    `ptpl_fw-core-tpa`, `enabled` set locally, eleven fields at a PAN-OS default and two not
    configured - so PAN-AUTH-002 is fixed on the Panorama and PAN-AUTH-010 on the box.

    THE AUTHORITY IS THE VALUE'S OWN PROVENANCE, and nothing else (Jason, 2026-11-04). A local
    value is an override and the box is where it changes; a pushed value is authoritative and
    its container is where it changes; an implicit value - `pan_os_default`, `assumed_default`,
    `not_configured` - was never set anywhere and says so in its own words. No rule, no
    precedence, no looking up at the container: the rows then GROUP on `Edit on`, `Authority`
    and `Location` together, so each row is one place and one kind of answer.

    Returns `(managed from, defined in, authority)`, or None where no field at fault carries a
    provenance row at all and the caller keeps the entry-level answer.

    THE ONE TIE-BREAK: a finding whose asserted fields disagree. A row carries one answer, so
    a value that EXISTS governs over one that does not - it is the value an engineer changes.
    Measured estate-wide, all twenty such findings pair a real value with an unset one, and
    none pairs a pushed value with a local one.
    """
    # READ THROUGH `_provenance_of`, not out of the index: a column the model declares in
    # `DERIVED_FIELDS` has no stored row and the closure synthesises a `derived` one. Reading
    # the index directly reported `Not recorded` for every computed column - 14 rows over five
    # pages, each one a verdict this application calculated rather than a value nobody read.
    provenance_of = _provenance_of(subject, provenance, content_type_id)
    rows = [row for row in (provenance_of(field) for field in fields) if row is not None]
    if not rows:
        return None
    #: A value that EXISTS outranks one that does not, and a computed column counts with the
    #: absences: neither names a place, and the row's destination is the strongest answer
    #: among its failing fields.
    row = max(rows, key=lambda found: 0 if (
        found.provenance_type in FieldProvenance.ABSENT_TYPES
        or found.provenance_type == "derived") else 1)
    authority = _AUTHORITY_LABELS.get(row.provenance_type, row.provenance_type)
    if row.provenance_type in _PUSHED_TYPES:
        return _panorama_of(subject), row.raw_value or authority.lower(), authority
    managed_from, defined_in = _where(subject, None)
    return managed_from, defined_in, authority


def _where(rule, entry_row) -> tuple[list[str], str]:
    """(managed from, defined in) - the two halves of where a definition lives.

    Read it as one sentence: log into THIS, and look in THAT. The word `shared` appears under both
    planes and means two different places - Panorama Shared, and a firewall's own shared scope -
    so the first half is what tells them apart.

    THE PUSHED CASE READS PROVENANCE, NOT THE RULE. `config_source` says a rule was pushed and
    which rulebase it landed in; only the `@loc` marker on its entry says WHICH DEVICE GROUP
    authored it, which is the thing a reader opens on Panorama. And `@loc` carries the literal
    `shared` for Panorama Shared, which `provenance_type` alone cannot distinguish from a device
    group - so this reads the VALUE, not the type.
    """
    by_namespace = _where_by_namespace(rule, entry_row)
    if by_namespace is not None:
        return by_namespace
    # A TEMPLATE IS PANORAMA'S ANSWER TO A DEVICE SETTING, and it has to be read before the
    # appliance fallback below or a pushed setting reads as "the device itself" - an instruction
    # to make an edit the next push will overwrite. Measured on the lab: 100 `__entry__` markers
    # of type `template` (`ptpl_fw-core-tpa`, `stack_fw-core-tpa`, `shared-base`), on management
    # interfaces, interface management profiles, SSL/TLS service profiles, server profiles and
    # six other Device subjects. None of them is on a page yet, which is why this was never
    # wrong on screen; the Network and Device pages are the ones it would have been wrong on.
    #
    # THE NAME IS THE TEMPLATE OR THE STACK, whichever authored the entry - the marker carries
    # what Panorama itself calls the container, and an engineer opens exactly that.
    if entry_row is not None and entry_row.provenance_type == "template":
        return _panorama_of(rule), entry_row.raw_value or "template"
    point = getattr(rule, "enforcement_point", None)
    if point is None:
        return (_where_by_appliance(rule)
                or (_firewalls_of(_group_of(rule)) or [UNNAMED_APPLIANCE], "shared"))
    if entry_row is not None and entry_row.provenance_type == "device_group":
        return _panorama_of(rule), entry_row.raw_value or "shared"
    return _firewalls_of(_group_of(rule)) or [UNNAMED_APPLIANCE], point.vsys_name


def _asserted_fields(controls) -> dict:
    """{control pk: {query name: (field, ...)}} - what each query says is at fault.

    The same map `build_rows` marks the value-at-fault fill from, so a cell highlighted here is
    highlighted on the findings tab for the same reason.
    """
    return {
        control.pk: {query.name: tuple(query.asserted_fields or ())
                     for query in control.queries.all()}
        for control in controls
    }


#: Subject columns that say WHERE the object is rather than what it says - this surface answers
#: that in its own two columns, and repeating it would cost three columns per row. `Object` is
#: the name, which is the third key column. Everything else a sheet declares is a value a reader
#: came for, and comes through untouched.
PLACEMENT_COLUMNS = frozenset({"Firewalls", "Vsys", "Device group", "Object", "Rule name",
                               "Appliance", "HA role"})


def value_columns(spec, controls=()):
    """The sheet's own value columns for a page over `controls` - (heading, read, field).

    Read off the SHEET rather than listed here, so a column added to a findings tab appears here
    too and the two surfaces cannot drift into describing one object two ways.

    TWO SOURCES, because a sheet states a value in two places. `subject_columns` are what the
    object always says - a profile's kind, a rule's applications. `setting_columns` are derived,
    one per field the page's controls actually TEST, and this surface drew none of them until
    2026-11-03: measured then, 24 of the 50 pages carried no failing value at all, because the
    thing the control asked about had no cell to be marked in. PAN-URL-002 was described by five
    antivirus columns and nothing about URL categories.

    PER PAGE, NOT PER CONTROL. A group page passes every control in the group, so each control's
    rows are built against the same columns and the merge cannot produce two rows with different
    cells. Passing nothing draws the subject columns alone, which is what the sheet's own tabs
    do when no control is named.

    AND NOT FOR A SUBSTITUTED CONTROL. PAN-AVW-001 asks its question of a RULE and this surface
    draws the PROFILE the rule names, so the control's tested fields - `antivirus_blocks_malware`,
    `config_source` - belong to a model the row is not. `setting_columns` guards the read and
    returns nothing for them, but it still makes the column, headed with the raw Django field
    name because the profile sheet has no label for a rule's field. Four such columns appeared on
    the antivirus page the moment this was wired, which is the measured reason the filter is here
    rather than left to the guard. Those controls are marked by `_ASSERTION_AXES` instead.
    """
    columns = [column for column in map(as_column, spec.subject_columns)
               if column[0] not in PLACEMENT_COLUMNS]
    drawn = [control for control in controls if not _substituted(control)]
    columns += [as_column(column) for column in setting_columns(spec, drawn)]
    return [(column[0], column[3], column[4]) for column in columns]


def _headings_by_field(spec, columns) -> dict:
    """{field: the heading of the cell that presents it} over the columns a page draws.

    `hidden_fields` wins where it names a carrying column, which is the sheet's own statement
    that one column speaks for a field that has no column of its own.
    """
    headings = {}
    hidden = spec.hidden_fields
    if isinstance(hidden, dict):
        headings.update({field: heading for field, heading in hidden.items() if heading})
    for heading, _read, field in columns:
        if field:
            headings.setdefault(field, heading)
    return headings


#: What the sheet calls the object itself. Every findings sheet has one, and its heading is one
#: of these - the generic `Object`, or the policy sheets' `Rule name`.
IDENTITY_COLUMNS = ("Object", "Rule name")


def _name_reader(spec):
    """How to name a subject, taken from the sheet rather than guessed from its fields.

    Guessing cost a round: `DecryptionPolicyRule` calls its name `rule_name`, so `subject.name`
    is None and `str(subject)` is the whole path - `standalone-691665AC334B458 / vsys1 / local /
    oep-dec6-d01` - which is four facts where the row wants one. The sheet already states the
    answer in its identity column, and taking it from there means a model that renames a field
    cannot quietly change what this surface calls it.
    """
    for column in map(as_column, spec.subject_columns):
        if column[0] in IDENTITY_COLUMNS:
            read = column[3]
            return lambda subject, provenance_of: read(subject, provenance_of)
    return lambda subject, _provenance_of: (
        getattr(subject, "name", None) or getattr(subject, "rule_name", None) or str(subject))


#: THE PROFILE CONTROLS ASK A QUESTION ABOUT A PROFILE AND REPORT IT ON A RULE, so the thing to
#: change is the profile and not the rule - unless there is no profile, which is the other half
#: of the same question. Jason, 2026-11-03: *"There's two ways to look at this. The first is when
#: an antivirus profile isn't attached to a rule at all. The second is an antivirus profile that
#: is applied to rules but does not properly enforce the block action(s). One fix is to apply a
#: profile to the rule, the other is to modify the profile."*
#:
#: THE DATA ALREADY SAYS WHICH, in three states on `SecurityRuleProfileVerdict.satisfied`:
#: True a profile of the right kind is in force and satisfies, False one is in force and does
#: not, NULL none reaches this rule at all. Measured on the lab, PAN-AVW-001: 1,012 findings are
#: NULL - no profile - and 15 are False over 14 distinct profiles.
#:
#: SO THE OBJECT ON THESE PAGES IS THE PROFILE, and a rule with none gets a row whose object is
#: the ABSENCE. That is what makes the fold worth having: 1,027 findings become fifteen-odd rows
#: instead of a thousand, and each one is a thing somebody does once.
_VERDICT_KINDS = {}


#: THE SECOND KIND OF SUBSTITUTED CONTROL, 2026-11-04: the finding's subject is an IPSec TUNNEL
#: PATH and the object an engineer opens is one of the two crypto profiles that path runs on.
#:
#: WHY IT IS A SUBSTITUTION AND NOT A GROUP OVER THE PATH. These nine controls raise a finding per
#: TUNNEL - which is the point of the path, so the finding count is the blast radius - while the
#: remedy is the ONE profile every one of those tunnels names. A page keyed on the path would put
#: the same profile on six rows and send an engineer to edit it six times; keyed on the profile it
#: is one row whose finding count says how far the edit reaches. Jason, 2026-11-04: *"One row
#: stops being one place."*
#:
#: {control_id: (the path's foreign key, the findings domain whose sheet draws the object,
#:               what to call a row where the path resolves no profile at all)}
PATH_SUBSTITUTION = {
    "PAN-IKE-002": ("ike_crypto_profile", "ike-crypto-profiles", "(no IKE crypto profile)"),
    "PAN-IKE-003": ("ike_crypto_profile", "ike-crypto-profiles", "(no IKE crypto profile)"),
    "PAN-IKE-004": ("ike_crypto_profile", "ike-crypto-profiles", "(no IKE crypto profile)"),
    "PAN-IKE-005": ("ike_crypto_profile", "ike-crypto-profiles", "(no IKE crypto profile)"),
    "PAN-IPS-001": ("ipsec_crypto_profile", "ipsec-crypto-profiles",
                    "(no IPSec crypto profile)"),
    "PAN-IPS-002": ("ipsec_crypto_profile", "ipsec-crypto-profiles",
                    "(no IPSec crypto profile)"),
    "PAN-IPS-003": ("ipsec_crypto_profile", "ipsec-crypto-profiles",
                    "(no IPSec crypto profile)"),
    "PAN-IPS-004": ("ipsec_crypto_profile", "ipsec-crypto-profiles",
                    "(no IPSec crypto profile)"),
    "PAN-IPS-005": ("ipsec_crypto_profile", "ipsec-crypto-profiles",
                    "(no IPSec crypto profile)"),
}


def _path_substitution(control):
    """`(foreign key, domain slug, absence name)` for a path-keyed control, else None.

    THE CONTROL'S TYPE IS CHECKED AND NOT ONLY ITS ID, which is what keeps this honest while a
    catalog re-seed is outstanding: the same nine ids existed for weeks keyed on the two
    crypto profile models, and a control still seeded that way reports ON the profile - its
    finding's subject already IS the object. Matching on the id alone fired the substitution on
    those findings and asked a profile for a foreign key it does not have, which turned every
    row on both pages into an absence row. Measured on the lab, 2026-11-04, before the re-seed.
    """
    if control.control_type != Control.ControlType.IPSEC_TUNNEL_PATH:
        return None
    return PATH_SUBSTITUTION.get(control.control_id)


def _substituted(control) -> bool:
    """Whether this control's object is something other than its finding's own subject."""
    return _verdict_assertion(control) is not None or _path_substitution(control) is not None


def _verdict_assertion(control) -> str | None:
    """The profile assertion this control reports, or None if it is not one of them."""
    from optivedge_integrations.integrations.models.policy.rules import (
        SecurityRuleProfileVerdict as Verdict)

    if not _VERDICT_KINDS:
        for assertion in Verdict.ANTIVIRUS_ASSERTIONS:
            _VERDICT_KINDS[assertion] = ("virus", "antivirus")
        for assertion in Verdict.SPYWARE_ASSERTIONS:
            _VERDICT_KINDS[assertion] = ("spyware", "anti-spyware")
        for assertion in Verdict.VULNERABILITY_ASSERTIONS:
            _VERDICT_KINDS[assertion] = ("vulnerability", "vulnerability protection")
    asserted = {field for query in control.queries.all()
                for field in (query.asserted_fields or ())}
    found = sorted(asserted & set(_VERDICT_KINDS))
    return found[0] if found else None


def _agreed(values) -> str:
    """One value where every object of this name agrees, `(differs)` where they do not.

    The idiom `rules_by_device_group.agreed` uses, for the same reason: a row that folds several
    objects must not print one of them as if it spoke for the rest.

    THE VALUE COLUMNS NO LONGER READ THIS - see `_agreed_lines`. It remains the Authority
    column's, where a disagreement is not a measurement to show but a row that should have been
    keyed apart, and one word is the right amount to say about it.
    """
    distinct = {value for value in values}
    if not distinct:
        return ""
    return distinct.pop() if len(distinct) == 1 else "(differs)"


def _agreed_lines(values, is_list: bool) -> list[str]:
    """A folded cell as the lines to draw it on: every value the objects hold, each counted.

    `(differs)` was all this said until 2026-11-05, and on the one page where it appears it was
    both uninformative and MARKED AT FAULT - the amber says "this is the value to change" over a
    word that is not a value. Jason: *"The differs should carry all the values. On the values
    that differ, perhaps just a simple count of how many appliances carry the differing value."*

    COUNTED IN DEFINITIONS AND NOT IN APPLIANCES, which is the one place this departs from how
    he put it. The objects folded onto a row are the materialisations of one definition, and for
    a security rule that is one per ENFORCEMENT POINT: `Ingress Internet` is pushed to seven, and
    five of those seven are virtual systems on one HA pair. "5 appliances" would be false of a
    pair that is two boxes, and "2 appliances" would lose four of the five readings. `4 of 7` is
    the ratio that is true either way, and the row's `In force on` column names the seven.

    A SET COLUMN IS COUNTED BY ITS MEMBERS, not by the whole set. `Sources` and the offer sets
    hold several values in one cell, and counting the sets would print two cells that read the
    same - `ftp`, and `ftp` again - with a count against each and no way to see that what
    differs is the `smtp` one of them also offers. Counted per member, the same cell says `ftp`
    on all seven and `smtp (3 of 7)`, which is the sentence an engineer acts on.

    ORDER. A set keeps the reader's own order, first appearance first, because the order of an
    offer set or a member list means something. Single values lead with the biggest share, then
    alphabetically, so the dominant reading is read first and nothing moves between runs.

    AGREEMENT IS LEFT EXACTLY AS IT WAS: the value, no annotation, in the reader's order. The
    count earns its place only where there is something to count.
    """
    held = [value for value in values]
    if not held:
        return []
    total = len(held)
    if len({*held}) == 1:
        return _as_lines(held[0], is_list)

    if is_list:
        # DEDUPED WITHIN AN OBJECT FIRST: a member a single object lists twice is still that one
        # object holding it, and counting it twice would read as two.
        counts: dict = {}
        for members in (_as_lines(value, True) for value in held):
            for member in dict.fromkeys(members):
                counts[member] = counts.get(member, 0) + 1
        return [member if count == total else f"{member} ({count} of {total})"
                for member, count in counts.items()]

    lines = []
    for value, count in sorted(collections.Counter(held).items(),
                               key=lambda item: (-item[1], str(item[0]))):
        # ANNOTATED ON THE FIRST LINE OF THE VALUE, because a single value can still be several
        # lines - `any` and the address count it expands to - and a count on a line of its own
        # would read as a value. A blank still carries its count: "nothing recorded here, on
        # three of the seven" is a measurement and not an absence of one.
        drawn = _as_lines(value, is_list) or [NO_VALUE]
        lines.append(f"{drawn[0]} ({count} of {total})")
        lines.extend(drawn[1:])
    return lines


#: assertion -> the profile fields the verdict pass READ to reach it, which is also which of
#: the drawn sheet's cells holds the value at fault. Mirrors `RULE_PROFILE_ASSERTIONS`'
#: `_antivirus_malware_verdict_for_rule` and `_antivirus_ml_verdict_for_rule` in OEI's
#: `normalization/security_profiles.py`, which is the one place an assertion is tied to what it
#: reads: the malware verdict collects FOUR independent gaps and the inline-ML verdict one.
#:
#: WHY NOT "EVERY AXIS THIS PROFILE FAILS". `oep-avw-weak` has both non-blocking decoders and
#: non-blocking inline ML models - the first is PAN-AVW-001's and the second is PAN-AVW-002's,
#: and highlighting both on 001's page would make the fill mean "something here is wrong"
#: instead of "this is the value that fired THIS control", which is what it means everywhere
#: else in the application.
#:
#: THE OTHER NINE ASSERTIONS ARE ABSENT BECAUSE THE SHEET HAS NO CELL FOR THEM. The
#: security-profile sheet carries `Kind`, `Object` and these five antivirus axes and nothing
#: about spyware or vulnerability, so a spyware control folded here has no value column to
#: mark and its rows carry no amber at all - measured, every row on the anti-spyware and
#: vulnerability pages. Adding a column there is a findings tab change, not this surface's.
_ASSERTION_AXES = {
    "antivirus_blocks_malware": ("has_non_blocking_decoder",
                                 "has_non_blocking_wildfire_decoder",
                                 "has_non_blocking_mlav_decoder",
                                 "has_non_blocking_application_override"),
    "antivirus_inline_ml_blocks": ("has_non_blocking_ml_model",),
}


def _axis_columns(headings: dict) -> frozenset:
    """The headings of the cells that hold a LIST, so they can be written one value per line.

    Every one of them reads a `non_blocking_*` collection and comma-joins it. The rest of what a
    sheet declares is either a single value or prose, and the measurement that settled this is
    the reason it is a set rather than a blanket rule: the rules sheet's `Profiles` cell holds
    sentences - "WildFire analysis: oep-avw6-w4: no rules at all, so nothing is sent for
    analysis" - and splitting those on the comma cuts one sentence into two lines, the second of
    which says nothing.
    """
    fields = {field for axes in _ASSERTION_AXES.values() for field in axes}
    return frozenset(filter(None, (headings.get(field, "") for field in fields)))


def _as_lines(value: str, is_list: bool) -> list[str]:
    """A cell as the lines to draw it on - one value per line where it holds several.

    Jason, 2026-09-27 and again 2026-11-03: *"in cells that contain multiple values, those values
    are separated by new lines and not commas."* The sheets' readers already line-separate the
    rule member sets; the five antivirus axes comma-join theirs, and on a row this wide a joined
    decoder list reads as one long word.

    SPLIT AT PAREN DEPTH ZERO ONLY, because a value carries commas of its own: `ftp (no action
    set, which allows), gmail-base (allow)` is TWO values and splitting on every comma makes it
    four, attaching half a sentence to the wrong application.
    """
    lines = [line.strip() for line in str(value).splitlines()]
    if not is_list:
        return [line for line in lines if line]
    out = []
    for line in lines:
        depth, buf = 0, ""
        for character in line:
            if character == "(":
                depth += 1
            elif character == ")":
                depth = max(0, depth - 1)
            if character == "," and depth == 0:
                out.append(buf.strip())
                buf = ""
            else:
                buf += character
        out.append(buf.strip())
    return _without_actions([line for line in out if line])


#: `ftp (alert only)` -> `ftp`. The leading group is the value, the trailing parenthesis the
#: action it is set to.
_ACTION_SUFFIX = re.compile(r"^(?P<value>\S.*?)\s*\([^()]*\)$")


def _without_actions(lines: list[str]) -> list[str]:
    """The axis values with the per-value ACTION dropped (Jason, 2026-11-03).

    These columns name what does not block - `ftp`, `MSOffice`, `web-browsing` - and each value
    carried what it is set to instead: `(alert only)`, `(disabled)`, `(allow)`, `(no action set,
    which allows)`. On a page this wide the suffix is most of the cell and the same few words
    repeat down every row, so the names a reader is scanning for are the part that gets lost.

    ONLY WHERE SOMETHING PRECEDES THE PARENTHESIS, so a value that IS a parenthesis survives
    whole - `(1,048,576 addresses)` on an address group, `(no antivirus profile)` on an absence
    row. And the result is de-duplicated, because two values that differed only by their action
    - `smb` and `smb (alert only)` on one profile - are one value once the action is gone.

    DONE HERE AND NOT IN THE SHEET, so the findings tabs and the workbook still carry the
    action: there the cell is the evidence for a verdict and the action is part of it. This
    surface asks a different question - what do I change - and the answer is the name.
    """
    out = []
    for line in lines:
        match = _ACTION_SUFFIX.match(line)
        value = match.group("value") if match else line
        if value not in out:
            out.append(value)
    return out


def _axes_at_fault(assertion, subjects, headings: dict) -> set:
    """Which of this row's own cells hold the value the assertion failed on.

    THE ASSERTED FIELD IS A COLUMN ON THE RULE AND THE OBJECT HERE IS THE PROFILE, so the fill
    that `build_rows` lands from the control's `asserted_fields` has nothing to land on - which
    is why `What to change` exists and why, before this, a profile row carried no highlight at
    all. The axis the verdict read is the same value in the profile's own vocabulary.

    MARKED ONLY WHERE THE AXIS IS ACTUALLY AT FAULT: `oep-avw-app-override` blocks on every
    decoder and fails on its application exceptions alone, so one cell of its four is filled.
    """
    marked = set()
    for field in _ASSERTION_AXES.get(assertion, ()):
        column = headings.get(field, "")
        if column and any(getattr(subject, field, False) for subject in subjects):
            marked.add(column)
    return marked


#: WHICH OF THE PROFILE'S OWN COLUMNS EACH PATH-KEYED CONTROL FAULTS, by the FIELD the column
#: declares. The shipped pattern, from the Security Profile sheet: the marked cell is the one
#: that NAMES WHAT TO CHANGE - `Decoders not blocking` reads "http, ftp, smtp (alert only)" - so
#: here it is the offer set, which prints the whole list with the member an exchange can be
#: driven down to named inside it. A weakest-member column would name something nobody can edit.
#:
#: TWO OF THEM CHOOSE BY THE PROFILE'S OWN BRANCH rather than naming one column, because the two
#: branches are exclusive on a device and the column that applies follows the branch: on an
#: AH-only profile there is no ESP cipher list to delete from, and what is at fault is the branch
#: itself. `ipsec_presentation.integrity_offered` reads the same way for the same reason.
_PATH_AXES = {
    "PAN-IKE-002": ("dh_groups",),
    "PAN-IKE-003": ("encryption_ciphers",),
    "PAN-IKE-004": ("hash_algorithms",),
    # The lifetime cell, which carries the hours AND the unit branch they are written in - the
    # one a remediation has to open. `reauth_interval_bounded` is NOT marked: its own column
    # reads the computed interval and the verdict, and marking it on a row that fired on the
    # lifetime half would claim both halves failed.
    "PAN-IKE-005": ("key_lifetime_unit",),
    "PAN-IPS-004": ("dh_group",),
    "PAN-IPS-005": ("lifetime_unit",),
}


def _path_axes_at_fault(control_id, subjects, headings: dict) -> set:
    """The profile's own cells this path-keyed control faults, chosen per subject where needed."""
    from optivedge_integrations.integrations.models import IpsecCryptoProfile

    if not subjects:
        return set()
    fields = list(_PATH_AXES.get(control_id, ()))
    for subject in subjects:
        branch = getattr(subject, "protocol_branch", None)
        if control_id == "PAN-IPS-001":
            # The branch IS the assertion, so the branch column is the cell - and on a profile
            # carrying NEITHER branch the two lists read as inapplicable, which is the same cell.
            fields.append("protocol_branch")
        elif control_id == "PAN-IPS-002":
            fields.append("esp_encryption" if branch == IpsecCryptoProfile.ProtocolBranch.ESP
                          else "protocol_branch")
        elif control_id == "PAN-IPS-003":
            fields.append("esp_authentication"
                          if branch == IpsecCryptoProfile.ProtocolBranch.ESP
                          else "ah_authentication"
                          if branch == IpsecCryptoProfile.ProtocolBranch.AH
                          else "protocol_branch")
    return {headings[field] for field in fields if field in headings}


def _profiles_by_name(kind: str, prefetch=()) -> dict:
    """{name: [profile, ...]} for one profile kind, loaded in one go.

    LOADED WITH `.all()` AND NARROWED IN PYTHON, which is a boundary and not a preference:
    `test_query_service_boundary` refuses a filter on an asserted model outside the search
    service, and `SecurityProfile` is one - the first version filtered on name and kind and
    turned that test red. The whole table is 299 rows on the lab and this runs once per page,
    so the cost of obeying it is nothing.
    """
    from optivedge_integrations.integrations.models import SecurityProfile

    index: dict[str, list] = {}
    # THE SHEET'S OWN CHILD SETS COME WITH THEM. Without this the value columns read a
    # profile's decoders, ML models and application overrides one query at a time: measured on
    # the antivirus page, 211 of its 253 queries were those three tables.
    found = SecurityProfile.objects.all().select_related(
            "enforcement_point", "enforcement_point__appliance_group",
            "enforcement_point__appliance_group__management_station",
            "enforcement_point__appliance_group__active_appliance",
            "appliance_group", "appliance_group__management_station",
            "appliance_group__active_appliance")
    if prefetch:
        found = found.prefetch_related(*prefetch)
    for profile in found:
        if profile.kind == kind:
            index.setdefault(profile.name, []).append(profile)
    return index


def _profile_for(rule, name, index):
    """The profile a verdict was read from, resolved the way the verdict resolved it.

    The verdict stores the NAME - "resolved by name AND scope", in the model's own words - and
    not the object, so this re-resolves it: the candidate in the rule's own virtual system
    first, then any other of that name. On the lab the only name carried by several objects is
    `default`, and all eleven of those are PREDEFINED and identically placed, so the preference
    never has to choose between two real answers.
    """
    candidates = index.get(name) or []
    point_id = getattr(rule, "enforcement_point_id", None)
    for candidate in candidates:
        if candidate.enforcement_point_id == point_id:
            return candidate
    return candidates[0] if candidates else None


def domain_spec_for(control):
    """The findings sheet this control's rows are drawn on - its columns and its labels.

    Resolved by asking each domain which controls it SELECTS, which is the repository's own
    routing (`selected_controls`): the control type alone answers wrongly for the eleven profile
    controls, which share a type with the PAN-POL controls and are drawn on four other tabs.
    """
    for domain in artifact_domains.DOMAINS:
        if control.control_type in domain.spec.control_types:
            if control.pk in {found.pk for found in selected_controls(domain.spec)}:
                return domain.spec
    return None


def remediation_controls() -> list[dict]:
    """Every control a declared group covers that has a finding, with its totals.

    THE GROUPS NAME THEM, by control id. It used to be every control of four hand-listed types
    - the device-group policy subjects - which worked only while every page was a policy page: a
    Network or Device group then had to be declared twice, and a type missed from the second
    list left the group with no row and no page, silently, on the one surface whose job is to
    say where a change is made.

    Counted rather than folded: the index needs how many and how bad, and folding fifty
    controls to total them would do the whole job of every page to draw one.
    """
    controls = {control.pk: control for control in Control.objects.filter(
        control_id__in=GROUP_BY_CONTROL_ID, is_active=True)}
    totals: dict[int, dict] = {}
    for kind in _kinds({control.control_type for control in controls.values()}):
        for control_id, severity, count in (kind.model.objects
                                            .filter(control__in=controls)
                                            .values_list("control_id", "severity")
                                            .annotate(total=Count("severity"))):
            row = totals.setdefault(control_id, {"findings": 0, "by_severity": {}})
            row["findings"] += count
            row["by_severity"][severity] = row["by_severity"].get(severity, 0) + count

    rows = []
    for control_id, total in totals.items():
        worst = max(total["by_severity"], key=lambda severity: SEVERITY_RANK[severity])
        control = controls[control_id]
        rows.append({
            "control": control,
            "summary": _summary_of(control),
            "subject": _kind_for(control.control_type).label,
            "findings": total["findings"],
            "by_severity": total["by_severity"],
            "severity": Control.Severity(worst).label,
            "severity_value": worst,
        })
    # CATALOGUE ORDER - NOT by severity. These rows are folded into group rows by
    # `remediation_index`, which sorts the page itself; what this order decides is the order a
    # group's controls are listed in, and that should be the order the controls list and the
    # workbook's own Controls tab use. Ranking by severity makes the same control move between
    # estates.
    rows.sort(key=lambda row: row["control"].control_id)
    return rows


def _summary_of(control) -> str:
    """The control's description in one line, which is the line it already opens with.

    A catalog description runs from 1KB to 8.5KB - the whole argument for the control, its
    severity bands, what the vendor says - and the index wants the sentence, not the argument.
    Measured over these fifty: every one opens with a single sentence naming what is wrong, 65
    to 221 characters, and the rest is separated from it by a blank line. So this takes the
    first non-empty line rather than truncating prose, which would cut mid-word and read as
    damage. The whole description is on the control's own page, one click away.
    """
    for line in (control.description or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def _kinds(control_types):
    """The finding kinds for these control types - the models the index has to count over."""
    return [kind for kind in finding_registry.FINDING_KINDS
            if kind.control_type in control_types]


def _kind_for(control_type):
    for kind in finding_registry.FINDING_KINDS:
        if kind.control_type == control_type:
            return kind
    raise LookupError(control_type)


def _findings_of(control, spec, kind=None, placement_only=False):
    """This control's findings - or a LIST of controls' - with the value columns' joins loaded.

    NOT through `load(spec)`: the rules spec excludes the eleven profile controls, which are
    rule-based since 2026-10-12 and belong on this surface exactly as the PAN-POL controls do.
    The joins ARE the spec's own, prefixed with the finding's subject field, so a sheet that
    declares what its readers need gets it here too - without them the member sets behind
    Sources, Service, Application and Profiles are a query per row.

    The placement joins are added by what the SUBJECT MODEL has rather than by a fixed list: a
    rule and a profile hang off an enforcement point, a settings row off an appliance, and
    asking for the wrong one raises.
    """
    controls = control if isinstance(control, list) else [control]
    kind = kind or _kind_for(controls[0].control_type)
    subject = kind.subject_field
    model = kind.model._meta.get_field(subject).related_model
    fields = {field.name for field in model._meta.get_fields()}

    # A SUBSTITUTED CONTROL'S FINDINGS ARE READ FOR THEIR PLACEMENT, NOT THEIR VALUES. The
    # page draws the PROFILE the rule names, so the rule's own member sets - its zones,
    # services, applications and profile bindings - are loaded and never read. Measured on the
    # antivirus page: 2,049 rule findings carrying those joins instantiate 83,030 model
    # objects to produce 30 rows, and `_findings_of` was 2.1s of its 2.9s.
    related = [subject]
    prefetch = []
    if not placement_only:
        related += [f"{subject}__{name}" for name in spec.subject_select_related]
        prefetch += [f"{subject}__{name}" for name in spec.subject_prefetch]
    if "enforcement_point" in fields:
        related += [f"{subject}__enforcement_point",
                    f"{subject}__enforcement_point__appliance_group",
                    f"{subject}__enforcement_point__appliance_group__management_station",
                    f"{subject}__enforcement_point__appliance_group__active_appliance"]
        prefetch.append(f"{subject}__enforcement_point__appliance_group__appliances")
    if "appliance" in fields:
        related += [f"{subject}__appliance", f"{subject}__appliance__appliance_group",
                    f"{subject}__appliance__appliance_group__active_appliance"]
        prefetch.append(f"{subject}__appliance__appliance_group__appliances")

    return list(kind.model.objects.filter(control__in=controls)
                .select_related(*dict.fromkeys(related))
                .prefetch_related(*dict.fromkeys(prefetch)))


def _findings_of_controls(controls, spec):
    """Every finding of SEVERAL controls that share a finding model, in one query per model.

    `_findings_of` asks the same question one control at a time, which is what the per-control
    fold needs and what makes a group page pay for the same subjects again per control:
    measured on the security-rule group, sixteen controls over the same 1,035 rules instantiate
    175,930 model objects to build 1,035 rows, and `_findings_of` is 4.2s of that page's 8.4s.
    Here the rules are fetched once per model and the objects are shared by every control's
    findings, because Django returns the same instance for a select_related join within one
    queryset.
    """
    found = []
    #: KEYED BY THE KIND AND THE CONTROL'S OWN SHEET, not the page's. The joins a finding
    #: needs belong to the model it hangs off: a substituted control's findings are RULE
    #: findings, and loading them with the profile sheet's related names asks a rule for
    #: `appliance_group` and raises.
    by_kind: dict = {}
    for control in controls:
        own = domain_spec_for(control)
        if own is None:
            continue
        by_kind.setdefault((_kind_for(control.control_type), own.sheet_title),
                           (own, []))[1].append(control)
    for (kind, _title), (own, kind_controls) in by_kind.items():
        found += _findings_of(
            kind_controls, own, kind=kind,
            placement_only=all(_verdict_assertion(control) is not None
                               for control in kind_controls))
    return found


def remediation_rows(control: Control, columns_controls=None, prune=True,
                     columns_spec=None) -> list[dict]:
    """One row per object DEFINITION this control has a finding against.

    `columns_controls` names whose settings get a column. A group page passes the whole group,
    so every control's rows are built against one column set and the merge cannot produce two
    rows with different cells; left out, the page draws this control's own.

    `columns_spec` names WHICH SHEET those columns come from, which a group page also decides
    for itself - see `group_columns_spec`. Left out it is this control's own sheet.

    For a profile-on-rule control the object is the PROFILE, and a rule that names none of the
    right kind gets a row whose object is the absence - see `_verdict_assertion`. Both land in
    one table, because both are the same question about the same thing: what inspects this
    traffic, and where do I go to change it.
    """
    spec = domain_spec_for(control)
    if spec is None:
        return []
    findings = _findings_of(control, spec)
    if not findings:
        return []

    kind = _kind_for(control.control_type)
    assertion = _verdict_assertion(control)
    subjects, missing_for, own_columns_spec = _subjects_for(
        control, findings, kind, assertion, spec)
    columns_spec = columns_spec or own_columns_spec
    # INDEXED OVER BOTH: the resolved objects, and the rules a row is PLACED on where no object
    # exists. A missing row's plane comes from the rule's own entry provenance, so leaving the
    # rules out of the index read every one of them as locally defined.
    provenance = provenance_index(
        {subject for subject in subjects.values() if subject is not None}
        | {kind.subject_of(finding) for finding in findings})
    by_type = {}
    asserted_by_query = _asserted_fields([control]).get(control.pk, {})
    columns = value_columns(columns_spec, columns_controls or [control])
    headings = _headings_by_field(columns_spec, columns)
    list_columns = _axis_columns(headings)
    name_of = _name_reader(columns_spec)

    grouped: dict[tuple, dict] = {}
    for finding in findings:
        subject = subjects[finding]
        placed_on = subject if subject is not None else kind.subject_of(finding)
        content_type_id = by_type.setdefault(
            type(placed_on), ContentType.objects.get_for_model(type(placed_on)).pk)
        entry_row = provenance.get((content_type_id, placed_on.pk, "__entry__"))
        managed_from, defined_in = _where(placed_on, entry_row)
        if subject is None:
            # THE ABSENCE HAS NO OBJECT, so `Defined in` names the PLANE rather than a container:
            # there is nothing holding a profile that is not there. For a pushed rule that is the
            # device group off the `@loc` marker, read on Panorama; for a local one it is the word
            # `Local` and the box is `Managed from`.
            #
            # A LOCAL ABSENCE IS ONE ROW PER APPLIANCE GROUP, NOT ONE ROW FOR THE ESTATE, which
            # is the shape `Managed from` gives it for free once `Defined in` stops being empty.
            # Measured on PAN-AVW-001 before the split: a single `Local` row carried 390 findings
            # over 386 rules on NINE enforcement points - 263 rules on the HA pair, 107 on
            # pan-fw-111, 20 on the PA-VM. Three boxes, three sittings, and one row that read as
            # one job. Every Panorama row on that page is genuinely one trip because it splits by
            # device group; this is the same split on the plane that has no device groups. It does
            # NOT split by virtual system: seven vsys on one pair is still one trip.
            name = missing_for
            if entry_row is not None and entry_row.provenance_type == "device_group":
                managed_from = _panorama_of(placed_on)
                defined_in = entry_row.raw_value or "shared"
            else:
                # NO CONTAINER, AND THE COLUMN SAYS SO WITH A DASH. A pushed absence is
                # missing from a device group, which is a place to open; a local one is
                # missing from the firewall's own rulebase, which `Edit on` already names and
                # `Authority` reads `Local` for. The literal "Local" sat in the container
                # column until 2026-11-04 and said the same thing twice.
                defined_in = ""
        else:
            subject_ct = by_type.setdefault(
                type(subject), ContentType.objects.get_for_model(type(subject)).pk)
            name = name_of(subject, _provenance_of(subject, provenance, subject_ct))
        # ONE ROW PER OBJECT NAME, counts aggregated there (Jason, 2026-11-03). The places are
        # collected rather than keyed on, so `(no antivirus profile)` is ONE row carrying every
        # firewall and virtual system whose rules lack one - nine places and 1,012 findings on
        # the lab - instead of nine rows of the same instruction.
        #
        # WHAT THIS MERGES, measured and visible rather than hidden: a name that exists in two
        # places is two objects to edit, and both places are listed in the row. PAN-POL-002 has
        # six such names and PAN-POL-008 forty-seven, all of them a rule defined in two device
        # groups. Where the objects do not agree the cell carries EVERY value they hold, each
        # with how many of them hold it - see `_agreed_lines`.
        # ONE ROW IS ONE PLACE YOU GO. Jason, 2026-11-04: *"Each row should be an 'instance'
        # of an object that can be changed. Each row should resolve to a single location."*
        # The name alone used to be the key for a named object, which folded every definition
        # of that name in the estate onto one row: the zone `Private` is defined on three
        # firewalls in two virtual systems, and that row said "go to pan-fw-111, PA-VM and
        # fw-core-tpa-a/b, in vsys1 and vsys8" - three edits read as one, and no way to tell
        # which value belonged to which box.
        #
        # THE PLACE IS NOT THE SAME AS THE NUMBER OF FINDINGS CLEARED. A profile defined once
        # in a device group and pushed to thirty virtual systems is still ONE row and one
        # edit, because its place is the device group; the findings it clears are counted
        # beside it and the virtual systems are listed in `Enforcement points`.
        key = (name, tuple(managed_from), defined_in)
        row = grouped.setdefault(key, {
            "managed_from": [],
            "defined_in": set(),
            "name": name,
            "missing": subject is None,
            "findings": 0,
            "points": set(),
            "severities": set(),
            #: The same severities, counted - what the page's own strip adds up.
            "by_severity": collections.Counter(),
            "matched": set(),
            "at_fault": set(),
            #: WHICH CONTROL MARKED EACH CELL. On a one-control page that is the page's own
            #: control and tells a reader nothing; on a GROUP page a row can carry five marked
            #: cells from three controls, and without the attribution the amber says "something
            #: here is wrong" instead of naming the question that was asked. Carried on every row
            #: either way, so one code path builds both pages.
            "at_fault_by": {},
            #: WHO AUTHORED THE DEFINITION - see `_authority`. A set, because a row can fold
            #: several materialisations of one definition and they must agree before the page
            #: says so.
            "authority": set(),
            #: {control id: the control's CATALOGUE NAME}. Jason, 2026-11-04: *"Findings,
            #: Severity, Control Id, Control Name ... should be readable as a group from left to
            #: right"*, reading *"3 findings of medium severity for control id PAN-IOT-002 with
            #: control name Device-ID Enabled on IoT-Hosting Zones"*, and *"There should only be
            #: one 'line' per control id."*
            "control_names": {},
            "subjects": [],
            #: Distinct rule DEFINITIONS behind an absence, which is not the same number as the
            #: findings. Jason, 2026-11-03: *"the number of rules should be the number of rule
            #: objects in the device group without an antivirus rule. Findings should count the
            #: number of times those rules materialize on the Firewall and Virtual Systems."*
            #: Measured on PAN-AVW-001: Panorama Shared holds TWO rules with no antivirus
            #: profile and they materialise FOURTEEN times, once on each of seven virtual
            #: systems. Saying 14 rules there would be wrong twice over - there are two, and
            #: attaching a profile to each is two edits, not fourteen.
            "rule_names": set(),
        })
        for line in managed_from:
            if line not in row["managed_from"]:
                row["managed_from"].append(line)
        row["defined_in"].add(defined_in)
        if subject is not None and subject not in row["subjects"]:
            row["subjects"].append(subject)
        row["findings"] += 1
        row["rule_names"].add(getattr(kind.subject_of(finding), "name", ""))
        row["points"].update(_reach_of(kind.subject_of(finding)))
        row["severities"].add(finding.severity)
        row["by_severity"][finding.severity] += 1
        row["control_names"][control.control_id] = control.name
        row["authority"].add(_authority(placed_on, entry_row))
        for query_name in finding.matched_query_names or []:
            row["matched"].add(query_name)
            for field in asserted_by_query.get(query_name, ()):
                # THE MARK ONLY. The field the query asserts used to be printed as a column of
                # its own - the setting at fault, in the findings tab's words - and Jason,
                # 2026-11-04: *"I do not need a column for 'the setting at fault'."* What it
                # said is still said, by the amber on the cell that holds the failing value.
                column = headings.get(field, "")
                if column:
                    row["at_fault"].add(column)
                    row["at_fault_by"].setdefault(column, set()).add(control.control_id)

    rows = []
    for row in grouped.values():
        subjects_here = row.pop("subjects")
        worst = max(row["severities"], key=lambda severity: SEVERITY_RANK[severity])
        if not subjects_here:
            values = [(heading, []) for heading, _read, _field in columns]
        else:
            readings = []
            for subject in subjects_here:
                subject_ct = ContentType.objects.get_for_model(type(subject)).pk
                provenance_of = _provenance_of(subject, provenance, subject_ct)
                readings.append([read(subject, provenance_of)
                                 for _heading, read, _field in columns])
            values = [(heading, _agreed_lines(column, heading in list_columns))
                      for (heading, _read, _field), column in zip(columns, zip(*readings))]
            # The highlight for a substituted profile row, which the control's own asserted
            # fields cannot place - see `_axes_at_fault`.
            marked = _axes_at_fault(assertion, subjects_here, headings)
            marked |= _path_axes_at_fault(control.control_id, subjects_here, headings)
            for column in marked:
                row["at_fault"].add(column)
                row["at_fault_by"].setdefault(column, set()).add(control.control_id)
        rows.append({
            **row,
            "defined_in": sorted(row["defined_in"]),
            "authority": _agreed_authority(row["authority"]),
            "objects": len(subjects_here),
            "points": sorted(row["points"]),
            "severity": Control.Severity(worst).label,
            "severity_value": worst,
            "matched": sorted(row["matched"]),
            # THE RULE NAMES SURVIVE, not just their count: a group page unions the absences of
            # several controls onto one row, and two controls that fire on overlapping sets of
            # rules would otherwise have their counts added together and report more rules than
            # the estate has.
            "rule_names": sorted(row["rule_names"]),
            "rule_objects": len(row["rule_names"]),
            "at_fault_by": {column: sorted(ids) for column, ids in row["at_fault_by"].items()},
            #: THE CHANGE LINES STAY RAW HERE and become display lines in `_attach_cells`,
            #: because on a group page the line's count is not known until every control's row
            #: for the object has been folded in. Sorted by CONTROL first so a control's lines
            #: are adjacent - within one control that is the same order as sorting by setting,
            #: so the fifty single-control pages are unchanged.
            #: WHAT EACH CONTROL CONTRIBUTED to this row. The badge is the worst severity on the
            #: row and the count is every finding on it, and on a group page those two describe
            #: different things: `(no antivirus profile)` on Local reads `High / 526` while
            #: being 263 high from PAN-AVW-001 and 263 medium from PAN-AVW-002, the same rules
            #: counted once by each question. These make that arithmetic visible on the row.
            #: {control id: {severity: count}}. BY SEVERITY TOO, because a control's own
            #: findings on one row need not agree: PAN-POL-013's `Ingress Internet` is two
            #: medium and one low, and crediting all three to the row's worst is the same
            #: mistake one badge per row made at the next level up.
            "findings_by_control": {control.control_id: dict(row["by_severity"])},
            "severity_by_control": {control.control_id: worst},
            "controls": [control.control_id],
            "values": values,
        })
    rows.sort(key=_row_order)
    # NOT PRUNED FOR A GROUP. The group merges several controls' rows and only then knows what
    # anything marks, so it prunes once after the merge; pruning here would give each control's
    # rows a different column set and the merge would pick one of them arbitrarily.
    if prune:
        _prune_columns(rows)
    return [_attach_cells(row) for row in rows]


def _row_order(row):
    """THE ABSENCES FIRST, then the objects by name (Jason, 2026-11-03).

    Not by finding count, which is what this sorted by when it was built: the largest row on a
    profile page is always an absence, so a count sort put them at the top by accident and then
    interleaved them with the profiles underneath as the counts crossed. The split is real work
    rather than presentation - an absence row says *attach a profile to these rules*, and a
    named row says *change this profile* - so it is stated rather than left to arithmetic.

    Within the absences the biggest job leads, because they are a handful of rows and their
    names are all the same word; the named rows are alphabetical, because a reader of thirty of
    them is looking for one profile by name.

    AND THEN BY PLACE, since one row is one place (2026-11-04): a name defined on three
    firewalls is three rows, and they read together, in a fixed order, rather than in whatever
    order the controls happened to reach them.
    """
    place = (tuple(row["defined_in"]), tuple(row["managed_from"]))
    if row["missing"]:
        return (0, -row["findings"], row["name"]) + place
    return (1, 0, row["name"]) + place


def _prune_columns(rows: list[dict], hide=()) -> None:
    """Drop the value columns this page has nothing to say in (Jason, 2026-11-03).

    A sheet's subject columns belong to the SHEET, not to the page: the security-profile sheet
    describes antivirus, URL filtering, file blocking and the rest through one set of columns,
    so a URL filtering page drew `Decoders not blocking` and `Inline ML not blocking` as a dash
    on all thirty rows, and three more columns reading the single word `none`.

    A COLUMN GOES ONLY IF IT IS BOTH UNMARKED AND UNIFORM - no control on the page ever found
    fault in it, and every row that has a value at all gives the same one. Marked survives
    uniformity, because a column where every profile fails the same way is the point of the
    page: `Every reachable category logged` reads `No` on all thirty URL rows and is exactly
    what PAN-URL-002 is about.

    BLANKS DO NOT COUNT AS A VALUE. An absence row has no object and so no cells, and letting
    its emptiness count as a second value would keep every column on any page that has one.
    """
    if not rows:
        return
    marked = set().union(*(row["at_fault"] for row in rows))
    values: dict = {}
    for row in rows:
        for heading, lines in row["values"]:
            values.setdefault(heading, set())
            if lines:
                values[heading].add("\n".join(lines))
    drop = {heading for heading, seen in values.items()
            if heading not in marked and len(seen) <= 1} | set(hide)
    if not drop:
        return
    for row in rows:
        row["values"] = [(heading, lines) for heading, lines in row["values"]
                         if heading not in drop]


def _attach_cells(row: dict) -> dict:
    """`row["cells"]` - one entry per value column, carrying its own verdict.

    DERIVED LAST AND IN ONE PLACE, because `at_fault` is not final until every finding on the row
    has been read, and on a group page not until every control's row has been folded in. A
    Django template cannot index a dict by a variable key, so the alternative was a template
    filter library for one lookup; this keeps `values` as what the object says and puts the
    marking beside it.
    """
    row["cells"] = [{"heading": heading,
                     "lines": lines,
                     "at_fault": heading in row["at_fault"],
                     "controls": row["at_fault_by"].get(heading, [])}
                    for heading, lines in row["values"]]
    # ONE LINE PER CONTROL - Jason, 2026-11-04: *"There should only be one 'line' per control
    # id."* It used to be one line per SETTING a control asks for, with the control's count and
    # badge carried against its first line and its other lines blank in those two columns; the
    # four columns then only read across on the leading line. A line now reads as one sentence
    # all the way over: this many findings, at this severity, for this control, whose name is
    # this. The counts down the column still add up to the row's own total, because a control's
    # several settings on one object were always one count.
    lines = []
    for control_id in sorted(row["findings_by_control"]):
        severity = row["severity_by_control"].get(control_id)
        lines.append({"control": control_id,
                      "control_name": row["control_names"].get(control_id, ""),
                      "severity": Control.Severity(severity).label if severity else "",
                      #: Carried so the view can put the badge classes on the line, the same way
                      #: it puts them on the row - the Severity column draws one badge per
                      #: control, aligned with that control's line.
                      "severity_value": severity,
                      "count": sum(row["findings_by_control"].get(control_id, {}).values())})
    row["control_lines"] = lines
    return row


def _subjects_for(control, findings, kind, assertion, spec, cache=None):
    """{finding: the object to change}, the name to give its absence, and whose columns to draw.

    For every control but the profile-on-rule ones the object is the finding's own subject and
    the sheet is its own. For those eleven it is the PROFILE the verdict was read from, drawn
    with the security-profile sheet's columns, and None where no profile of that kind reaches
    the rule at all - which is the row that says to attach one.
    """
    path = _path_substitution(control)
    if path is not None:
        # THE JOIN IS A FOREIGN KEY AND NOTHING MORE. The path row already resolved the name the
        # tunnel or the gateway carries, so this reads the object it resolved to - and None where
        # it resolved to nothing, which is the row that says to NAME a profile rather than to
        # harden one.
        field, slug, absent = path
        profile_spec = artifact_domains.DOMAIN_BY_SLUG[slug].spec
        resolved = {finding: getattr(kind.subject_of(finding), field, None)
                    for finding in findings}
        return resolved, absent, profile_spec

    if assertion is None:
        return {finding: kind.subject_of(finding) for finding in findings}, "", spec

    from optivedge_integrations.integrations.models.policy.rules import (
        SecurityRuleProfileVerdict as Verdict)

    profile_kind, noun = _VERDICT_KINDS[assertion]
    rules = [kind.subject_of(finding) for finding in findings]
    verdicts = {verdict.security_rule_id: verdict for verdict in
                Verdict.objects.filter(assertion=assertion,
                                       security_rule__in=[rule.pk for rule in rules])}
    resolved: dict = {}
    # THE INDEX IS PER PROFILE KIND, not per control: two antivirus controls resolve against
    # the same profiles, and loading it twice walked every profile in the estate again.
    profile_spec = artifact_domains.DOMAIN_BY_SLUG["security-profiles"].spec
    prefetch = tuple(profile_spec.subject_prefetch)
    if cache is None:
        index = _profiles_by_name(profile_kind, prefetch)
    else:
        index = cache.get(profile_kind)
        if index is None:
            index = cache[profile_kind] = _profiles_by_name(profile_kind, prefetch)
    for finding in findings:
        rule = kind.subject_of(finding)
        verdict = verdicts.get(rule.pk)
        if verdict is not None and verdict.satisfied is False and verdict.profile_name:
            resolved[finding] = _profile_for(rule, verdict.profile_name, index)
        else:
            resolved[finding] = None
    return resolved, f"(no {noun} profile)", profile_spec


def _provenance_of(subject, index, content_type_id):
    """The bulk-loaded provenance row for a field, or the model's own answer for a computed one.

    The same closure `build_rows` hands a subject column, built the same defensive way: a model
    that is not provenanced has no `DERIVED_FIELDS` attribute and no rows, and "no row" is the
    honest answer for it rather than a crash.
    """
    from optivedge_integrations.integrations.models.provenance import FieldProvenance

    def provenance_of(field):
        row = index.get((content_type_id, subject.pk, field))
        if row is None and field in getattr(type(subject), "DERIVED_FIELDS", ()):
            return FieldProvenance(provenance_type=FieldProvenance.ProvenanceType.DERIVED)
        return row

    return provenance_of


def fold_is_complete(control: Control, rows) -> bool:
    """Every finding reached a row. The fold may make rows fewer, never findings."""
    kind = _kind_for(control.control_type)
    return sum(row["findings"] for row in rows) == kind.model.objects.filter(
        control=control).count()


def _worse(left: str, right: str) -> str:
    return left if SEVERITY_RANK[left] >= SEVERITY_RANK[right] else right


def _absorb(held: dict, row: dict) -> None:
    """Fold one control's row for an object into the row already held for it.

    COUNTS ADD AND SETS UNION, and the difference matters in both directions. `findings` adds,
    because a profile that fails two controls carries both findings and clearing it clears both.
    `points` and `rule_names` UNION, because the same profile is in force in the same places
    whichever question was asked of it, and adding those would report an estate twice its size.
    """
    held["findings"] += row["findings"]
    held["points"] = sorted(set(held["points"]) | set(row["points"]))
    held["defined_in"] = sorted(set(held["defined_in"]) | set(row["defined_in"]))
    for line in row["managed_from"]:
        if line not in held["managed_from"]:
            held["managed_from"].append(line)
    held["severities"] = held["severities"] | row["severities"]
    held["by_severity"] = collections.Counter(held["by_severity"]) + collections.Counter(
        row["by_severity"])
    held["severity_value"] = _worse(held["severity_value"], row["severity_value"])
    held["severity"] = Control.Severity(held["severity_value"]).label
    held["matched"] = sorted(set(held["matched"]) | set(row["matched"]))
    held["at_fault"] = held["at_fault"] | row["at_fault"]
    for column, ids in row["at_fault_by"].items():
        held["at_fault_by"][column] = sorted(set(held["at_fault_by"].get(column, ())) | set(ids))
    held["control_names"].update(row["control_names"])
    held["authority"] = _agreed_authority({held["authority"], row["authority"]})
    for control_id, counts in row["findings_by_control"].items():
        kept = held["findings_by_control"].setdefault(control_id, {})
        for severity, count in counts.items():
            kept[severity] = kept.get(severity, 0) + count
    for control_id, severity in row["severity_by_control"].items():
        current = held["severity_by_control"].get(control_id)
        held["severity_by_control"][control_id] = (
            severity if current is None else _worse(current, severity))
    held["rule_names"] = sorted(set(held["rule_names"]) | set(row["rule_names"]))
    held["rule_objects"] = len(held["rule_names"])
    held["objects"] = max(held["objects"], row["objects"])
    for control_id in row["controls"]:
        if control_id not in held["controls"]:
            held["controls"].append(control_id)
    # THE CELLS ARE THE SAME OBJECT'S EITHER WAY, read through the same sheet - so the only case
    # to settle is a row that HAS them meeting one that does not, which is an absence row from
    # one control meeting a named row from another. Keeping whichever is populated is right for
    # that and a no-op for every other row.
    if not any(lines for _heading, lines in held["values"]):
        held["values"] = row["values"]


def _group_key(row):
    """What makes two controls' rows the same object - the key `remediation_rows` folds on.

    THE OBJECT AND ITS PLACE, for a named object and for an absence alike: two controls fire on
    the same definition only if they fire on the same thing in the same place. `(no antivirus
    profile)` on one device group is not the same job as on another, and neither is the zone
    `Private` on one firewall and on the next.
    """
    return row["name"], tuple(row["managed_from"]), tuple(row["defined_in"])


def _normalised(label: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (label or "").lower())


def group_screen(group: RemediationGroup) -> str:
    """The product's own screen for this object, as the index's sub-heading.

    READ OFF THE RAIL, which already states the vendor's path per object - `Device > Setup >
    Management > Minimum Password Complexity`, `Network > GlobalProtect > Portals`. Jason's
    Panorama screenshot, 2026-11-04, is what settled the GRANULARITY: `Setup` is a screen of
    tabs and each tab a page of panels, so the rail's own heading ("Setup") is too coarse to
    group by and the path's third segment is the tab a reader opens.

    The heading is the path with its leaf dropped, capped at three segments: a four-segment
    path keeps three (`Device > Setup > Management`), a three-segment path keeps two
    (`Objects > Security Profiles`), and a two-segment path is already a screen
    (`Device > Administrators`, `Network > Zones`) and is kept whole. Many of the Device
    families ARE their own rail item and land under their own heading, which is right.

    ONE MODEL CAN HAVE SEVERAL RAIL ENTRIES - `SecurityProfile` has eight, one per profile
    kind - so the group's label picks among them before the path is read.
    """
    kind = _kind_for(group.subject_type)
    model = kind.model._meta.get_field(kind.subject_field).related_model
    label = f"integrations.{model.__name__}"
    candidates = [entry for entry in config_nav.CONFIG_OBJECTS
                  if entry.search_model == label]
    wanted = _normalised(group.label)
    chosen = next((entry for entry in candidates
                   if _normalised(entry.label) and (_normalised(entry.label) in wanted
                                                    or wanted in _normalised(entry.label))),
                  candidates[0] if candidates else None)
    segments = [part.strip() for part in (chosen.where if chosen else "").split(" > ")
                if part.strip()]
    # A SUBJECT THE PRODUCT HAS NO SCREEN FOR still needs a heading: `ApplianceOperationalMode`
    # is "shown in the status bar; set from maintenance mode", which is prose and not a path.
    if len(segments) < 2:
        return f"{group_category(group)} > Other"
    if len(segments) == 2:
        return " > ".join(segments)
    if len(segments) == 3:
        return " > ".join(segments[:2])
    return " > ".join(segments[:3])


def group_controls(group: RemediationGroup) -> list:
    """The group's controls, in the order the group names them, skipping any not in the catalog.

    THE QUERIES COME WITH THEM. `_verdict_assertion`, `_asserted_fields` and `setting_columns`
    each walk `control.queries.all()`, and on an unprefetched instance that is a round trip per
    call: measured on the zone page, 27 of its 34 queries were `assessments_controlquery`, and
    on the security-rule page 830 of 1,052. Prefetching caches the rows on the instance, so the
    walk is free after the first - and the cache lives exactly as long as this list does, which
    keeps a control edited mid-process from being answered out of a stale global.
    """
    found = {control.control_id: control for control in Control.objects.filter(
        control_id__in=group.control_ids, is_active=True).prefetch_related("queries")}
    return [found[control_id] for control_id in group.control_ids if control_id in found]


def group_columns_spec(controls):
    """The ONE sheet a group page's value columns come from.

    WHY A GROUP HAS TO CHOOSE. Each control's rows were drawn with its OWN sheet's columns, and
    sixteen controls over the security rulebase are not all drawn on one tab: PAN-AVW-003 is on
    `WildFire Analysis (by rule)` and the fifteen PAN-POL controls on `Security Rules`. The
    merge then produced rows of two different shapes on one page - measured on the lab, 1,006
    rows with nine columns and 29 with twenty-three - and the header row is one row's headings,
    so the twenty-three-column rows ran fourteen cells past the end of the table. One page, one
    vocabulary.

    THE SHEET THAT DESCRIBES MOST OF THE GROUP IS THE ONE, counted after substitution (a
    profile-on-rule control is drawn with the security-profile sheet, whatever tab its own
    findings land on). Ties go to the sheet with more to say about the object, then to its title
    so the answer does not move between runs. On the eleven groups built today the count is
    never close: fifteen of sixteen for `Security Rules`, and unanimous everywhere else.
    """
    counted: dict = {}
    for control in controls:
        spec = domain_spec_for(control)
        if spec is None:
            continue
        if _verdict_assertion(control) is not None:
            spec = artifact_domains.DOMAIN_BY_SLUG["security-profiles"].spec
        else:
            path = _path_substitution(control)
            if path is not None:
                spec = artifact_domains.DOMAIN_BY_SLUG[path[1]].spec
        held = counted.setdefault(spec.sheet_title, [spec, 0])
        held[1] += 1
    if not counted:
        return None
    return max(counted.values(),
               key=lambda held: (held[1], len(value_columns(held[0], controls)),
                                 held[0].sheet_title))[0]


def fold_group_rows(group: RemediationGroup) -> list[dict] | None:
    """The group's rows in ONE PASS over its findings - the same rows, at a fraction of the cost.

    WHAT THE PER-CONTROL PATH SPENDS. `remediation_group_rows` folds each control separately and
    merges, so a group's controls each load their own copy of the same subjects and each read
    every value column again. Measured on the security-rule group, 2026-11-04: 8.4s wall for
    1,035 rows, of which SQL is 1% - 175,930 model instantiations and 213,000 queryset
    iterations, because sixteen controls instantiate the same 1,035 rules sixteen times and
    `profiles_in_force` runs 4,647 times to fill 1,035 rows. About 1ms and 22KB of heap per
    FINDING, both linear, and findings are what a real estate multiplies.

    WHAT THIS DOES INSTEAD. One query per finding MODEL covering every control at once; one
    provenance index; one content-type lookup per model; and each subject's columns, name and
    placement read ONCE and reused by every finding and every control that lands on it.

    WHY IT IS NOT YET THE ONLY PATH. It does not handle a SUBSTITUTED control - the
    profile-on-rule eleven, whose object is not the finding's own subject and which can produce
    a row for an object that is absent - and it reads a row's values from every subject folded
    onto it, where the merge keeps the first control's reading. It RETURNS None for a group it
    cannot answer identically, and the caller falls back. Zone is the first page to use it
    (Jason, 2026-11-04: *"implement the recommendations only for the zone page"*).
    """
    controls = group_controls(group)
    if not controls:
        return None
    spec = group_columns_spec(controls)
    if spec is None:
        return None
    findings = _findings_of_controls(controls, spec)
    if not findings:
        return []

    by_pk = {control.pk: control for control in controls}
    by_id = {control.control_id: control for control in controls}
    kinds = {control.pk: _kind_for(control.control_type) for control in controls}
    assertions = {control.pk: _verdict_assertion(control) for control in controls}

    # THE SUBSTITUTED CONTROLS RESOLVE ONCE EACH. `_subjects_for` answers per control - it reads
    # that control's verdicts - but the profile INDEX it resolves against is the same for every
    # control of one profile kind, and loading it per control was two passes over every profile
    # in the estate on the antivirus page.
    held: dict = {}
    for control in controls:
        rows_of = [finding for finding in findings if finding.control_id == control.pk]
        held[control.pk] = _subjects_for(
            control, rows_of, kinds[control.pk], assertions[control.pk],
            domain_spec_for(control), cache=held.setdefault("__profiles__", {}))
    missing_for = {pk: answer[1] for pk, answer in held.items() if pk != "__profiles__"}
    subjects = {}
    for pk, answer in held.items():
        if pk != "__profiles__":
            subjects.update(answer[0])

    # INDEXED OVER BOTH the resolved objects and the rules a row is PLACED on where no object
    # exists - an absence row's plane comes from the rule's own entry provenance.
    placed = {finding: (subjects[finding] if subjects[finding] is not None
                        else kinds[finding.control_id].subject_of(finding))
              for finding in findings}
    provenance = provenance_index(
        {subject for subject in subjects.values() if subject is not None}
        | set(placed.values()))
    asserted = _asserted_fields(controls)
    columns = value_columns(spec, controls)
    headings = _headings_by_field(spec, columns)
    list_columns = _axis_columns(headings)
    name_of = _name_reader(spec)

    # EACH SUBJECT READ ONCE, keyed by the object rather than by the finding: the readings are
    # what the per-control path pays for again per control, and they describe the object.
    by_type: dict = {}
    readings: dict = {}
    names: dict = {}
    placement: dict = {}
    entries: dict = {}

    def read_key(subject):
        # BY MODEL AND PRIMARY KEY, never by `id()`: a select_related join hands back equal but
        # distinct instances for the same row, so `set(...)` keeps one of them and an identity
        # key then misses for every finding holding another. The content type is in the key
        # because two models can share a primary key.
        content_type_id = by_type.setdefault(
            type(subject), ContentType.objects.get_for_model(type(subject)).pk)
        return (content_type_id, subject.pk)

    drawn = {subject for subject in subjects.values() if subject is not None}
    # PLACEMENT FOR EVERY OBJECT A ROW SITS ON, cells only for the ones the page DRAWS. An
    # absence row is placed on the RULE that lacks a profile, and the page's columns are the
    # profile's - asking a rule for `get_kind_display` raises.
    for subject in drawn | set(placed.values()):
        content_type_id, _pk = read_key(subject)
        key = (content_type_id, subject.pk)
        provenance_of = _provenance_of(subject, provenance, content_type_id)
        entry_row = provenance.get((content_type_id, subject.pk, "__entry__"))
        placement[key] = (_where(subject, entry_row), _authority(subject, entry_row))
        entries[key] = entry_row
        if subject in drawn:
            readings[key] = [read(subject, provenance_of)
                             for _heading, read, _field in columns]
            names[key] = name_of(subject, provenance_of)

    grouped: dict = {}
    field_placement: dict = {}
    for finding in findings:
        control = by_pk[finding.control_id]
        subject = subjects[finding]
        on = placed[finding]
        key = read_key(on if subject is None else subject)
        (managed_from, defined_in), authority = placement[key]
        if subject is None:
            # THE ABSENCE HAS NO OBJECT, so the row is placed by the RULE that lacks one and
            # named for what is missing. A pushed rule's absence belongs to its device group,
            # read on Panorama; a local one has no container at all.
            entry_row = entries[key]
            if entry_row is not None and entry_row.provenance_type == "device_group":
                managed_from = _panorama_of(on)
                defined_in = entry_row.raw_value or "shared"
            else:
                defined_in = ""
        # NO ENTRY OF ITS OWN: the authority is a property of the FIELDS this finding is about,
        # not of the object - see `_field_placement`. Cached per subject and per asserted field
        # set, because several findings of one control land on the same answer.
        if authority == AUTHORITY_UNRECORDED:
            fields = frozenset(
                field
                for query_name in (finding.matched_query_names or [])
                for field in asserted.get(control.pk, {}).get(query_name, ()))
            # ONLY WHERE THERE IS AN OBJECT TO READ THEM OFF. An absence row has none - the
            # finding is that nothing resolves - and its placement came from the subject the row
            # is PLACED on, two branches above. Reading fields off `None` is how the first
            # path-substituted page crashed.
            if fields and subject is not None:
                cached = field_placement.get((key, fields), False)
                if cached is False:
                    cached = _field_placement(subject, provenance, key[0], fields)
                    field_placement[(key, fields)] = cached
                if cached is not None:
                    managed_from, defined_in, authority = cached
        if group.shape == "posture":
            # THE ROW IS A VIRTUAL SYSTEM, not an object: there is nothing to open and nothing
            # to name but the place itself, so the vsys is the row's identity and the
            # container column is empty.
            name = _vsys_of(subject if subject is not None else on)
            defined_in = ""
        elif subject is None:
            name = missing_for[control.pk]
        else:
            name = names[key]
        # GROUPED ON `Edit on`, `Authority` AND `Location` TOGETHER (Jason, 2026-11-04). The
        # authority is in the key because a singleton's settings can be local, pushed and unset
        # in the same object, and those are three different errands even where two of them are
        # made on the same box.
        row = grouped.setdefault((name, tuple(managed_from), defined_in, authority), {
            "managed_from": list(managed_from),
            "defined_in": {defined_in},
            "name": name,
            "missing": subject is None,
            "findings": 0,
            "points": set(),
            "severities": set(),
            "by_severity": collections.Counter(),
            "matched": set(),
            "at_fault": set(),
            "at_fault_by": {},
            "authority": set(),
            "control_names": {},
            "subjects": [],
            "rule_names": set(),
            "findings_by_control": {},
            "severity_by_control": {},
            #: A set here and a LIST in catalogue order on the way out: the per-control path
            #: appends as it folds each control in turn, which is the group's own order, and a
            #: one-pass walk meets them in whatever order the findings arrive.
            "controls": set(),
            #: Per control, so `objects` stays what the merge made it - the LARGEST number of
            #: objects any ONE control saw on this row, not the size of the union.
            "objects_by_control": {},
        })
        if subject is not None and subject not in row["subjects"]:
            row["subjects"].append(subject)
        row["objects_by_control"].setdefault(control.control_id, set()).add(
            subject.pk if subject is not None else None)
        row["findings"] += 1
        #: THE FINDING'S OWN SUBJECT for both, which for a substituted control is the RULE
        #: even where a profile was resolved: `rule_objects` counts the definitions behind the
        #: row - two rules naming one profile is two edits' worth of reach - and the places a
        #: row is in force are the places those rules run.
        own_subject = kinds[finding.control_id].subject_of(finding)
        row["rule_names"].add(getattr(own_subject, "name", ""))
        row["points"].update(_reach_of(own_subject))
        row["severities"].add(finding.severity)
        row["by_severity"][finding.severity] += 1
        row["control_names"][control.control_id] = control.name
        row["authority"].add(authority)
        row["controls"].add(control.control_id)
        counts = row["findings_by_control"].setdefault(control.control_id, {})
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        current = row["severity_by_control"].get(control.control_id)
        row["severity_by_control"][control.control_id] = (
            finding.severity if current is None else _worse(current, finding.severity))
        for query_name in finding.matched_query_names or []:
            row["matched"].add(query_name)
            for field in asserted.get(control.pk, {}).get(query_name, ()):
                column = headings.get(field, "")
                if column:
                    row["at_fault"].add(column)
                    row["at_fault_by"].setdefault(column, set()).add(control.control_id)

    rows = []
    for row in grouped.values():
        subjects_here = row.pop("subjects")
        objects_by_control = row.pop("objects_by_control")
        worst = max(row["severities"], key=lambda severity: SEVERITY_RANK[severity])
        if not subjects_here:
            # AN ABSENCE HAS NO CELLS. There is no profile to describe, and a row of dashes
            # would read as "measured and empty" rather than "there is nothing here".
            values = [(heading, []) for heading, _read, _field in columns]
            # AND NO CELL TO FAULT, which the shipped antivirus page already reads this way -
            # its `(no antivirus profile)` rows carry no mark at all. The asserted-field fill
            # above lands by FIELD NAME, and the nine path-keyed controls assert fields that
            # exist on the profile sheet under the same names, so without this an absence row
            # would highlight an EMPTY cell and tell an engineer to change it. What that row
            # says is in its name: name a profile.
            row["at_fault"] = set()
            row["at_fault_by"] = {}
        else:
            held = [readings[read_key(subject)] for subject in subjects_here]
            values = [(heading, _agreed_lines(column, heading in list_columns))
                      for (heading, _read, _field), column in zip(columns, zip(*held))]
            # The highlight for a substituted profile row, which the control's own asserted
            # fields cannot place - see `_axes_at_fault`.
            for control_id in row["controls"]:
                axes = _axes_at_fault(assertions[by_id[control_id].pk], subjects_here, headings)
                axes |= _path_axes_at_fault(control_id, subjects_here, headings)
                for column in axes:
                    row["at_fault"].add(column)
                    row["at_fault_by"].setdefault(column, set()).add(control_id)
        rows.append({
            **row,
            "defined_in": sorted(row["defined_in"]),
            "authority": _agreed_authority(row["authority"]),
            "objects": len(subjects_here),
            "points": sorted(row["points"]),
            "severity": Control.Severity(worst).label,
            "severity_value": worst,
            "matched": sorted(row["matched"]),
            "rule_names": sorted(row["rule_names"]),
            "rule_objects": len(row["rule_names"]),
            "at_fault_by": {column: sorted(ids) for column, ids in row["at_fault_by"].items()},
            "controls": [control.control_id for control in controls
                         if control.control_id in row["controls"]],
            "values": values,
        })
    rows.sort(key=_row_order)
    _prune_columns(rows, hide=group.hide_columns)
    return [_attach_cells(row) for row in rows]


def remediation_group_rows(group: RemediationGroup) -> list[dict]:
    """One row per object DEFINITION over every control in the group.

    Built by folding each control's own rows rather than by a second query path, so a group page
    and the control pages behind it cannot describe one object two ways - the whole argument for
    reading the value columns off the sheet, applied one level up.
    """
    if group.one_pass:
        folded = fold_group_rows(group)
        if folded is not None:
            return folded
    merged: dict = {}
    controls = group_controls(group)
    columns_spec = group_columns_spec(controls)
    for control in controls:
        for row in remediation_rows(control, columns_controls=controls, prune=False,
                                    columns_spec=columns_spec):
            key = _group_key(row)
            held = merged.get(key)
            if held is None:
                merged[key] = row
            else:
                _absorb(held, row)
    rows = list(merged.values())
    rows.sort(key=_row_order)
    _prune_columns(rows, hide=group.hide_columns)
    # RE-DERIVED AFTER THE MERGE, not carried over from the control rows: a cell marked by the
    # second control is not marked on the first control's row.
    return [_attach_cells(row) for row in rows]


#: What a stored row carries. The page and the view read these and nothing else, so the stored
#: form is the drawn form rather than a second shape that has to be rebuilt into one. Sets and
#: counters are not JSON, and none of the three that exist on a live row - `severities`,
#: `at_fault`, `by_severity` - is read after `_attach_cells` has run.
_STORED_ROW_KEYS = (
    "managed_from", "defined_in", "name", "missing", "findings", "points", "authority",
    "severity", "severity_value", "rule_objects", "objects", "controls",
    "findings_by_control", "severity_by_control", "cells", "control_lines",
)


def _stored_row(row: dict) -> dict:
    return {key: row[key] for key in _STORED_ROW_KEYS}


def stored_group_rows(group: RemediationGroup, *, allow_running: bool = False) -> list[dict]:
    """The group's rows, kept for the run they describe rather than folded on every read.

    THE SAME THREE THINGS A FINDINGS TAB'S TABLE IS A FUNCTION OF - the run, the catalog and
    `layout_version()` - so a remediation page keeps its table the same way and under the same
    fingerprint rules: an edited control, an edited column or an edited layout misses and is
    rebuilt, and nothing is kept for a run still filling. Measured on the antivirus page: 700ms
    to fold, 20ms to decode.

    `allow_running` is how the RUN ITSELF stores these - see `artifacts.stored.store_run_tables`.
    The rule it waives exists for readers: a page opened mid-run would otherwise keep a table of
    half the findings. The run's own last step is past every generator, so its findings are
    complete even though the row still says RUNNING.

    Falls back to folding where there is no single run to keep a table for.
    """
    from assessments.artifacts.stored import stored_table

    controls = group_controls(group)
    if not controls:
        return []
    runs, count = set(), 0
    for control in controls:
        model = _kind_for(control.control_type).model
        runs.update(model.objects.filter(control=control)
                    .values_list("assessment_run_id", flat=True).distinct())
        count += model.objects.filter(control=control).count()
    run_id = runs.pop() if len(runs) == 1 else None

    def compute():
        rows = remediation_group_rows(group)
        return {"count": sum(row["findings"] for row in rows),
                "rows": [_stored_row(row) for row in rows]}

    payload = stored_table(f"Remediation:{group.slug}", controls, run_id, count, compute,
                           allow_running=allow_running)
    if payload is None:
        return [_stored_row(row) for row in remediation_group_rows(group)]
    return payload["rows"]


def group_fold_is_complete(group: RemediationGroup, rows) -> bool:
    """Every finding of every control in the group reached a row."""
    total = 0
    for control in group_controls(group):
        total += _kind_for(control.control_type).model.objects.filter(control=control).count()
    return sum(row["findings"] for row in rows) == total


def remediation_index() -> list[dict]:
    """The index's rows: one per control, except that a group's controls are ONE row.

    Both shapes carry `title`, `summary`, `findings` and `by_severity`, so the page
    draws them the same way and nothing on it has to know which it is looking at.
    """
    rows, by_group = [], {}
    for row in remediation_controls():
        control = row["control"]
        group = GROUP_BY_CONTROL_ID.get(control.control_id)
        if group is None:
            # GROUPS ONLY. Jason, 2026-11-03: *"We're moving away from the per-control
            # remediation page"*, then *"remove the indexes ... except for Antivirus profile,
            # in preparation for object-oriented pages we're about to build."* A control no
            # group covers has no page and no row - it arrives here when its object group is
            # declared in `REMEDIATION_GROUPS`, and not before.
            #
            # SO THIS INDEX DOES NOT COUNT THE ESTATE. It counts what this surface answers
            # today: 2,049 of the lab's 16,533 remediation findings while the antivirus group
            # is the only one built. The findings surfaces remain the place that counts
            # everything.
            continue
        held = by_group.get(group.slug)
        if held is None:
            held = by_group[group.slug] = {
                "title": group.label,
                "summary": group.summary,
                "category": group_category(group),
                "screen": group_screen(group),
                "control_type": group.subject_type,
                "findings": 0,
                "by_severity": {},
                "url_name": "assessment_remediation_group",
                "url_arg": {"slug": group.slug},
            }
            rows.append(held)
        held["findings"] += row["findings"]
        for severity, count in row["by_severity"].items():
            held["by_severity"][severity] = held["by_severity"].get(severity, 0) + count

    for row in rows:
        worst = max(row["by_severity"], key=lambda severity: SEVERITY_RANK[severity])
        row["severity"] = Control.Severity(worst).label
        row["severity_value"] = worst
    # BY PAN-OS CATEGORY, then by the object's own name - Jason, 2026-11-04: *"Organize
    # /assessments/remediation/ in similar fashion to /assessments/findings/ using Policies,
    # Objects, Network, Device categories."* The index used to section by SUBJECT KIND, which
    # put "Security profile" and "Security rule" headings over rows that already name their
    # object in the first column; the category says something the rows do not, and it is the
    # heading the findings summary and the workbook's Summary tab already use.
    rows.sort(key=lambda row: (config_nav.CATEGORIES.index(row["category"]),
                               row["screen"], row["title"]))
    return rows
