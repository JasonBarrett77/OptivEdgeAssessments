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

Each object links to its FINDINGS page, which is a SIBLING and not a predecessor: that page
reports what the controls found, and these pages ask the configuration a question and show
what matches. Both surfaces stay. The link is DERIVED from `search_model` - see
`artifacts.domains.domain_for_model` - rather than named here, so a rail item cannot point at
a page that no longer exists and a new domain is linked the day it exists.

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
    # Policies > Security, second rail item, 2026-11-01, for the five PAN-POL controls whose
    # subject is the virtual system's WHOLE policy rather than any rule in it - no catch-all
    # refusal, no application block above the permits, nothing about geography.
    #
    # WHY IT IS ON THE RAIL AT ALL, since every column of the model is a verdict this assessment
    # computes and the rail is "the promise about what can be asked" of a firewall. The subject
    # is a PAN-OS node: one virtual system's `rulebase/security/rules`, which an assessor opens
    # at this address and reads. What the model holds is our reading of that node, the way
    # `has_antivirus_profile` is our reading of a rule's profile-setting - and the rail item
    # promises the NODE, not the reading. Contrast Normalization Coverage, which is off the rail
    # and carries an explicit sheet category instead: its subject is our own record of an object
    # that failed to build, and there is no address on a firewall where an assessor could go and
    # look at it. The test is whether the subject HAS a vendor path; this one does and that one
    # does not.
    #
    # A SECOND ITEM RATHER THAN A SECOND MODEL ON `security`, because an engineer fixes one or
    # the other: a rule's own settings are edited in the rule, and everything here is fixed by
    # ADDING a rule that is not there. `objects_for_model` already allows two items over one
    # model; this is the reverse - two items over two models at one vendor address.
    ConfigObject("rule-posture", "Rulebase Posture", "Policies", "", "shield",
                 where="Policies > Security",
                 search_model="integrations.VsysRulePosture"),
    # Policies > Security, THIRD rail item, 2026-11-02, for PAN-IOT-004 - whose subject is also
    # the virtual system's whole rule set, read for one dimension: whether any rule that PERMITS
    # traffic matches on what the connecting device IS.
    #
    # FOLLOWING `rule-posture` ABOVE RATHER THAN INVENTING A PATTERN, and its reasoning block
    # applies here unchanged. The subject is a PAN-OS node - one virtual system's
    # `rulebase/security/rules` - which an assessor opens at this address and reads; the model
    # holds OUR READING of that node; the rail item promises the node and not the reading. The
    # test that block states is whether the subject HAS a vendor path, and this one has the same
    # path `rule-posture` does.
    #
    # A THIRD ITEM RATHER THAN A SECOND MODEL ON `rule-posture`, by that entry's own argument
    # that an engineer fixes one or the other. Everything on `rule-posture` is fixed by ADDING a
    # rule that refuses something; everything here is fixed by adding the device DIMENSION to
    # rules that already exist - or, where the count of visible device objects is zero, by
    # defining the objects a rule could name at all. Two different pieces of work.
    #
    # THE LABEL IS OURS AND THE VENDOR'S WORDS ARE IN IT. Help p.128 names the two rule fields
    # that take a device object "Source Device" and "Destination Device", in Building Blocks in
    # a Security Policy Rule. The vendor has no name for the ABSENCE of both across a whole rule
    # set, which is what this item is about, so "Device-ID Policy Match" is a proposal.
    ConfigObject("rulebase-device-match", "Device-ID Policy Match", "Policies", "", "shield",
                 where="Policies > Security",
                 search_model="integrations.RulebaseDeviceMatchVerdict"),
    # Policies > DoS Protection, 2026-11-02, for PAN-ZON-007 - the DoS rulebase's own rows.
    #
    # LAST IN Policies AND NOT BESIDE THE THREE ABOVE, which is the product's order rather than
    # ours: PAN-OS's Policies rail runs Security, NAT, QoS, Policy Based Forwarding, Decryption,
    # Network Packet Broker, Tunnel Inspection, Application Override, Authentication, DoS
    # Protection, SD-WAN - so the DoS rulebase sits at the tail, after everything this report
    # already has an item for. The three items above are all at Policies > Security; this is a
    # different screen and a different rulebase.
    #
    # ITS SUBJECT IS A PAN-OS NODE, which is the test this module states for being on the rail:
    # one virtual system's `rulebase/dos/rules`, which an assessor opens at this address and
    # reads. A rule's identity includes its POSITION - a rulebase resolves by order and not by
    # name - which is why the results page prints the position beside the name.
    #
    # THE SLUG SAYS `-rules` AND THE REASON IS MECHANICAL: `configuration_results.RESULTS` is
    # keyed on the slug ALONE, while `CONFIG_OBJECTS_BY_KEY` is keyed on (category, slug). So
    # the DoS PROFILE item below could not also be `dos-protection` without one of the two
    # results specs shadowing the other. The label is the vendor's own rail word for both.
    ConfigObject("dos-protection-rules", "DoS Protection", "Policies", "", "shield",
                 where="Policies > DoS Protection",
                 search_model="integrations.DosPolicyRule"),
    # Objects > Addresses, 2026-10-02. Turned on for the PAN-COV coverage controls, which query
    # address objects: every control query must have a results page, and a query with nowhere to
    # go is one an assessor cannot check.
    ConfigObject("addresses", "Addresses", "Objects", "", "list-checks",
                 where="Objects > Addresses",
                 search_model="integrations.AddressObject"),
    # Objects > Custom Objects > URL Category, 2026-11-02, for PAN-URL-006 - a NEW GROUP, and the
    # first rail item over `integrations.CustomUrlCategory`, which stage 7 minted for this domain
    # and which had never been queried from this repository at all.
    #
    # WHY IT IS ON THE RAIL, by `rule-posture`'s own test: does the subject HAVE a vendor path?
    # It does - `Objects > Custom Objects > URL Category` is a real PAN-OS screen an assessor can
    # open, and the Categories tab of a URL Filtering profile lists these entries under its own
    # "Custom URL Categories" drop-down (Web Interface Help 11.2 p.296, verbatim). So the item
    # promises a node that exists. Contrast Normalization Coverage, which is off the rail with an
    # explicit sheet category because its subject is our own record of a failed build.
    #
    # THE GROUP SITS BEFORE `Security Profiles`, WHICH IS THE PRODUCT'S OWN ORDER: PAN-OS lists
    # Custom Objects above Security Profiles in the Objects tree. Placing it here inserts a new
    # group ahead of an existing one and REARRANGES NO EXISTING ITEM relative to any other, which
    # is the line `dos-protection` and `file-blocking` both drew - they declined to reorder the
    # four older profile items among themselves, which is a different thing from putting a new
    # group where the vendor puts it. `group`s render in the order their first object appears.
    #
    # IT DECLARES NO `scope`, and that is required rather than tidy: its model has exactly ONE
    # page, so `object_for_canonical_query` short-circuits on the single candidate and a scope
    # would be dead weight a later second page would have to reckon with. Same call as
    # `data-filtering-posture`.
    ConfigObject("custom-url-categories", "URL Category", "Objects", "Custom Objects",
                 "list-checks", where="Objects > Custom Objects > URL Category",
                 search_model="integrations.CustomUrlCategory"),
    # Objects > Security Profiles - the first Objects items, 2026-09-11. PAN-OS lists each profile
    # type as its own rail child, and so does this: two items over one model, split by kind in
    # configuration_results, each backed by a completed control.
    ConfigObject("anti-spyware", "Anti-Spyware", "Objects", "Security Profiles", "shield",
                 where="Objects > Security Profiles > Anti-Spyware",
                 search_model="integrations.SecurityProfile"),
    ConfigObject("vulnerability-protection", "Vulnerability Protection", "Objects",
                 "Security Profiles", "shield",
                 where="Objects > Security Profiles > Vulnerability Protection",
                 search_model="integrations.SecurityProfile"),
    ConfigObject("antivirus", "Antivirus", "Objects", "Security Profiles", "shield",
                 where="Objects > Security Profiles > Antivirus",
                 search_model="integrations.SecurityProfile"),
    # Objects > Security Profiles > URL Filtering, 2026-11-02, for PAN-URL-001 to -005 - the
    # EIGHTH rail item over `SecurityProfile`, and ONE item for five controls rather than five:
    # all five carry `kind eq "url-filtering"` and nothing else, so they share one page.
    #
    # PLACED IN THE VENDOR'S OWN ORDER, which the `file-blocking` block below enumerates from the
    # product: Antivirus, Anti-Spyware, Vulnerability Protection, URL FILTERING, File Blocking,
    # WildFire Analysis, Data Filtering, DoS Protection. So URL Filtering sits immediately before
    # File Blocking. The three items above it are not themselves in the vendor's order - that is
    # older and is not this entry's to rearrange, which is the judgement `dos-protection` made
    # for itself and `file-blocking` repeated.
    #
    # ITS SCOPE IS EXACTLY ONE `kind eq` CLAUSE AND NOTHING LOOSER, for the reason the
    # `dos-protection` block below states at length: `object_for_canonical_query` keeps every
    # candidate whose own scope clauses are a SUBSET of the query's and answers only when exactly
    # one matched, so a scope of {} would be a subset of EVERY query over this model and would
    # push ALL EIGHT kinds to None. The seven pages that already work are what a wrong scope here
    # breaks, which is why `tests/test_url_filtering_presentation.py` asserts all eight resolve
    # rather than only the one that is new.
    ConfigObject("url-filtering", "URL Filtering", "Objects", "Security Profiles", "shield",
                 where="Objects > Security Profiles > URL Filtering",
                 search_model="integrations.SecurityProfile"),
    # Objects > Security Profiles > File Blocking, 2026-11-02, for PAN-FIL-001, -002 and -004 -
    # the SIXTH rail item over `SecurityProfile`, with `data-filtering` below the seventh.
    #
    # PLACED IN THE VENDOR'S OWN ORDER RELATIVE TO WildFire Analysis, which the `dos-protection`
    # block below enumerates from the product: Antivirus, Anti-Spyware, Vulnerability Protection,
    # URL Filtering, FILE BLOCKING, WildFire Analysis, DATA FILTERING, DoS Protection. So File
    # Blocking sits before WildFire Analysis and Data Filtering after it. The four items above
    # are not themselves in the vendor's order - that is older and is not these entries' to
    # rearrange, which is the judgement `dos-protection` made for itself.
    #
    # ITS SCOPE IS EXACTLY ONE `kind eq` CLAUSE, for the reason the `dos-protection` block states
    # below at length. TWO entries were added here on one day, so SEVEN pages now rest on that
    # rule, and `tests/test_file_data_filtering_presentation.py` asserts all seven resolve rather
    # than only the two that are new: a scope too loose breaks the SIBLINGS, not the newcomer.
    ConfigObject("file-blocking", "File Blocking", "Objects", "Security Profiles", "shield",
                 where="Objects > Security Profiles > File Blocking",
                 search_model="integrations.SecurityProfile"),
    ConfigObject("wildfire-analysis", "WildFire Analysis", "Objects", "Security Profiles",
                 "shield", where="Objects > Security Profiles > WildFire Analysis",
                 search_model="integrations.SecurityProfile"),
    # Objects > Security Profiles > Data Filtering, 2026-11-02, for PAN-FIL-004's data-filtering
    # half - the SEVENTH rail item over `SecurityProfile`. Order and scope: see File Blocking.
    ConfigObject("data-filtering", "Data Filtering", "Objects", "Security Profiles", "shield",
                 where="Objects > Security Profiles > Data Filtering",
                 search_model="integrations.SecurityProfile"),
    # Objects > Security Profiles > Data Filtering, 2026-11-02, for PAN-FIL-003 - a SECOND item at
    # that one vendor address, over a DIFFERENT model.
    #
    # WHY IT IS ON THE RAIL AT ALL, by `rule-posture`'s own test above: does the subject HAVE a
    # vendor path? `integrations.DataFilteringPosture` holds one verdict per enforcement point -
    # whether this virtual system's outbound traffic is watched for its own regulated data - and
    # every column of it is a reading this assessment computed. The node an assessor opens and
    # reads is this address, that vsys's data-filtering profiles; so the subject has a vendor path
    # and the rail item promises the NODE rather than the reading. Contrast Normalization
    # Coverage, which is off the rail with an explicit sheet category instead: its subject is our
    # own record of an object that failed to build, and there is no address on a firewall where an
    # assessor could go and look at it. This subject has one and that one does not.
    #
    # A SECOND ITEM RATHER THAN A SECOND MODEL ON `data-filtering`, by `rule-posture`'s own
    # argument that an engineer fixes one or the other: a profile's thresholds and its data
    # patterns are edited in the profile, and everything THIS model reports is fixed by attaching
    # a profile to a rule that has none - which is the commonest failing state of the domain and
    # the whole reason the model is keyed on the point rather than on a profile.
    #
    # AND IT IS REQUIRED RATHER THAN OPTIONAL. PAN-FIL-003's baseline is a shipped query over this
    # model, and clearing `PAN-FIL` from `AWAITING_PRESENTATION` leaves no off-rail route:
    # `test_every_query_in_the_shipped_catalog_has_somewhere_to_go` walks the SEED PAYLOAD without
    # consulting `is_active`, and `LEGACY_SURFACE` is asserted `== {}` by a test of its own.
    ConfigObject("data-filtering-posture", "Data Filtering Posture", "Objects",
                 "Security Profiles", "shield",
                 where="Objects > Security Profiles > Data Filtering",
                 search_model="integrations.DataFilteringPosture"),
    # Objects > Security Profiles > DoS Protection, 2026-11-02, for PAN-ZON-008 - THE FIFTH rail
    # item over `SecurityProfile`, and the one that makes that model's resolver work again for
    # this kind.
    #
    # AFTER WildFire Analysis, which is the vendor's order: PAN-OS lists the Security Profiles
    # children Antivirus, Anti-Spyware, Vulnerability Protection, URL Filtering, File Blocking,
    # WildFire Analysis, Data Filtering, DoS Protection, so DoS Protection follows the four
    # above. (The four above are not themselves in the vendor's order; that is older and is not
    # this entry's to rearrange.)
    #
    # WHY IT HAS TO EXIST AT ALL, measured rather than reasoned. `object_for_canonical_query`
    # short-circuits only when a model has ONE page; with several it keeps every candidate whose
    # own `scope` clauses are a SUBSET of the query's and returns a result only if exactly one
    # matched. `SecurityProfile` had four pages, each scoped by one `kind eq <kind>` clause, and
    # both of PAN-ZON-008's queries carry `kind eq "dos-protection"` - which is a subset of
    # nothing, so nothing matched and the resolver returned None for both.
    #
    # ITS SCOPE IS EXACTLY ONE CLAUSE AND NOTHING LOOSER. A scope of {} would be a subset of
    # EVERY query over this model, so it would match alongside each sibling, make `matched`
    # two long, and push all five kinds to None - the one change here that would break the four
    # pages that already work. `_kind_scope("dos-protection")` is the whole scope.
    ConfigObject("dos-protection", "DoS Protection", "Objects", "Security Profiles", "shield",
                 where="Objects > Security Profiles > DoS Protection",
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
                 search_model="integrations.ManagementInterface"),
    ConfigObject("login-banner", "Login Banner", "Device", "Setup", "book-marked",
                 where="Device > Setup > Management > General Settings",
                 search_model="integrations.LoginBanner"),
    ConfigObject("management-tls", "Management TLS", "Device", "Setup", "clipboard-check",
                 where="Device > Setup > Management > SSL/TLS Service Profile",
                 search_model="integrations.ManagementTlsBinding"),
    ConfigObject("management-ssh", "SSH Management Profiles", "Device", "Setup", "shield",
                 where="Device > Setup > Management > SSH Management Profiles",
                 search_model="integrations.ManagementSshSettings"),
    # NTP shares the Services screen with the update server above, and is a rail item of its own
    # because it is a different question - where time comes from, not where software does.
    ConfigObject("ntp", "NTP", "Device", "Setup", "refresh-cw",
                 where="Device > Setup > Services > NTP",
                 search_model="integrations.NtpSettings"),
    # SNMP Setup is reached from Operations rather than Setup > Management, which is why `where`
    # says so: an assessor following the address needs the vendor's path, not ours.
    ConfigObject("snmp", "SNMP", "Device", "Setup", "server",
                 where="Device > Setup > Operations > SNMP Setup",
                 search_model="integrations.SnmpSettings"),
    ConfigObject("system-identity", "System Identity", "Device", "Setup", "settings",
                 where="Device > Setup > Management > General Settings, and Setup > Interfaces",
                 search_model="integrations.SystemIdentity"),
    ConfigObject("authentication-settings", "Authentication Settings", "Device", "Setup",
                 "clipboard-check", where="Device > Setup > Management > Authentication Settings",
                 search_model="integrations.AuthenticationSettings"),
    ConfigObject("wildfire-settings", "WildFire", "Device", "Setup", "clipboard-check",
                 where="Device > Setup > WildFire",
                 search_model="integrations.WildfireSettings"),
    ConfigObject("logging-and-reporting", "Logging and Reporting", "Device", "Setup",
                 "clipboard-check",
                 where="Device > Setup > Management > Logging and Reporting Settings",
                 search_model="integrations.LoggingSettings"),
    ConfigObject("password-complexity", "Minimum Password Complexity", "Device", "Setup", "eye",
                 where="Device > Setup > Management > Minimum Password Complexity",
                 search_model="integrations.PasswordComplexityPolicy"),
    # Device > Setup > Management > Policy Rulebase Settings, 2026-11-01. The two device-wide
    # switches the PAN-POL rulebase controls depend on, at `deviceconfig/setting/management`.
    #
    # IT IS DEVICE CONFIGURATION AND THE EASIER OF THE TWO CALLS: both columns read a real key
    # at a real xpath, both carry a provenance row saying whether the key was present,
    # template-supplied or absent, and the first of them has a checkbox on this screen an
    # assessor can tick. The second does not - the vendor's Policy Rulebase Settings panel
    # enumerates its controls and `disable-shadow-rule-check` is not among them, so that key is
    # reachable only through the configuration - which is a reason the FINDING names the node
    # rather than a reason the node is not configuration.
    #
    # ITS ONE CONTROL SHIPS INACTIVE, which does not earn or forfeit a rail item: PAN-AUTH-020
    # set that precedent on Administrators. What earns this one is that the catalogue ships
    # QUERIES over the model - `test_every_query_in_the_shipped_catalog_has_somewhere_to_go`
    # reads the seed payload and does not consult `is_active` - so without the item PAN-POL-011's
    # query has nowhere to go the moment `security-policy` leaves AWAITING_PRESENTATION.
    ConfigObject("policy-rule-settings", "Policy Rulebase Settings", "Device", "Setup",
                 "settings",
                 where="Device > Setup > Management > Policy Rulebase Settings",
                 search_model="integrations.PolicyRuleSettings"),
    # Device, top-level rail items - no heading in the product either.
    ConfigObject("password-profiles", "Password Profiles", "Device", "", "book-marked",
                 where="Device > Password Profiles",
                 search_model="integrations.PasswordProfile"),
    ConfigObject("administrators", "Administrators", "Device", "", "shield",
                 where="Device > Administrators",
                 search_model="integrations.AdminUser"),
    ConfigObject("authentication-profile", "Authentication Profile", "Device", "", "shield",
                 where="Device > Authentication Profile",
                 search_model="integrations.AuthenticationProfile"),
    ConfigObject("authentication-sequence", "Authentication Sequence", "Device", "",
                 "list-checks", where="Device > Authentication Sequence",
                 search_model="integrations.AuthenticationSequence"),
    # Device > Certificate Management.
    ConfigObject("certificates", "Certificates", "Device", "Certificate Management",
                 "clipboard-check", where="Device > Certificate Management > Certificates",
                 search_model="integrations.Certificate"),
    ConfigObject("certificate-profile", "Certificate Profile", "Device",
                 "Certificate Management", "server",
                 where="Device > Certificate Management > Certificate Profile",
                 search_model="integrations.CertificateProfile"),
    ConfigObject("ssl-tls-service-profile", "SSL/TLS Service Profile", "Device",
                 "Certificate Management", "settings",
                 where="Device > Certificate Management > SSL/TLS Service Profile",
                 search_model="integrations.SslTlsServiceProfile"),
    # Device > Server Profiles. PAN-OS lists one rail child per protocol; we hold all the
    # authentication kinds on one object today, so it is one child until that splits.
    ConfigObject("aaa-server-profiles", "AAA Server Profiles", "Device", "Server Profiles",
                 "server", where="Device > Server Profiles > LDAP / RADIUS / TACACS+ / "
                                 "Kerberos / SAML / Multi Factor Authentication",
                 search_model="integrations.ServerProfile"),
    # Device > Licenses, 2026-11-02, for PAN-IOT-001 and PAN-IOT-003 - the appliance's whole
    # device-identification service state on one row.
    #
    # ITS POSITION IS THE PRODUCT'S. Help p.950-956 runs the Device rail's tail Software,
    # Dynamic Updates, Plugins, Licenses, Support, Master Key and Diagnostics - so Licenses sits
    # immediately above the master key, where this is.
    #
    # THREE INSTRUMENTS, THREE SCREENS, ONE `where`, and the choice is stated rather than taken
    # quietly. The row is built from `request license info` (the entitlement), `show system
    # info` (the installed device-dictionary version and its release date) and the configuration
    # node `deviceconfig/setting/iot/edge` (the address the firewall sends to). Only the third
    # has a configuration xpath at all - stage 4 records the entitlement as runtime state with
    # no node at any scope - and the vendor splits the other two across Device > Licenses and
    # Device > Dynamic Updates. `where` names Licenses because the entitlement is the PREMISE:
    # the firewall itself prints "IoT Security license is required for feature to function" in
    # red on the page the feature is used from, so an assessor with one finding to chase starts
    # there. THE DICTIONARY HALF IS AT Device > Dynamic Updates, where help p.951 says the
    # Feature column reads "IoT, short for IoT Security" and p.952 that the check mark means
    # that release is the one running. A reader sent to Licenses for a staleness finding is at
    # the wrong screen, and that is the cost of there being one field for three addresses.
    #
    # WHY IT IS ON THE RAIL, by `rule-posture`'s own test above - does the subject have a vendor
    # path. It has two, both of them screens an assessor opens and reads. What the model holds
    # is our reading of them, exactly as that entry describes.
    #
    # THE LABEL IS THE VENDOR'S OWN NAME FOR THE SUBSCRIPTION, from help p.951.
    ConfigObject("iot-security", "IoT Security", "Device", "", "clipboard-check",
                 where="Device > Licenses",
                 search_model="integrations.DeviceIdentificationState"),
    # Device > User Identification > User Mapping, 2026-11-02, for the PAN-UID controls. TWO
    # ITEMS AT ONE VENDOR ADDRESS, on `rule-posture`'s precedent above: an engineer fixes the
    # agent's behaviour or the list that bounds where it looks, and those are two grids on the
    # same screen. `objects_for_model` allows two items over one model; this is the reverse, two
    # items over two models at one address.
    #
    # BOTH SUBJECTS ARE PAN-OS CONFIGURATION NODES, which is the test this module states for
    # being on the rail at all: an assessor opens Device > User Identification > User Mapping and
    # reads both of them. The collector settings are a singleton node per virtual system and the
    # discovery bound is a collection on the same node - what the second model holds is OUR
    # READING of that collection, as `rule-posture` describes, and the rail item promises the
    # grid rather than the reading. Contrast Normalization Coverage, which is off the rail
    # because there is no address on a firewall where its subject could be looked at.
    #
    # THE PATHS ARE THE VENDOR'S AND BOTH ARE CITED. Help p.977 puts the agent's own options
    # under "Palo Alto Networks User-ID Agent Setup" on the User Mapping tab, and help p.981
    # names the list's own section "Include or Exclude Subnetworks for User Mapping". Stage 1 of
    # `user-id` reached both by screen map.
    #
    # NAMED FOR THE VENDOR'S OBJECTS AND NOT FOR THIS DOMAIN, on the `zones` entry's reasoning
    # below: nothing in either slug, label or path says "PAN-UID", so a later domain that
    # queries either model reuses the item instead of adding one.
    ConfigObject("user-id-collector", "User-ID Agent Setup", "Device", "User Identification",
                 "settings",
                 where="Device > User Identification > User Mapping > "
                       "Palo Alto Networks User-ID Agent Setup",
                 search_model="integrations.UserIdCollectorSettings"),
    ConfigObject("user-id-discovery", "User Mapping Discovery", "Device",
                 "User Identification", "list-checks",
                 where="Device > User Identification > User Mapping > "
                       "Include or Exclude Subnetworks for User Mapping",
                 search_model="integrations.UserIdDiscoveryBound"),
    # Device > Master Key and Diagnostics.
    ConfigObject("master-key", "Master Key", "Device", "", "refresh-cw",
                 where="Device > Master Key and Diagnostics",
                 search_model="integrations.MasterKey"),
    # Network > Zones, 2026-11-02, for PAN-IOT-002. TOP-LEVEL and ABOVE IPSec Tunnels, which is
    # the product's own order: the enumeration quoted on the next entry runs Interfaces, Traffic
    # Objects, ZONES, VLANs, Virtual Wires, Virtual Routers, Routing, IPSec Tunnels - so Zones
    # comes third and the tunnels eighth. Same citation, help p.359.
    #
    # THIS ENTRY IS NOT ONLY THIS DOMAIN'S, AND IT IS DELIBERATELY NAMED FOR THE OBJECT RATHER
    # THAN FOR DEVICE-ID. Two later pipeline domains hold homeless queries on `integrations.Zone`
    # and both reuse this item rather than adding one: `user-id` (PAN-UID) over the zone's
    # User-ID switch and its two User Identification ACLs, and `zone-dos-protection` (PAN-ZON)
    # over the zone's protection-profile attachment. A slug, label or `where` naming Device-ID
    # would have made both of those look like they were in the wrong place, and `search_model`
    # already carries everything any of the three needs. So: the vendor's object, the vendor's
    # label, the vendor's path, and three domains' controls reporting under it.
    #
    # The columns the page offers are the union, for the same reason - see its `ResultsSpec`.
    #
    # `Zone` HAD BEEN STORED FOR MONTHS WITH NO CONTROL, NO PAGE AND NO SEARCH SURFACE. It has
    # carried `enable_device_identification` and both Device-ID ACLs since `integrations`
    # migration 0018; PAN-IOT-002 is the first control ever written over a zone, which is why
    # the item appears now rather than when the model did.
    ConfigObject("zones", "Zones", "Network", "", "shield",
                 where="Network > Zones",
                 search_model="integrations.Zone"),
    # Network, TOP-LEVEL rail item - no heading in the product either, and it sits ABOVE the
    # Network Profiles group because that is where PAN-OS puts it. Measured in the vendor's own
    # two enumerations of this tab rather than chosen: help p.359 lists the Network nodes as
    # Interfaces, Traffic Objects, Zones, VLANs, Virtual Wires, Virtual Routers, Routing >
    # Logical Routers, Routing > Routing Profiles, IPSec Tunnels, GRE Tunnels, DHCP, DNS Proxy,
    # Proxy, QoS, LLDP, Network Profiles - Network Profiles LAST - and the admin-role privilege
    # tree at guide p.115-118 runs the same order down to the same leaf.
    #
    # NOT UNDER `Network Profiles`, which is where build order would have put it: the two objects
    # this domain presents are different kinds of thing at two different addresses. A crypto
    # profile is a reusable PROPOSAL under Network Profiles; a tunnel is the phase-2 BINDING that
    # consumes one, and the vendor keeps it a tab away. An engineer fixes one or the other.
    #
    # Turned on 2026-11-02 for the nine PAN-IPS controls, which query both of this domain's
    # models: every control query must have a results page, and a query with nowhere to go is one
    # an assessor cannot check.
    ConfigObject("ipsec-tunnels", "IPSec Tunnels", "Network", "", "server",
                 where="Network > IPSec Tunnels",
                 search_model="integrations.IpsecTunnel"),
    # Network > Network Profiles. The rail order inside this group is the PRODUCT's, taken
    # from the vendor's own help, whose Network Profiles sections run GlobalProtect IPSec
    # Crypto, IKE Gateways, IPSec Crypto, IKE Crypto, Monitor, Interface Mgmt, Zone Protection
    # (help 11.2 p.635-650) - so both IKE items sit ABOVE Interface Mgmt rather than after it,
    # which is where build order would have put them.
    #
    # Turned on 2026-10-28 for the nine PAN-IKE controls, which query both objects: every
    # control query must have a results page, and a query with nowhere to go is one an assessor
    # cannot check. Two rail items and not one, because PAN-OS lists them as two and because
    # they are two models - a gateway names a profile, and an engineer fixes one or the other.
    ConfigObject("ike-gateways", "IKE Gateways", "Network", "Network Profiles", "server",
                 where="Network > Network Profiles > IKE Gateways",
                 search_model="integrations.IkeGateway"),
    # IPSec Crypto sits BETWEEN the two IKE items, which is neither build order nor alphabetical:
    # the group's rail order is the vendor's, and both its enumerations put it there - the
    # Network Profiles sections run GlobalProtect IPSec Crypto, IKE Gateways, IPSec Crypto, IKE
    # Crypto, Monitor, Interface Mgmt (help p.655-659, guide p.116-117). Phase 2 before phase 1
    # reads backwards to us and is what the product does.
    #
    # Network > Network Profiles > Monitor has NO item, and that is the rule rather than an
    # omission: `integrations.MonitorProfile` is stored and normalised for this domain and NO
    # SHIPPED QUERY NAMES IT - the one stage 5 record that reads it is discharged to an
    # engineer's question - so by Jason's rule of 2026-09-10 it has not earned a rail item. Its
    # content still reaches a reader, through the tunnel row's resolved monitor action.
    ConfigObject("ipsec-crypto", "IPSec Crypto", "Network", "Network Profiles", "shield",
                 where="Network > Network Profiles > IPSec Crypto",
                 search_model="integrations.IpsecCryptoProfile"),
    ConfigObject("ike-crypto", "IKE Crypto", "Network", "Network Profiles", "shield",
                 where="Network > Network Profiles > IKE Crypto",
                 search_model="integrations.IkeCryptoProfile"),
    ConfigObject("interface-mgmt", "Interface Mgmt", "Network", "Network Profiles",
                 "list-checks", where="Network > Network Profiles > Interface Mgmt",
                 search_model="integrations.InterfaceManagementProfile"),
    # Network > Network Profiles > Zone Protection, 2026-11-02, for PAN-ZON-002 to -006.
    #
    # LAST IN THE GROUP, AND THE CITATION IS ALREADY IN THIS FILE: the `ike-gateways` entry
    # above quotes the vendor's own Network Profiles enumeration as GlobalProtect IPSec Crypto,
    # IKE Gateways, IPSec Crypto, IKE Crypto, Monitor, Interface Mgmt, ZONE PROTECTION (help
    # 11.2 p.635-650). Zone Protection is the last section in that run, so it goes here rather
    # than beside the zone itself at Network > Zones - which is where build order and the
    # domain's name would both have put it.
    #
    # NOT THE SAME SUBJECT AS `zones`, and the distinction is the one that entry's group makes
    # for a profile and its binding: a zone protection profile is a reusable PROPOSAL under
    # Network Profiles, and the ATTACHMENT of one to a zone is a leaf on the zone. An engineer
    # fixes the profile's contents here and fixes a missing attachment on the zone - which is
    # exactly the split between PAN-ZON-002..006 (this item) and PAN-ZON-001 (the `zones` item).
    #
    # A PROFILE IS DEVICE-LOCAL AND NOT VSYS-SCOPED, which stage 4 measured: `action=complete`
    # answers code=6 Invalid sequence at both the shared and the vsys spelling of
    # `network/profiles/zone-protection-profile`, so there is one scope on a firewall and the
    # results page's owner column is the APPLIANCE rather than a vsys.
    ConfigObject("zone-protection", "Zone Protection", "Network", "Network Profiles", "shield",
                 where="Network > Network Profiles > Zone Protection",
                 search_model="integrations.ZoneProtectionProfile"),
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
