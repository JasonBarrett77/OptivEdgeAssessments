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
    # Policies > Security, FOURTH rail item, 2026-11-02, for PAN-SAS-003 - the virtual system's
    # whole rule set read for a third dimension: whether the UPLOAD and SHARING functions of the
    # applications it permits are refused, and whether an attribute-driven selection of
    # unapproved cloud applications is refused.
    #
    # FOLLOWING `rule-posture` AND `rulebase-device-match` ABOVE RATHER THAN INVENTING A PATTERN,
    # and their reasoning blocks apply here unchanged. The subject is a PAN-OS node - one virtual
    # system's `rulebase/security/rules`, plus the `application-filter` container beside it -
    # which an assessor opens at this address and reads; the model holds OUR READING of that
    # node; the rail item promises the node and not the reading. By `rule-posture`'s own test:
    # does the subject HAVE a vendor path? It does, and Help 11.2 p.147 confirms the filter half
    # is reached from the rule - an Application Filter "works the same way as Objects >
    # Application Filters ... You can filter cloud-based (with a SaaS Inline Security
    # subscription) and content-based applications".
    #
    # AND IT IS REQUIRED RATHER THAN OPTIONAL. PAN-SAS-003's baseline is a shipped query over
    # this model, and clearing `PAN-SAS-` from `AWAITING_PRESENTATION` leaves no off-rail route:
    # `test_every_query_in_the_shipped_catalog_has_somewhere_to_go` walks the SEED PAYLOAD
    # without consulting `is_active`, and `LEGACY_SURFACE` is asserted `== {}` by a test of its
    # own.
    #
    # NO `scope`: this model has exactly ONE page, so `object_for_canonical_query`
    # short-circuits on the single candidate and a scope would be dead weight. Same call as
    # `data-filtering-posture`.
    ConfigObject("saas-application-policy", "SaaS Application Policy", "Policies", "", "shield",
                 where="Policies > Security",
                 search_model="integrations.SaasApplicationPolicyPosture"),
    # Policies > Decryption, 2026-11-02, for PAN-DEC-001 to -003 and -005 to -010 - TWO items
    # at one vendor address, over the two models that carry the decryption policy.
    #
    # ITS POSITION IS THE PRODUCT'S, like the DoS item below it. PAN-OS's Policies rail runs
    # Security, NAT, QoS, Policy Based Forwarding, DECRYPTION, Network Packet Broker, Tunnel
    # Inspection, Application Override, Authentication, DoS Protection, SD-WAN - so Decryption
    # sits after the three Policies > Security items above and before DoS Protection at the tail.
    #
    # ITS SUBJECT IS A PAN-OS NODE, which is the test this module states for being on the rail at
    # all: one virtual system's `rulebase/decryption/rules`, which an assessor opens at this
    # address and reads. Help 11.2 p.170, under the section path `Policies > Decryption`
    # verbatim: "You can configure the firewall to decrypt traffic for visibility, control, and
    # granular security ... Add a decryption policy rule to define traffic that you want to
    # decrypt."
    #
    # NOT `Objects > Decryption Profile`, WHICH IS A DIFFERENT SCREEN AND A DIFFERENT CATEGORY.
    # That address belongs to the `decryption-profile` item in the Objects block, added the same
    # week for PAN-DCP: a profile is a reusable proposal and a policy is where it is applied, and
    # help p.174 points from one to the other ("For details on creating a Decryption profile,
    # select Objects > Decryption Profile"). There is no `Objects > Decryption` group in any of
    # the three indexed Help versions.
    #
    # THE LABEL IS THE VENDOR'S OWN RAIL WORD and the SLUG says `-rules`, for the mechanical
    # reason `dos-protection-rules` below records: `configuration_results.RESULTS` is keyed on
    # the slug ALONE while `CONFIG_OBJECTS_BY_KEY` is keyed on (category, slug), so a bare
    # `decryption` slug here and the Objects profile item could not both carry a results spec.
    ConfigObject("decryption-rules", "Decryption", "Policies", "", "shield",
                 where="Policies > Decryption",
                 search_model="integrations.DecryptionPolicyRule"),
    # Policies > Decryption, SECOND item at that address, 2026-11-02, for PAN-DEC-001 and -009 -
    # whose subject is the virtual system's WHOLE decryption rulebase rather than any rule in it.
    #
    # A SECOND ITEM RATHER THAN A SECOND MODEL ON `decryption-rules`, which is `rule-posture`'s
    # argument one rulebase over: an engineer fixes one or the other. Everything on the item
    # above is fixed by EDITING a rule that exists; everything here is fixed by ADDING a rule
    # that is not there, and the commonest state of this subject in the measured estate is no
    # decryption rulebase at all. `objects_for_model` already allows two items over one model;
    # this is the reverse - two items over two models at one vendor address, the same shape as
    # the three at Policies > Security.
    #
    # WHY IT IS ON THE RAIL, since every column of the model is a verdict this assessment
    # computes. `rule-posture` states the test and this passes it the same way: the subject is a
    # PAN-OS node - one virtual system's `rulebase/decryption/rules` - which an assessor opens at
    # this address and reads, and the rail item promises the NODE, not our reading of it.
    #
    # THE LABEL IS OURS AND IS A PROPOSAL. The vendor has no word for the state of a whole
    # rulebase: help 11.2 p.170-175 describes the decryption RULE and its five field tables and
    # names no rulebase-level state at all.
    ConfigObject("decryption-coverage", "Decryption Coverage", "Policies", "", "shield",
                 where="Policies > Decryption",
                 search_model="integrations.DecryptionRulebaseVerdict"),
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
    # Objects > Applications, 2026-11-02, for PAN-SAS-001 - the first rail item at that vendor
    # address, over `integrations.SanctionedApplicationMarking`, which stage 7 minted for this
    # domain and which had never been queried from this repository at all.
    #
    # WHY IT IS ON THE RAIL, by `rule-posture`'s own test: does the subject HAVE a vendor path?
    # It does. Established in the corpus rather than from memory: PAN-OS Web Interface Help 11.2
    # p.231, under the section `Objects > Applications`, says verbatim "A predefined tag named
    # sanctioned is available for you to tag SaaS applications ... Tag applications as
    # sanctioned to help differentiate sanctioned SaaS application traffic from unsanctioned
    # SaaS application traffic", and p.242 names the screen from the other side: "A predefined
    # tag named Sanctioned is available for tagging applications (Objects > Applications)." So
    # the item promises a node an assessor can open. The model holds one VERDICT per enforcement
    # point over the entries at that address, and the rail item promises the node rather than
    # the reading - the same call `data-filtering-posture` and `rule-posture` both make.
    #
    # ITS POSITION IS THE PRODUCT'S. Help 11.2 p.213 lists the Objects tree in order -
    # "Objects>Addresses, Objects>Address Groups, Objects>Regions, Objects>Applications,
    # Objects>Application Groups, Objects>Application Filters, Objects>Services ...
    # Objects>Custom Objects, Objects>Security Profiles" - so Applications follows Addresses and
    # precedes both Custom Objects and Security Profiles, which is where this sits. It
    # REARRANGES NO EXISTING ITEM relative to any other.
    #
    # THE LABEL NAMES WHAT WE SHOW AND NOT THE WHOLE SCREEN, on `data-filtering-posture`'s
    # precedent: that item sits at `Objects > Security Profiles > Data Filtering` and is labelled
    # "Data Filtering Posture" because the page presents a posture verdict rather than the
    # profile grid. This page presents the approval marking and not the application inventory,
    # and labelling it "Applications" would promise a grid it does not draw.
    #
    # NO `scope`: one page over this model, so `object_for_canonical_query` short-circuits.
    ConfigObject("sanctioned-applications", "Sanctioned Applications", "Objects", "",
                 "list-checks",
                 where="Objects > Applications",
                 search_model="integrations.SanctionedApplicationMarking"),
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
    # Objects > Security Profiles > URL Filtering, 2026-11-02, for PAN-SAS-002 and PAN-SAS-004 -
    # a SECOND item at that one vendor address, over a DIFFERENT model. Exactly the shape
    # `data-filtering` and `data-filtering-posture` already make below, and that pair's
    # reasoning applies here unchanged.
    #
    # WHY IT IS ON THE RAIL AT ALL, by `rule-posture`'s own test: does the subject HAVE a vendor
    # path? `integrations.SaasUrlFilteringPosture` holds one verdict per enforcement point over
    # the URL Filtering profiles reachable from that partition, and the node an assessor opens
    # and reads is this address. Established in the corpus: Help 11.2 p.302 names the screen
    # verbatim - "select Objects > Security Profiles > URL Filtering > HTTP Header Insertion" -
    # and p.297 gives the category action under the heading "Site Access". Every column of the
    # model is a reading this assessment computed, and the rail item promises the NODE rather
    # than the reading.
    #
    # A SECOND ITEM RATHER THAN A SECOND MODEL ON `url-filtering`, by `rule-posture`'s argument
    # that an engineer fixes one or the other: a profile's categories and its header-insertion
    # entries are edited in the profile, and what THIS model reports is fixed by making a rule of
    # the partition carry such a profile at all - which is the commonest failing state of the
    # domain and the reason the model is keyed on the point rather than on a profile.
    #
    # AND IT IS REQUIRED RATHER THAN OPTIONAL, for the reason spelled out on
    # `saas-application-policy` above: clearing `PAN-SAS-` from `AWAITING_PRESENTATION` leaves no
    # off-rail route for the two controls' shipped queries.
    #
    # NO `scope`: one page over this model, so `object_for_canonical_query` short-circuits. The
    # `kind eq` scopes the siblings above carry are a `SecurityProfile` problem and this is a
    # different model.
    ConfigObject("saas-url-filtering", "SaaS URL Filtering Posture", "Objects",
                 "Security Profiles", "shield",
                 where="Objects > Security Profiles > URL Filtering > HTTP Header Insertion",
                 search_model="integrations.SaasUrlFilteringPosture"),
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
    # Objects > Decryption Profile, 2026-11-02, for PAN-DCP-001 to -005 and -007 - the NINTH rail
    # item over `integrations.SecurityProfile`, and ONE item for six controls rather than six: all
    # six carry `kind eq "decryption"` and nothing else, so they share one page.
    #
    # IT IS NOT UNDER `Security Profiles` AND IT IS NOT UNDER A `Decryption` GROUP, which is the
    # one thing about this entry that was checked rather than assumed. The brief that commissioned
    # it said PAN-OS lists the profile at `Objects > Decryption > Decryption Profile` in current
    # releases and at `Objects > Decryption Profile` in older ones. MEASURED across all three Help
    # versions the corpus carries, and the brief is wrong: 11.1 p.213, 11.2 p.213 and 12.2 p.215
    # each enumerate the Objects rail with the SAME entry, verbatim - "Objects>Authentication •
    # Objects>Decryption Profile • Objects > SD-WAN Link Management • Objects>Schedules" - and a
    # complete rung-1 count over every document for `Objects>Decryption` returns those three pages
    # and nothing else. So it is a TOP-LEVEL Objects rail item in every version we hold,
    # `group=""`, and not a child of anything.
    #
    # PLACED IN THE VENDOR'S OWN ORDER. That same list runs ... Security Profiles, Security Profile
    # Groups, Log Forwarding, Authentication, DECRYPTION PROFILE, SD-WAN Link Management,
    # Schedules - so Decryption Profile follows the whole `Security Profiles` block above, which is
    # where it sits. (The items above it are not themselves in the vendor's order; that is older
    # and is not this entry's to rearrange, which is the judgement `dos-protection` made for itself
    # and `file-blocking` and `url-filtering` each repeated.)
    #
    # ITS SCOPE IS EXACTLY ONE `kind eq` CLAUSE AND NOTHING LOOSER, for the reason the
    # `dos-protection` block above states at length: `object_for_canonical_query` keeps every
    # candidate whose own scope clauses are a SUBSET of the query's and answers only when exactly
    # one matched, so a scope of {} would be a subset of EVERY query over this model and would push
    # ALL NINE kinds to None. The eight pages that already work are what a wrong scope here breaks,
    # which is why `tests/test_decryption_presentation.py` asserts all nine resolve rather than
    # only the one that is new.
    ConfigObject("decryption-profile", "Decryption Profile", "Objects", "", "shield",
                 where="Objects > Decryption Profile",
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
    # Device > Setup > ACE, 2026-11-02, for PAN-SAS-005 - the App-ID Cloud Engine, a device-wide
    # service switch with no entry name and no vsys.
    #
    # THE ADDRESS AND THE LABEL ARE BOTH THE VENDOR'S OWN, established in the corpus and stable
    # across releases. The section path `Device > Setup > ACE` appears verbatim in all three
    # indexed Help versions - 11.2 p.796, 11.1 p.783 and 12.2 p.824 - so an assessor sent here
    # finds the screen on any of them. Help 11.2 p.796: "Device > Setup > ACE Enable or disable
    # App-ID Cloud Engine (ACE) settings and settings related to SaaS Security Inline policy
    # recommendations", with the checkbox labelled "Disable the App-ID Cloud Engine" and the
    # note "You must have a valid SaaS Security Inline license on the firewall to use ACE". The
    # label is `ACE` because that is what the vendor's own tab is called, and `where` spells the
    # whole path for a reader who does not know the acronym.
    #
    # WHY IT IS ON THE RAIL, by `rule-posture`'s own test: the subject is a PAN-OS configuration
    # node, `deviceconfig/setting/cloudapp`, which an assessor opens at this address and reads.
    # Two of the model's columns are computed from an OPERATIONAL command rather than from that
    # node - whether the engine is working, and why not - but the node is real and the item
    # promises the node.
    #
    # APPENDED TO THE `Setup` GROUP RATHER THAN PLACED IN THE VENDOR'S TAB ORDER, stated because
    # the alternative was available and was declined. PAN-OS's Setup tab strip runs Management,
    # Operations, Services, Content-ID, WildFire, Session, HSM, ACE, DLP, so ACE would follow
    # WildFire and Session; this group is NOT in that order today and putting one item right
    # would mean rearranging the twelve that are not. `dos-protection` and `file-blocking` both
    # drew that line - they declined to reorder older items among themselves - and appending
    # rearranges nothing.
    #
    # NO `scope`: one page over this model, so `object_for_canonical_query` short-circuits.
    ConfigObject("ace", "ACE", "Device", "Setup", "settings",
                 where="Device > Setup > ACE",
                 search_model="integrations.CloudAppEngineSetting"),
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
    # Device > Certificate Management > Certificates, 2026-11-02, for PAN-DCP-006 - a SECOND item
    # at that one vendor address, over a DIFFERENT model, which is `data-filtering-posture`'s
    # pattern and `rule-posture`'s argument.
    #
    # THE VENDOR'S OWN ADDRESS FOR IT, and it is not the node's own address. The designation lives
    # at `/config/shared/ssl-decrypt`, and PAN-OS presents it as something you select while
    # editing the CERTIFICATE: Web Interface Help 11.2 p.170 verbatim, "Create a certificate on the
    # Device > Certificate Management > Certificates page and then click the name of the
    # certificate and select Forward Trust Certificate", and p.889 carries "usage is set to Forward
    # Trust Certificate or Forward Untrust Certificate" under that same section. So an engineer
    # looking for "where is the forward trust certificate set" finds the certificate screen, and
    # `where` sends them there rather than to the xpath.
    #
    # A SECOND ITEM RATHER THAN A SECOND MODEL ON `certificates`, by `rule-posture`'s own test -
    # an engineer fixes one or the other. A certificate's key, CA flag and validity are edited in
    # the certificate; everything THIS model reports is fixed by changing WHICH certificate the
    # firewall signs with, which is a different act on the same screen. `RESULTS` is keyed on the
    # slug alone, so one page cannot serve two models anyway.
    #
    # ITS LABEL IS A PROPOSAL. The vendor has a word for the USAGE - "Forward Trust Certificate",
    # "Forward Untrust Certificate" - and no word for the node as an object; "Forward Proxy" is the
    # vendor's own name for the decryption mode (help 11.2 p.339, "SSL FORWARD PROXY TAB ...
    # decrypted using Forward Proxy"), so the label is built from the vendor's two terms. Jason
    # takes the heading pass once across many domains (P399).
    #
    # IT DECLARES NO `scope`: its model has exactly ONE page, so `object_for_canonical_query`
    # short-circuits on the single candidate and a scope would be dead weight a later second page
    # would have to reckon with. Same call as `data-filtering-posture` and `custom-url-categories`.
    #
    # AND IT IS REQUIRED RATHER THAN OPTIONAL. PAN-DCP-006's baseline is a shipped query over this
    # model, and clearing `PAN-DCP` from `AWAITING_PRESENTATION` leaves no off-rail route:
    # `test_every_query_in_the_shipped_catalog_has_somewhere_to_go` walks the SEED PAYLOAD without
    # consulting `is_active`, and `LEGACY_SURFACE` is asserted `== {}` by a test of its own.
    ConfigObject("forward-proxy-signing", "Forward Proxy Signing", "Device",
                 "Certificate Management", "clipboard-check",
                 where="Device > Certificate Management > Certificates",
                 search_model="integrations.DecryptionSettings"),
    # Device > Certificate Management > SSL Decryption Exclusion, 2026-11-02, for PAN-DEC-004 -
    # the exclusions the organisation added itself.
    #
    # THE ADDRESS IS THE VENDOR'S AND IT IS NOT IN `Policies`, which is where the rest of this
    # pipeline domain lands and where the dispatch brief put it. Established in the corpus rather
    # than inferred: PAN-OS Web Interface Help 11.2 p.901, under the section path
    # `Device > Certificate Management > SSL Decryption Exclusion` verbatim - "View and manage
    # SSL/TLS decryption exclusions. There are two types of decryption exclusions, predefined
    # exclusions and custom exclusions" - and again on p.903 naming the screen in running text,
    # "the SSL Decryption Exclusion List (Device Certificate Management SSL Decryption
    # Exclusion)". The same section path exists in all three indexed Help versions, at p.889 in
    # 11.1 and p.940 in 12.2, so the address is stable across releases.
    #
    # SO THIS DOMAIN'S THREE ITEMS SIT IN TWO CATEGORIES, which is required rather than untidy:
    # tabs and rail items follow the product's own organisation, and an assessor sent to Policies
    # for this object would not find it.
    #
    # THE LABEL IS THE VENDOR'S OWN, singular as the screen spells it.
    ConfigObject("ssl-decryption-exclusion", "SSL Decryption Exclusion", "Device",
                 "Certificate Management", "clipboard-check",
                 where="Device > Certificate Management > SSL Decryption Exclusion",
                 search_model="integrations.SslDecryptionExclusion"),
    ConfigObject("certificate-profile", "Certificate Profile", "Device",
                 "Certificate Management", "server",
                 where="Device > Certificate Management > Certificate Profile",
                 search_model="integrations.CertificateProfile"),
    ConfigObject("ssl-tls-service-profile", "SSL/TLS Service Profile", "Device",
                 "Certificate Management", "settings",
                 where="Device > Certificate Management > SSL/TLS Service Profile",
                 search_model="integrations.SslTlsServiceProfile"),
    # Device > Log Settings, 2026-11-02, for PAN-PLT-006 - the log-database alarm mechanism, a
    # device-wide singleton at `deviceconfig/setting/management/common-criteria-alarm-generation`.
    #
    # BETWEEN Certificate Management AND Server Profiles, which is PAN-OS's own rail order rather
    # than an append: the product's Device rail runs Certificate Management, Response Pages, Log
    # Settings, Server Profiles, and this group's two neighbours are already in that order, so one
    # item lands in the right place without rearranging anything. `ace` above declined to reorder
    # twelve items to place itself correctly; nothing needs reordering here.
    #
    # THE ADDRESS AND THE LABEL ARE BOTH ESTABLISHED IN THE CORPUS, not written from memory. The
    # section is `Define Alarm Settings`, whose own breadcrumb line reads "Define Alarm Settings -
    # Device > Log Settings", and it is present verbatim in all three indexed Help editions: 11.2
    # p.912-914, 11.1 p.898, 12.2 p.949. Help 11.2 p.912: "Use the Alarm Settings to configure
    # Alarms for the CLI and the web interface", listing "The Log database for each log type is
    # nearing full" among the three events, and "Alarms are visible only if you Enable Alarms. If
    # you disable alarms, the firewall does not alert you to critical events that require action."
    # The label is `Alarm Settings` because that is the vendor's own name for the panel in that
    # sentence; `where` spells the screen it sits on.
    #
    # WHY IT IS ON THE RAIL, by `rule-posture`'s own test: the subject is a PAN-OS configuration
    # node that an assessor opens at this address and reads, and every column of the model is
    # either a leaf of that node or a reading of it. Contrast Normalization Coverage, which is off
    # the rail because there is no address on a firewall where an assessor could go and look.
    #
    # ONE NOTE A READER OF THE MODEL WILL WANT: the alarm LOG is not reachable - `show log alarm`
    # answers "invalid client cli" through the API on all four lab appliances - so this page shows
    # the configured mechanism and never an alarm that fired.
    ConfigObject("log-alarms", "Alarm Settings", "Device", "", "triangle-alert",
                 where="Device > Log Settings",
                 search_model="integrations.LogAlarmSettings"),
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
    # Device > Dynamic Updates, 2026-11-02, for PAN-PLT-002 - the content streams the appliance is
    # actually running, as its own runtime reports them.
    #
    # HERE, IMMEDIATELY ABOVE Master Key, BECAUSE THAT IS THE PRODUCT'S OWN ORDER. The Help lists
    # these sections in sequence - `Device > Software` p.950, `Device > Dynamic Updates` p.950-953,
    # `Device > Licenses` p.954, `Device > Master Key and Diagnostics` p.959 - and the
    # `iot-security` entry above already cites the same run from the other end. Both paths are
    # present verbatim in all three indexed Help editions: 11.2 p.950/954, 11.1 p.940, 12.2 p.992.
    #
    # Help 11.2 p.950: "Palo Alto Networks regularly posts updates that include new and modified
    # applications, threat protection, device dictionary files for IoT Security, and GlobalProtect
    # data files through dynamic updates", with "Currently Installed" as the screen's own column
    # for what is on the box and "Release Date" as its own column for the date this row ages
    # against.
    #
    # THE LABEL IS OURS AND IS A PROPOSAL, deliberately NOT `Dynamic Updates`. That screen carries
    # two different questions and two pipeline domains: what the appliance has LOADED, which is
    # this item, and the SCHEDULE on which it retrieves more, which is `updates`/PAN-UPD and whose
    # own `integrations.ContentUpdateSchedule` has no rail item yet - its `AWAITING_PRESENTATION`
    # entry is still open and its stage 9 run is what clears it. Taking the vendor's screen name
    # for one of the two would leave the other with no name to take, and `security` /
    # `rule-posture` set the precedent for two differently-named items at one vendor address.
    #
    # WHY IT IS ON THE RAIL, and this one is the harder call of the three in this block: every
    # reading on the model comes from an OPERATIONAL command, `show system info`, and not from a
    # configuration node - there is no xpath behind any column. It passes the rail's own test
    # anyway, which `configuration_navigation`'s header states as a promise about what can be
    # ASKED: Device > Dynamic Updates is a screen an assessor opens and reads the installed
    # versions off, which is exactly what this page shows. `iot-security` above made the same
    # call on the same grounds - "two of the three are screens an assessor opens".
    ConfigObject("content-streams", "Installed Content", "Device", "", "download",
                 where="Device > Dynamic Updates",
                 search_model="integrations.FirewallContentStreams"),
    # Device > Licenses, 2026-11-02, for PAN-PLT-004 - a verdict over the appliance's whole
    # entitlement set. Immediately below Dynamic Updates and above Master Key, per the citation on
    # the entry above.
    #
    # Help 11.2 p.954: "Select Device > Licenses to activate licenses on all firewall models", and
    # the same section names the thing this control's second half is about in the vendor's own
    # words - "it allows you to free up all active licenses - subscription licenses, VM-Capacity
    # licenses, and support entitlements". The label is the vendor's own screen name, including its
    # American spelling, while the model is `LicenceInventory`: the vendor's word heads the rail
    # and ours names the code, and neither is corrected to the other.
    #
    # WHAT THIS PAGE SHOWS THAT THE VENDOR'S SCREEN DOES NOT DOCUMENT, which is recorded in
    # `reference/known-vendor-contradictions.md` and matters to an assessor following this path:
    # the Threat Prevention guide p.35 sends a reader here to "verify that the Threat Prevention
    # expiration date is in the future", and the Help's own section for this screen documents no
    # expiry, no status and no per-subscription field at all, checked across all three editions.
    # So every expiry reading behind this page comes from `request license info` rather than from
    # a field the vendor documents on the screen. The item is still right - this is where licences
    # live and where a renewal is applied - and that is why the two can differ.
    #
    # SECOND ITEM AT THIS ADDRESS. `iot-security` above already claims `where="Device > Licenses"`
    # for the device-identification licence, over a different model; `objects_for_model` allows two
    # items at one vendor address and `security` / `rule-posture` set that precedent.
    ConfigObject("licenses", "Licenses", "Device", "", "clipboard-check",
                 where="Device > Licenses",
                 search_model="integrations.LicenceInventory"),
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
    # Network > GlobalProtect, 2026-11-02, for PAN-GPP-001 to -006 - THREE items in a NEW rail
    # group, over the three models this domain's stage 7 minted and which had never been queried
    # from this repository at all.
    #
    # THE GROUP IS THE VENDOR'S OWN AND SO IS ITS CONTENT. Help 11.2 p.997 enumerates the eight
    # GlobalProtect screens verbatim: "The following firewall web interface pages allow you to
    # configure and manage GlobalProtect components: • Network > GlobalProtect > Portals •
    # Network > GlobalProtect > Gateways • Network > GlobalProtect > MDM • Network > GlobalProtect
    # > Clientless Apps • Network > GlobalProtect > Clientless App Groups • Objects >
    # GlobalProtect > HIP Objects • Objects > GlobalProtect > HIP Profiles • Device >
    # GlobalProtect Client". So the group spans THREE PAN-OS categories in the product, and the
    # two items this domain needs are both in the Network five.
    #
    # LAST IN Network AND AFTER `Network Profiles`, which is the Help's own chapter order rather
    # than a layout anybody chose: Network Profiles is p.635-650 and the GlobalProtect chapter is
    # p.997-1085. `GlobalProtect` is a top-level chapter of the Help whose SCREENS are addressed
    # under Network, which is why the vendor's Network-node enumeration at p.359 (quoted on the
    # `ipsec-tunnels` item above) does not list it and this is still a Network group.
    #
    # THE NEXT DOMAIN ADDS TO THIS GROUP AND DOES NOT CHANGE IT. `globalprotect-gateway` is the
    # `Gateways` screen plus its own two child models, and `GlobalProtectEnforcementPoint` - the
    # third item below - is SHARED with it: that domain's `AWAITING_PRESENTATION` comment names
    # this entry as load-bearing for six of its seven controls.
    ConfigObject("globalprotect-portals", "Portals", "Network", "GlobalProtect", "server",
                 where="Network > GlobalProtect > Portals",
                 search_model="integrations.GlobalProtectPortal"),
    # Network > GlobalProtect > Portals > <portal-config> > Authentication, 2026-11-02, for
    # PAN-GPP-002 - a SECOND item under the portal's own address, over the child row.
    #
    # ITS `where` IS A TAB INSIDE A DIALOG AND THAT IS A REAL ADDRESS, not a formality. Help 11.2
    # p.1001 verbatim: "GlobalProtect Portals Authentication Configuration Tab • Network >
    # GlobalProtect > Portals > <portal-config> > Authentication", and p.1002 describes the table
    # this model's rows ARE: "Client Authentication ... You can create multiple client
    # authentication configurations and differentiate them by operating system." So an assessor
    # following a PAN-GPP-002 finding opens the portal and selects that tab, and naming only
    # `Network > GlobalProtect > Portals` would send them to a grid of portals with no indication
    # that the row they are looking for is two clicks inside one of them.
    #
    # A SECOND ITEM RATHER THAN A SECOND MODEL ON `globalprotect-portals`, on the argument
    # `decryption-coverage` makes one rulebase over: an engineer fixes one or the other. A
    # PAN-GPP-002 row is fixed by editing ONE ROW of ONE portal's table, and the portal item's own
    # controls are fixed on three other tabs of the same dialog. `configuration_results.RESULTS`
    # is keyed on the slug alone, so each needs a slug of its own in any case.
    #
    # THE LABEL IS THE VENDOR'S RAIL WORD FOR THE TAB and the slug says which portal thing it is.
    # `shield` AND NOT `lock`, WHICH IS NOT IN THE VENDORED SET. The field's own comment above
    # says an icon "must exist in OptivEdge's vendored icon set - templates/components/icons/.
    # Not lucide's full catalogue; a name that is not there renders a 500" - and it is worth
    # recording what that costs, because nothing validates the name at import time and the whole
    # set is nineteen files: book-marked, chevron-right, circle-question-mark, clipboard-check,
    # download, eye, flag, layout-dashboard, list-checks, monitor, plus, refresh-cw, server,
    # settings, shield, trash-2, triangle-alert, wand-sparkles, x. `lock` read as obviously
    # present and is not there, and because the RAIL renders on every page of the explorer the
    # `FileNotFoundError` took out FIFTY-SIX tests across `test_configuration_queries`,
    # `test_navigation` and `test_table_presentation` - for every rail item, not just this one -
    # and not one of their names mentions an icon.
    ConfigObject("globalprotect-portal-authentication", "Portal Authentication", "Network",
                 "GlobalProtect", "shield",
                 where="Network > GlobalProtect > Portals > <portal-config> > Authentication",
                 search_model="integrations.GlobalProtectPortalClientAuthRow"),
    # Network > GlobalProtect, 2026-11-02, for PAN-GPP-006 - and SHARED WITH `globalprotect-
    # gateway`, which runs next and whose PAN-GPG-005 reports on the same model.
    #
    # ITS `where` NAMES THE GROUP AND NOT A SCREEN, which is the honest answer for this subject
    # rather than a vagueness. The row is one virtual system's GlobalProtect configuration taken
    # as a whole, and the verdict on it is computed from THREE of the group's screens at once:
    # `Clientless Apps` and `Clientless App Groups` hold the definitions, and a portal's own
    # `Clientless VPN` tab holds the publishing. There is no single vendor screen for the vsys's
    # posture, and picking one of the three would send a reader to the wrong one on two thirds of
    # the rows - the `latent` rank is specifically the state where NO portal publishes, so the
    # portal screen is empty of it. The Clientless definitions cell on the findings tab names the
    # counts so a reader knows which of the three to open. A compound `where` has precedent on
    # this rail ("Device > Setup > Management > General Settings, and Setup > Interfaces").
    #
    # WHY IT IS ON THE RAIL AT ALL, since every column of the model is a verdict this assessment
    # computes. `rule-posture` and `decryption-coverage` state the test and this passes it the same
    # way: the subject is a PAN-OS node - one virtual system's `global-protect` subtree - which an
    # assessor opens at this address and reads, and the rail item promises the NODE, not our
    # reading of it. The model's own docstring records that node PRESENCE is the wrong test and an
    # entry count the right one, which is what the page shows.
    #
    # THE LABEL IS OURS AND IS A PROPOSAL. The vendor has no word for the state of a whole virtual
    # system's GlobalProtect configuration: p.997 names eight screens and no roll-up over them.
    # "Coverage" follows `Decryption Coverage`, which is this report's established word for a
    # verdict over everything at one enforcement point, and it is deliberately NOT "Clientless
    # VPN": the next domain adds host-posture columns to the same model for PAN-GPG-005, and a
    # feature-specific label would become a lie the day it lands.
    # Network > GlobalProtect > Gateways, 2026-11-02, for PAN-GPG-001, -006 and -007 - THREE items
    # added to the group the domain before this one created, not a new group.
    #
    # BEFORE `globalprotect-coverage` AND AFTER THE TWO PORTAL ITEMS, which is the vendor's own
    # screen order and not a preference: Help 11.2 p.997 enumerates the GlobalProtect pages as
    # "Network > GlobalProtect > Portals • Network > GlobalProtect > Gateways • Network >
    # GlobalProtect > MDM • ...", so the gateway follows the portal. The vsys-wide roll-up stays
    # LAST for the reason its own comment gives - it is a verdict over the whole subtree rather than
    # one screen - so the three items go in between.
    #
    # THE PATH IS VERBATIM AND WAS COUNTED IN THE CORPUS, not written from memory: `probe.corpus`
    # reports "Network > GlobalProtect > Gateways" across the gp (23 sections), help (15) and guide
    # (7) documents, and Help 11.2 p.1044 opens the screen with "GlobalProtect Network >
    # GlobalProtect > Gateways Select Network > GlobalProtect > Gateways to configure a GlobalProtect
    # gateway."
    ConfigObject("globalprotect-gateways", "Gateways", "Network", "GlobalProtect", "server",
                 where="Network > GlobalProtect > Gateways",
                 search_model="integrations.GlobalProtectGateway"),
    # Network > GlobalProtect > Gateways > <gateway-config> > Authentication, 2026-11-02, for
    # PAN-GPG-002. The FIRST page over `integrations.GlobalProtectGatewayClientAuth`.
    #
    # ITS OWN ITEM AND NOT THE GATEWAY'S, for the reason the sibling portal item records: the row is
    # a CHILD of the gateway with a grain of its own, and one gateway's rows can sit at different
    # severities. Sending a reader to `Network > GlobalProtect > Gateways` would hand them a grid of
    # gateways with no indication which row of which gateway's table the finding is about.
    #
    # THE PLACEHOLDER IS THE VENDOR'S OWN, verbatim from Help 11.2 p.1046: "GlobalProtect Gateway
    # Authentication Tab • Network > GlobalProtect > Gateways > <gateway-config> > Authentication".
    # `probe.corpus` finds that string once in each of Help 11.1, 11.2 and 12.2.
    ConfigObject("globalprotect-gateway-authentication", "Gateway Client Authentication",
                 "Network", "GlobalProtect", "shield",
                 where="Network > GlobalProtect > Gateways > <gateway-config> > Authentication",
                 search_model="integrations.GlobalProtectGatewayClientAuth"),
    # Network > GlobalProtect > Gateways > <gateway-config> > Agent, 2026-11-02, for PAN-GPG-003
    # and -004. The FIRST page over `integrations.GlobalProtectGatewayAgentConfig`.
    #
    # ITS `where` NAMES THE PARENT TAB AND NOT A LEAF, and this one is a real choice rather than a
    # shortcut. THE AGENT CONFIGURATION IS NOT ONE SCREEN: Help 11.2 p.1048 enumerates six child
    # tabs beneath `Agent > <agent-config>` - "Tunnel Settings Tab • Client Settings Tab • Client IP
    # Pool Tab • Network Services Tab • Connection Settings Tab • Video Traffic Tab • HIP
    # Notification Tab" - and this subject's clause fields are spread across them: the cookie pair
    # is on Client Settings (p.1051), the local-network switch and the split-tunnel lists are on
    # Client Settings too (p.1053-1055), and the eighth exclusion axis is on Video Traffic (p.1060).
    # Naming any one leaf would send a reader to the wrong screen for most of the columns, so the
    # parent is the address that is true for all of them. `globalprotect-coverage` faced the same
    # question one item below and named the group for the same reason.
    #
    # AND THE VENDOR CONTRADICTS ITSELF ON THIS PATH, which is why it is quoted from the children.
    # The Help's own breadcrumb directly under the heading "GlobalProtect Gateways Agent Tab" reads
    # "Network > GlobalProtect > Portals > <portal-config> > Agent" - the PORTAL object, on the
    # gateway's screen - while every one of the six child tabs beneath it reads "Network >
    # GlobalProtect > Gateways > <gateway-config> > Agent > <agent-config> > ...". The children are
    # followed here. Already recorded in `reference/known-vendor-contradictions.md` under "The
    # `GlobalProtect Gateways Agent Tab` breadcrumb names the PORTAL object", so this run appended
    # nothing and confirmed the sighting.
    ConfigObject("globalprotect-gateway-agent", "Gateway Agent Configuration",
                 "Network", "GlobalProtect", "monitor",
                 where="Network > GlobalProtect > Gateways > <gateway-config> > Agent",
                 search_model="integrations.GlobalProtectGatewayAgentConfig"),
    ConfigObject("globalprotect-coverage", "GlobalProtect Coverage", "Network", "GlobalProtect",
                 "clipboard-check",
                 where="Network > GlobalProtect",
                 search_model="integrations.GlobalProtectEnforcementPoint"),
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
