"""Presentation for the `network-hardening` domain: PAN-NET-001 to 007, over five tabs.

FIVE TABS, FIVE CONTROL TYPES, THREE PAN-OS CATEGORIES. `_object_domain(slug, T.TYPE)` keys per
control type, so the tab count is the control-type count and not a choice. The categories are
DERIVED from the rail (`category=""` on every spec here) and they come out as three rather than
one, which is a first for this stage: `Network > Interfaces`, `Network > DHCP` and
`Network > Virtual Routers` are Network, `Device > Setup > Session` is Device, and
`Policies > Tunnel Inspection` is a policy rulebase. Each rail item's `where` is quoted from
PAN-OS Web Interface Help 11.2 in `configuration_navigation`, section by section.

EVERY HEADING AND EVERY TAB TITLE BELOW IS A PROPOSAL, on the precedent
`artifacts/sheets/objects.py` sets in terms - "EVERY HEADING BELOW IS A PROPOSAL ... Jason takes
the heading pass once across many domains (P399)". Where the vendor has its own word it is used
and sourced; where it has none that is SAID rather than implied, and the three cases are named
under each map.

THE TWO GREPS, ANSWERED PER MODEL AND PER FIELD, because this domain is in opposite states on
one domain's worth of tabs. Measured by Django introspection 2026-11-03, not by grep over source:

    field                             model                 choices  DERIVED_FIELDS  reader
    out_of_service_residue            Interface             YES(8)   model declares   MANDATORY
    lldp_enabled                      Interface             no       none at all      FORBIDDEN
    lldp_announced_content            Interface             YES(6)   none at all      MANDATORY
    session_rematch                   PanOsSessionSettings   no      not derived      REFUSED
    rematch_known                     PanOsSessionSettings   (not a model field)      FORCED
    ipv6_firewalling                  PanOsSessionSettings   no      not derived      FORBIDDEN
    dhcp_server_configured            PanOsDhcpInterface..   no      DERIVED          FORBIDDEN
    dhcp_relay_state                  PanOsDhcpInterface..   YES(3)  DERIVED          MANDATORY
    dhcp_server_mode                  PanOsDhcpInterface..   YES(3)  not derived      MANDATORY
    tunnel_inspection_coverage_state  PanOsTunnelInspect..   YES(8)  DERIVED          MANDATORY
    authentication_strength           PanOsRoutingAdjac..    YES(7)  DERIVED          MANDATORY
    protocol                          PanOsRoutingAdjac..    YES(4)  not derived      MANDATORY
    prefix_limit_state                PanOsRoutingAdjac..    YES(4)  DERIVED          MANDATORY

`FORBIDDEN` is the hard half of P462 and it is not a style rule: `get_<field>_display()` exists
ONLY on a field declaring `choices`, so on the `BooleanField` beside it the call raises
`AttributeError` at TEMPLATE RENDER - past `django check` and past all three cross-domain gates.
`display_value` already answers a boolean correctly ("Yes"/"No", `findings.py:469-470`), so the
three booleans here need nothing and must not be given it.

PAN-NET-003 IS THE FIRST CONTROL IN THE PIPELINE WHERE A READER IS MANDATORY ON ONE CLAUSE FIELD
AND FATAL ON THE OTHER, and both are clause fields of the SAME query on the SAME row.
`lldp_announced_content` is a `CharField` with six choices, so without a reader its cell prints
the stored key `unknown_global_defaults` under a vendor heading; `lldp_enabled` is a
`BooleanField` with no `choices` at all. `test_network_hardening_presentation` pins BOTH by name,
because the next person to touch this sheet will see one reader and add the matching one.

`Interface` IS NOT A `ProvenancedMixin` AND DECLARES NO `DERIVED_FIELDS` AT ALL - which is a
different thing from the empty tuple, and it is the state the contract's lesson 6 says cannot
build a tab. IT BUILDS. `build_findings_table`'s closure reads
`field in getattr(_model, "DERIVED_FIELDS", ())` (`findings.py:731`), made defensive by run 147
on 2026-11-02 for `integrations.Zone`, which is the same shape. So the trap is FIXED and the
warning is stale; measured on built rows here rather than reasoned about.

What it does mean is that nothing writes a `FieldProvenance` row for an interface - not per field
and not an `__entry__` - so every provenance cell on the Interfaces tab reads **"Not recorded"**,
which is the vocabulary's own words for "nothing tracks that field" and is TRUE here. So that tab
owes nothing for P451 ON CORRECTNESS, which is a first, and the reason is the opposite of the one
predicted: not that its fields are stored and keep their row, but that the model carries no
provenance at all and "Not recorded" is the accurate answer rather than the defective one.

THE PROVENANCE DECISION PER TAB, EACH MEASURED ON BUILT ROWS AND NOT REASONED ABOUT. Three tabs
take the branching cell and two keep the default, and one of the two is a case where branching
would be WORSE - which is the part no earlier run has met:

  * `firewall_interface` BRANCHES, and only to DE-DUPLICATE. Default and branching both answer
    "Not recorded" for every field, so no truth value changes; but on the five PAN-NET-003 rows,
    the control with two clause fields, the default prints "Not recorded" TWICE in one cell and
    the branching cell prints it once. 19 single-field rows read identically either way.
  * `dhcp_interface_config` and `routing_adjacency` BRANCH BECAUSE THE DEFAULT IS FALSE. On DHCP
    the default reads `Not recorded | Derived | Derived` where the recorded truth is
    `Derived | Local` - it loses `dhcp_server_mode`'s real Local row to the reader, and calls the
    DERIVED `dhcp_server_configured` untracked. One row reads `Derived | Not configured`, the
    third answer, where that key was absent. On routing the default reads `Derived` for all three
    and so states that `protocol` is derived, which it is not; branching reads
    `Derived | Not recorded`.
  * `tunnel_inspection` KEEPS THE DEFAULT: one clause field, declared derived, reader prose
    "Derived", and branching prints the same single word. Nothing to de-duplicate.
  * `session_settings` KEEPS THE DEFAULT BECAUSE BRANCHING IS WORSE HERE, measured:
    default `Local | Derived` against branching `Local | Not recorded`. `rematch_known` has no
    model field, so `provenance_of` finds no row and no `DERIVED_FIELDS` entry and answers
    nothing - while the READER arm prints the reader's own "Derived", which is true. A branching
    cell cannot see a reader, so on a tab whose clause fields include a reader-only field the
    default is the more honest of the two. That is the limit of the `ha-panorama` remedy and it
    is recorded here because the rule as written ("MIXED -> the cell must branch") would have
    sent this tab the wrong way.

AND THE BRANCHING CELL IS WHAT MAKES THE READERS FREE ON THOSE TWO TABS. `build_rows` computes
the whole per-field provenance `cells` list and then DISCARDS it when the spec sets
`provenance_cell`, so the P451 price a reader normally pays on a measured payload key - the
`remediation_accessor` walk past the field's own row to an `__entry__` that is never written -
costs nothing where the sheet answers for itself. That is why `dhcp_server_mode` gets both its
English label and its recorded provenance, which it could not have had from either remedy alone.

THE ONE PRICE THIS DOMAIN REFUSED TO PAY IS ON `session_rematch`, and it is refused deliberately.
It is a nullable `BooleanField` whose NULL is the finding - "nobody ever established this
setting" - and `display_value` renders that NULL as `(none)`, which is contract finding 4's shape
exactly. A reader would print "Never established" and would also make `remediation_accessor`
skip the field's own `FieldProvenance` row, and that row is the only thing separating an ABSENT
key from one explicitly written. On the control whose second query is ABOUT the absence, losing
it is the wrong trade. So the reader is refused and the companion column says it instead - which
is what `rematch_known` is, and it is the one reader on this tab that was not a choice at all.
"""

from __future__ import annotations

from .artifacts.layout import NONE, ha_role
from .artifacts.sheets import findings as findings_sheet


# --------------------------------------------------------------------- provenance

def provenance_cell(subject, provenance_of, fields) -> str:
    """What is RECORDED about each clause field, derived and measured told apart.

    Copied in form from `ha_panorama_presentation.provenance_cell`, which is the first branching
    cell in this repository, and used here on the two tabs whose clause fields are MIXED.

    Signature is `build_rows`' own: (subject, provenance_of, [(field, stored), ...]), with
    `fields` already narrowed to what the row shows and in the order the per-field cells are
    written, so this cell reads across with Setting and Fires when.

    `provenance_of` is read DIRECTLY rather than through `remediation_accessor`. The latter
    discards a DERIVED row on purpose - "DERIVED counts as no answer", `findings.py:563-564` -
    and then walks to an `__entry__` row that `write_node_row` never writes
    (`services_settings.py:37`), so the default cell reads "Not recorded" over a column that is
    derived deliberately and by a declaration on the model.

    DISTINCT ANSWERS, worst-known-first as encountered, matching `member_provenance`'s rule: a
    tab whose three clause fields are two DERIVED and one Local prints two lines, not three.
    Nothing is decided here - the cell prints what was recorded, and "at least three answers"
    is the measured state rather than two (`ha-panorama` met "Derived / PAN-OS default" on an
    absent management slot).
    """
    labels = []
    for field, _stored in fields:
        label, _template = findings_sheet.provenance_cells(provenance_of(field), stored=True)
        if label not in labels:
            labels.append(label)
    return "\n".join(labels) or "Not recorded"


# --------------------------------------------------------------------- value readers

#: `Interface.out_of_service_residue` - eight choices, and the stored keys are phrases
#: (`stripped_and_shut_down`, `administrative_state_unknown`) that would reach a customer as
#: snake_case under a vendor heading. `display_value` never calls a display method (P457), so
#: this reader is the only route to the label.
#:
#: `provenance` IS NOT "Derived" DELIBERATELY. A reader whose prose equals the DERIVED label
#: triggers the `remediation_accessor` walk (`findings.py:748-752`); anything else is printed
#: verbatim. `Interface` carries no `FieldProvenance` rows at all, so the walk has nothing to
#: find and the honest word is the vocabulary's own for an untracked field.
OUT_OF_SERVICE_RESIDUE = findings_sheet.ValueReader(
    read=lambda i: i.get_out_of_service_residue_display(),
    provenance="Not recorded")

#: `Interface.lldp_announced_content` - six choices. Same argument as above. NOTE that
#: `lldp_enabled`, the OTHER clause field of the same control, same query and same row, gets NO
#: reader: it is a `BooleanField` with `choices=None`, so `get_lldp_enabled_display()` does not
#: exist and calling it raises `AttributeError` at template render. Both are pinned by name in
#: `test_network_hardening_presentation.test_one_reader_and_one_refusal_on_pan_net_003`.
LLDP_ANNOUNCED_CONTENT = findings_sheet.ValueReader(
    read=lambda i: i.get_lldp_announced_content_display(),
    provenance="Not recorded")

#: `rematch_known` IS NOT A FIELD OF `PanOsSessionSettings` AND THIS READER IS WHY THE TAB
#: EXISTS. PAN-NET-002's shipped calibration "Setting never established" clauses on it, and
#: `tested_fields` (`findings.py:415-421`) RAISES `ValueError` on a tested field the model
#: neither stores nor computes unless the sheet declares a `value_reader` for it. So this is the
#: contract's finding 4, third case: the price is paid whether anyone wants it or not.
#:
#: AND THERE IS SOMETHING HONEST BEHIND IT, which is the part the dispatch brief had backwards.
#: The brief said `session_rematch` is "a non-nullable `BooleanField(default=False)` with no
#: `*_known` companion" and that the column therefore could not be filled. Measured by Django
#: introspection 2026-11-03: `session_rematch` is `BooleanField(null=True, blank=True)` with NO
#: default. The NULL is real and it is exactly the state the clause is about.
#:
#: The semantics are not invented here either - they are the shipped search compiler's, verbatim.
#: `search/session_settings/compiler.py:10` declares "`rematch_known` IS A VIRTUAL FIELD OVER
#: `session_rematch__isnull` AND IT IS THE SHIPPED ANSWER", registered as
#: `build_boolean_compiler("rematch_known", "session_rematch__isnull", invert=True)`, on a
#: convention three other compilers already use (`address_object.size_known`,
#: `collection_attempted`, `management_ssh.rekey_interval_known`). This reader is that predicate
#: and nothing more: a clause matching `rematch_known eq false` selects the rows this cell reads
#: "No" on, by construction.
#:
#: `provenance` is the DERIVED label, so the cell takes the remediation walk and falls back to
#: this prose when it finds nothing - which it does, no `__entry__` row being written for this
#: model. The value IS derived: it is read off the nullness of the key beside it, whose own
#: provenance row is in the next cell along.
REMATCH_KNOWN = findings_sheet.ValueReader(
    read=lambda s: "Yes" if s.session_rematch is not None else "No",
    provenance="Derived")

#: `PanOsDhcpInterfaceConfig.dhcp_relay_state` - three choices, declared DERIVED on the model, so
#: this reader is free of the P451 price twice over: once because the field is derived, and once
#: because this sheet sets `provenance_cell` and `build_rows` discards the per-field cells.
DHCP_RELAY_STATE = findings_sheet.ValueReader(
    read=lambda d: d.get_dhcp_relay_state_display(),
    provenance="Derived")

#: `PanOsDhcpInterfaceConfig.dhcp_server_mode` - three choices AND a measured payload key, the
#: one combination where the reader normally costs the column's own provenance row. It does not
#: here: the sheet's `provenance_cell` reads `provenance_of` directly, so the recorded answer for
#: this key reaches the row and the label reaches the cell. Measured on built rows: three rows
#: read `Local` for this key and one reads `Not configured`, the third answer, where the key was
#: absent - which the default cell printed as "Derived" for all four.
#:
#: NULLABLE, and the NULL is a real reading - no `mode` key under a server branch that exists -
#: which `display_value` would print `(none)` for. This reader says "No mode key" instead, rather
#: than `layout.NONE`: the em dash is for a branch that does not exist on this subject, and here
#: the branch DOES exist and the key inside it does not, which is a different statement.
DHCP_SERVER_MODE = findings_sheet.ValueReader(
    read=lambda d: (d.get_dhcp_server_mode_display() if d.dhcp_server_mode
                    else "No mode key"),
    provenance="Derived")

#: `PanOsTunnelInspectionCoverage.tunnel_inspection_coverage_state` - eight choices, declared
#: DERIVED. The only clause field on its tab, so the tab keeps the default per-field cell and
#: this reader's prose is what that cell prints.
TUNNEL_COVERAGE_STATE = findings_sheet.ValueReader(
    read=lambda t: t.get_tunnel_inspection_coverage_state_display(),
    provenance="Derived")

#: `PanOsRoutingAdjacency.authentication_strength` - seven choices, declared DERIVED.
AUTHENTICATION_STRENGTH = findings_sheet.ValueReader(
    read=lambda a: a.get_authentication_strength_display(),
    provenance="Derived")

#: `PanOsRoutingAdjacency.prefix_limit_state` - four choices, declared DERIVED.
PREFIX_LIMIT_STATE = findings_sheet.ValueReader(
    read=lambda a: a.get_prefix_limit_state_display(),
    provenance="Derived")

#: `PanOsRoutingAdjacency.protocol` - four choices, and NEITHER derived NOR a payload key: it is
#: part of the row's identity (the model's uniqueness constraint carries it, because a BGP peer
#: and an OSPF attachment can share a name and are different things). So it has no provenance row
#: and is not declared computed either, which is the third state and the reason this tab's cell
#: must branch rather than print a constant.
#:
#: IT IS A SCOPE CLAUSE THAT BECAME A PRESENTED COLUMN. Stage 5 gives it `role: "scope"` on
#: PAN-NET-007's second record, and it is a clause of the shipped "BGP peer with no enforced
#: prefix ceiling" query, so `tested_fields` derives a column for it among the verdict columns.
#: It is NOT in that query's `asserted_fields` (`["prefix_limit_state"]`), so it is not marked -
#: confirmed on a built row, which is the first confirmation anyone has had that the 2026-10-28
#: mark fix behaves on a scope clause.
PROTOCOL = findings_sheet.ValueReader(
    read=lambda a: a.get_protocol_display(),
    provenance="Derived")


# --------------------------------------------------------------------- subject columns

#: EVERY SUBJECT COLUMN HERE NAMES ITS `field` WHERE IT PRESENTS ONE, which is lesson 5 of the
#: first shape-B run: a subject column that declares no field does NOT suppress the derived
#: settings column for the same attribute, so one value reaches the tab twice under two headings
#: and the duplicate-header guard never fires because the headings differ.
#:
#: NONE OF THESE IS A CLAUSE FIELD, deliberately. `ipsec-crypto` kept every stage 5 clause field
#: in stage 5's relative order and moved none of them into its subject block; `ike-crypto` moved
#: one and changed what its customers read first. This domain follows `ipsec-crypto`, so the
#: column order a customer meets is the one stage 5's clauses and the shipped query names
#: produce, with nothing of mine in front of it.

#: One port of one appliance. The interface namespace is device-wide rather than vsys-scoped, so
#: there is no vsys column; on an HA pair a synchronised port draws TWO rows and `HA role` is
#: what tells them apart.
INTERFACE_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
    ("Interface", 16, False, lambda s, _p: s.name or NONE, "name"),
)

#: One `network/dhcp/interface` entry of one appliance. The entry's NAME is an interface name
#: rather than an operator-chosen label - measured by stage 5 - so the column is headed as the
#: port it is.
DHCP_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
    ("Interface", 16, False, lambda s, _p: s.interface_name or NONE,
     "interface_name"),
)

#: One vsys of one appliance. This is the only vsys-scoped subject in the domain, and the row
#: carries its vsys name because a tunnel-inspect rulebase is vsys-scoped content. `Scope`
#: follows the config subtree the value came from rather than which read returned it.
TUNNEL_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
    ("Virtual system", 14, False, lambda s, _p: s.vsys_name or NONE, "vsys_name"),
    ("Scope", 10, False, lambda s, _p: s.get_scope_display(), "scope"),
)

#: One adjacency within one router within one appliance. `Protocol` is NOT here - it is a clause
#: field and stays in the settings block for the reason the block comment above gives - so the
#: identity a reader assembles is Appliance + Virtual router + Adjacency, with the protocol a few
#: columns to the right. Recorded as a deliberate cost of keeping stage 5's clause order intact.
ROUTING_SUBJECT = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
    ("Virtual router", 18, False, lambda s, _p: s.router_name or NONE,
     "router_name"),
    ("Adjacency", 20, False, lambda s, _p: s.adjacency_name or NONE,
     "adjacency_name"),
)


# --------------------------------------------------------------------- setting labels

#: EVERY ENTRY IS A PROPOSAL (P399). A heading with no entry here falls back to the raw Django
#: field name, so declaring a column without a label IS choosing to show a customer a database
#: field name - which is why every clause field of all five tabs has one.
#:
#: VENDOR WORD WHERE THERE IS ONE, SAID WHERE THERE IS NOT:
#:   `lldp_enabled`             the vendor's own switch, `Network > Interfaces` > Advanced > LLDP
#:                              "Enable" (Help 11.2 p.402, Layer 3 Interface).
#:   `out_of_service_residue`   NO VENDOR WORD. It is this assessment's verdict over what is left
#:                              bound to a port that is administratively down - the vendor
#:                              describes the ingredients (Link State, Interface Mgmt Profile)
#:                              and has no term for the residue.
#:   `lldp_announced_content`   NO SINGLE VENDOR WORD. The ingredients are the LLDP Profile's
#:                              "Option TLVs" - Management Address, System Description and the
#:                              rest (Help 11.2 p.688-689, `Network > Network Profiles > LLDP
#:                              Profile`); the roll-up over them is ours.
INTERFACE_LABELS = {
    "out_of_service_residue": "Residue on an out-of-service port",
    "lldp_enabled": "LLDP enabled",
    "lldp_announced_content": "LLDP announced content",
}

#: BOTH VENDOR WORDS ARE VERBATIM from `Device > Setup > Session`, Help 11.2 p.779-780:
#: "Rematch Sessions Click Edit and select Rematch Sessions to cause the firewall to apply newly
#: configured security policy rules to sessions that are already in progress", and "Enable IPv6
#: Firewalling To enable firewall capabilities for IPv6 traffic".
#:
#: `rematch_known` HAS NO VENDOR WORD AND CANNOT: it is not a setting on the screen, it is
#: whether the setting was ever written. The heading says that rather than implying a switch.
SESSION_LABELS = {
    "session_rematch": "Rematch Sessions",
    "rematch_known": "Rematch setting established",
    "ipv6_firewalling": "IPv6 Firewalling",
}

#: `Network > DHCP` (Help 11.2, section `Network > DHCP`, whose children are DHCP Server, DHCP
#: Relay and DHCP Client). "Mode" is the vendor's own label on the DHCP Server tab; the other two
#: headings are ours over verdicts the vendor has no word for - whether a server branch exists at
#: all, and what a relay branch amounts to.
DHCP_LABELS = {
    "dhcp_server_configured": "DHCP server branch present",
    "dhcp_relay_state": "DHCP relay state",
    "dhcp_server_mode": "DHCP server mode",
}

#: NO VENDOR WORD. `Policies > Tunnel Inspection` (Help 11.2 p.182-184, "Building Blocks in a
#: Tunnel Inspection Policy") describes the rulebase and its rules; there is no vendor term for
#: a verdict over the whole rulebase of a vsys, and the commonest state here is that NO RULE
#: EXISTS, which a per-rule word could not name.
TUNNEL_LABELS = {
    "tunnel_inspection_coverage_state": "Tunnel inspection coverage",
}

#: `Network > Virtual Routers` (Help 11.2, BGP at p.517). "Max Prefixes" is the vendor's own
#: label on the BGP peer; "Protocol" is the vendor's own word for the distinction. The
#: authentication heading is ours: the vendor names the mechanisms (BGP Auth Profile, OSPF Auth
#: Profile) and has no word for their relative strength, which is what the column grades.
ROUTING_LABELS = {
    "authentication_strength": "Adjacency authentication",
    "protocol": "Protocol",
    "prefix_limit_state": "Prefix ceiling enforced",
}
