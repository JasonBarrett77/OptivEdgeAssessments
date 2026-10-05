"""Engineer-detail xlsx, prototype: the security-policy controls. PAN-POL-004 today.

The first NAMED-OBJECT findings sheet, and the first whose subject is not an appliance. Jason,
2026-09-17: "one row per subject finding, or per finding, except where multiple findings exist per
subject ... Later, we can implement a collapse function that collapses by provenance + subject, and
then lists the targets. Let's build the per target+subject view first." So: one row per finding.

WHAT A RULE NEEDS THAT A DEVICE SETTING DID NOT.
- ITS OWN SUBJECT COLUMNS. A rule is identified by its name and where it sits - the vsys and the
  rulebase - and read by what it does: its action and its service. Those four are columns, not
  lines inside a tested-value cell, because they are what an engineer scans a policy sheet for.
- NO APPLIANCE. A rule belongs to a vsys, which on an HA pair spans both firewalls, so there is
  no one appliance to name or to link to. The Firewalls column lists the pair, from the same
  topology the Appliances tab reports.
- A VALUE HELD ON RELATED ROWS. `service` is not a column: a rule's services are
  `SecurityRuleService` rows. `SERVICE_READER` reads them, for the Service column and for any
  control that tests the field without this sheet presenting it.
- ONE SOURCE, FOR THE RULE. A rule is pushed as a unit and an override replaces all of an
  object's values, so "where did this come from" has one answer per rule - the Device group
  column, blank where the rule is the firewall's own. The exception is the Notes column.

WHAT IS NOT HERE YET. The collapse by provenance + subject Jason described: 205 of this run's 390
findings are rules, and most are one device group's pushed rules repeated per vsys. This sheet is
the per target+subject view that collapse would fold.
"""
from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from optivedge_integrations.integrations.presentation import address_breadth_label

from ..layout import NONE, SheetInfo, appliance_names

def joined(rows, attribute="value") -> str:
    """Member values in CONFIGURED order, ONE PER LINE - the order PAN-OS shows them in.

    A line each rather than a comma list (Jason, 2026-09-18): a rule names objects whose own names
    contain hyphens and read as phrases, and a wrapped comma list makes the boundary between two
    of them a guess.

    "(empty)" rather than a blank cell: a rule with no member of a kind is a real state, and on a
    security rule it is usually `any` written another way.
    """
    return "\n".join(str(getattr(row, attribute)) for row in rows) or "(empty)"


def with_breadth(members: str, num_hosts) -> str:
    """Member names, then how much address space they come to - PAN-POL-002's subject.

    In this cell rather than a column of its own because the names and their size are one fact:
    a list of names says nothing about how much space it covers, and one name can be a /8. The
    same line appears on the configuration explorer's rule rows, from the same helper.

    On a NEGATED side the number is the size of the complement, so it is deliberately the one
    line here that does not describe the names above it. That is what the rule permits, and
    `raw_value` keeps the "NOT" implicit in the control's own Fires when cell.
    """
    return f"{members}\n{address_breadth_label(num_hosts)}"


#: A rule's services live on `SecurityRuleService` rows, in configured order.
SERVICE_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.securityruleservices.all()),
)

#: None of these carries a `provenance` line: a rule member records a raw marker string of its own
#: rather than a `FieldProvenance` row, and this tab shows the rule's single source instead - a
#: rule is pushed as a unit. The readers exist so a control testing one of these fields finds its
#: value.
#:
#: Addresses are REFERENCES: `raw_value` is what the rule names - an object, a group, `any` - which
#: is what an engineer reads in the UI and searches the configuration for. What each reference
#: resolves to is a question for the objects domain, not for this cell.
SOURCES_READER = findings_sheet.ValueReader(
    read=lambda rule: with_breadth(
        joined(rule.source_address_refs.all(), "raw_value"), rule.source_num_hosts),
)
DESTINATIONS_READER = findings_sheet.ValueReader(
    read=lambda rule: with_breadth(
        joined(rule.destination_address_refs.all(), "raw_value"), rule.destination_num_hosts),
)
APPLICATIONS_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.securityruleapplications.all()),
)


def firewalls(rule) -> str:
    """The appliances that enforce this rule's vsys, one per line - the enforcement point's OWNER,
    which the model guarantees is exactly one of an appliance group or an appliance."""
    point = rule.enforcement_point
    return appliance_names(point.appliance_group or point.appliance)


def enforcement_point_label(rule) -> str:
    """"fw-core-tpa-a+fw-core-tpa-b/vsys1" - the vsys AND the firewalls that run it.

    A vsys name is unique only per firewall (Jason, 2026-09-18): pan-fw-111 vsys1 and the tpa
    pair's vsys1 are different entities, so a list of bare vsys names across firewalls says
    nothing about which is which. On an HA pair both members run the same vsys, and both are
    named.
    """
    return f"{firewalls(rule).replace(chr(10), '+')}/{rule.enforcement_point.vsys_name}"


def device_group(rule, provenance_of) -> str:
    """The device group that pushed the RULE, or blank where it is the firewall's own.

    A rule is pushed as a unit and an override replaces all of an object's values, so this is one
    answer for the whole rule rather than one per tested field. Blank means local: the Rulebase
    column says so in the same breath, and a word here would only repeat it. The exception - a
    field recording a different source - is what the Notes column is for.
    """
    row = provenance_of("__entry__")
    if row is None:
        return "Not recorded"
    return row.raw_value if row.provenance_type == "device_group" else ""


def field_source_notes(rule, provenance_of, fields) -> str:
    """The exception to "one rule, one source", and nothing when there is none.

    Where a field records a source different from the rule's own - another device group, or a
    template - the Provenance cell alone would be wrong for that field, so it is written out here.
    """
    entry = provenance_of("__entry__")
    entry_key = (entry.provenance_type, entry.raw_value) if entry is not None else None
    notes = []
    for field, stored in fields:
        row = provenance_of(field) if stored else None
        if row is None:
            continue
        if (row.provenance_type, row.raw_value) != entry_key:
            source = row.raw_value or row.get_provenance_type_display()
            notes.append(f"{field} came from {source}")
    return "\n".join(notes)


def rulebase(rule) -> str:
    """"Pre-Rulebase", not "Pushed Pre-Rulebase": the Device group column beside it already says
    what pushed it, so the vendor label's prefix is a second answer to a question nobody asked."""
    return rule.get_config_source_display().removeprefix("Pushed ")


#: What an engineer scans a policy sheet for, left to right (Jason, 2026-09-17): the rule, who
#: enforces it, where it lives, who pushed it, and what it does. `hidden_fields` keeps the same
#: fields out of the tested-value cells, and `tested_columns=()` drops that block entirely.
SUBJECT_COLUMNS = (
    # Where it is enforced, then which rule, then what it matches and does.
    ("Firewalls", 16, True, lambda rule, _p: firewalls(rule)),
    ("Vsys", 10, False, lambda rule, _p: rule.enforcement_point.vsys_name or NONE),
    ("Device group", 26, False, device_group),
    ("Rulebase", 16, False, lambda rule, _p: rulebase(rule)),
    ("Rule name", None, False, lambda rule, _p: rule.name or NONE),
    # Width None: sized to the longest LINE on the sheet, so no object name wraps and the list
    # reads as one name per line rather than a paragraph (Jason, 2026-09-18).
    ("Sources", None, True, lambda rule, _p: SOURCES_READER.read(rule), "source_address"),
    ("Destinations", None, True, lambda rule, _p: DESTINATIONS_READER.read(rule),
     "destination_address"),
    ("Service", 24, True, lambda rule, _p: SERVICE_READER.read(rule), "service"),
    ("Application", 24, True, lambda rule, _p: APPLICATIONS_READER.read(rule), "application"),
    ("Action", 10, False, lambda rule, _p: rule.action or NONE, "action"),
)

SOURCE_COLUMNS = (
    ("Notes", 30, True, field_source_notes),
)

SPEC = findings_sheet.DeviceSettingSheet(
    title="Security Rules",
    #: This sheet names its settings itself - Sources, Service, Action - rather than taking a
    #: column per tested field.
    auto_setting_columns=False,
    control_types=(Control.ControlType.SECURITY_RULE,),
    subject_columns=SUBJECT_COLUMNS,
    source_columns=SOURCE_COLUMNS,
    value_readers={
        "service": SERVICE_READER,
        "source_address": SOURCES_READER,
        "destination_address": DESTINATIONS_READER,
        "application": APPLICATIONS_READER,
    },
    #: Every field PAN-POL-004 tests has a column of its own here, so the tested-value block -
    #: Setting, Observed value, Fires when, Provenance - would print nothing this sheet does not
    #: already say. A control testing a field with no column will need it back.
    tested_columns=(),
    hidden_fields=("config_source", "action", "service", "source_address", "destination_address",
                   "application",
                   # PAN-POL-002. The Sources and Destinations columns carry both the members and
                   # the side's host count, so a column per breadth field would repeat them -
                   # and `*_breadth_known` is the same fact as the count being Unknown.
                   "source_num_hosts", "destination_num_hosts",
                   "source_breadth_known", "destination_breadth_known",
                   # A SCOPE condition rather than an observation: PAN-POL-002 excludes disabled
                   # rules, so every row on this sheet is an enabled rule by construction. The
                   # Fires when cell states it on the surfaces that carry that block.
                   "disabled"),
    #: A rule belongs to a vsys, not to one appliance: nothing to link to on the Appliances tab.
    appliance_of=lambda rule: None,
    subject_select_related=("enforcement_point__appliance_group", "enforcement_point__appliance"),
    #: The service members every row reads, and the HA pair the Firewalls column lists.
    subject_prefetch=("securityruleservices", "securityruleapplications",
                      "source_address_refs", "destination_address_refs",
                      "enforcement_point__appliance_group__appliances"),
    description=("The security policy each firewall enforces: what the rules allow, how tightly "
                 "they are scoped, and where each rule comes from."),
)


def write_sheet(build) -> SheetInfo:
    return findings_sheet.write_sheet(build, SPEC)
