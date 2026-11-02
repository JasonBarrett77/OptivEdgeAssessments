"""Engineer-detail xlsx: what a virtual system's WHOLE policy does not do.

`security-policy`, stage 9, 2026-11-01. PAN-POL-007, -010, -017, -018 and -019.

THE ROW IS THE VIRTUAL SYSTEM AND NOT A RULE, and on this tab that is not a convenience. Every
column of `VsysRulePosture` is a statement about the ABSENCE of a rule somebody should have
written - no catch-all refusal recording its sessions, no refusal of named applications above the
permits, no rule naming a region, no refusal matched on a port - and a rule-keyed row cannot
report a rule that does not exist. The subject is real whether or not the vsys has a rulebase node
at all: on both lab PA-5220s three of nine virtual systems have no `rulebase/security/rules` node
and each one still enforces the two rules PAN-OS ships.

NO APPLIANCE COLUMN AND NOTHING TO LINK TO ON THE APPLIANCES TAB, the same as the Security Rules
tab and for the same reason: a vsys belongs to an enforcement point, which on an HA pair spans
both firewalls, so naming one of them would assert something false. The Firewalls column lists
the pair. Stage 5 declared this grain - "one enforcement point - one virtual system of one
appliance OR HA pair" - and these two columns are where the tab honours it.

NO SOURCE COLUMNS, AND THE PROVENANCE CELL IS ANSWERED BY THIS SPEC RATHER THAN BY THE DEFAULT.
Every column on the model is in its `DERIVED_FIELDS` - "EVERY column is computed at normalization
and no payload key carries any of them, so none can have a provenance row" - so the default
Template column would be blank on every row of every estate.

THE DEFAULT PROVENANCE CELL READ "Not recorded", MEASURED ON RENDERED ROWS, and that is the wrong
answer rather than a plain one. `build_rows` resolves a derived field through
`remediation_accessor`, which discards a DERIVED row on purpose - "DERIVED counts as no answer...
it is the case the object has to answer" - and falls back to the object's own `__entry__`
provenance row. Nothing writes one for this model: `security_policy.py` creates the row with
`update_or_create` and records no provenance at all, by design. So the fallback finds nothing and
`provenance_cells(None)` answers "Not recorded", which means "nothing tracks that field" and
reads to a customer as a gap in the collection. The value is not untracked; it is DERIVED, and
the row is a verdict this assessment computed over the vsys's stored rules. `provenance_cell`
exists for a subject that answers once for the whole object, so this spec uses it to say that.

WHAT A ROW HERE CANNOT SAY, and it is a remediation gap the model records rather than one this
tab introduces: WHICH of the three rulebases an absence spans. A vsys's rule set is the
firewall-local rulebase plus the Panorama pre- and post-rulebases pushed to it; the model stores
no scope column, so an estate whose policy comes from Panorama can be told to add a rule to a
vsys rulebase the firewall will not accept rules into. The distinction IS stored, on
`SecurityRule.config_source`. Joining back to it is a presentation question and this run did not
answer it.
"""
from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from ..layout import NONE, SheetInfo, appliance_names


def firewalls(posture) -> str:
    """The appliances that enforce this virtual system, one per line.

    The enforcement point's OWNER, which the model guarantees is exactly one of an appliance
    group or an appliance - the same walk the Security Rules tab makes, and deliberately the same
    text, so one vsys reads the same on both tabs.
    """
    point = posture.enforcement_point
    return appliance_names(point.appliance_group or point.appliance)


#: Where the policy is enforced, then which virtual system. Neither declares a `field`: the
#: verdicts the controls assert on are derived setting columns, and declaring one here would move
#: the value-at-fault mark off the verdict and onto the row's address.
SUBJECT_COLUMNS = (
    ("Firewalls", 16, True, lambda p, _prov: firewalls(p)),
    ("Vsys", 12, False, lambda p, _prov: p.enforcement_point.vsys_name or NONE),
)

#: PROPOSED HEADINGS, every one of them, for the derived setting columns. A heading is what a
#: customer reads, so none of these is a decision: the column SET comes from the controls' own
#: clauses and only the words are typed here. Without an entry a column would be headed
#: `has_application_block_rule_above_permits`.
#:
#: Each is phrased as the THING THAT SHOULD EXIST, so that "No" is the finding and "Yes" is the
#: healthy answer on every one of them. The exception is the count, which is phrased as what is
#: MISSING because that is what the column stores and what the control's severity turns on -
#: inverting it in presentation would put a number in the cell that no clause in the catalogue
#: mentions.
SETTING_LABELS = {
    # The applicability clause of all five controls. "Answered" rather than "Collected": the
    # column is false where no rulebase read came back for this vsys, and every verdict under it
    # would then be an absence nobody measured rather than an absence on the device.
    "rules_collected": "Rulebase read answered",
    # PAN-POL-010's two assertions.
    "has_logged_catch_all_deny": "Logged catch-all deny exists",
    "default_rules_log_session_end": "Default rules log at session end",
    # PAN-POL-007.
    "has_application_block_rule_above_permits": "Application block above the permits",
    # PAN-POL-017. A count of the two directions - traffic TO those addresses and traffic FROM
    # them - with no standing block rule. 0 is healthy, 2 is the worst band and the default.
    "vendor_hostile_list_block_directions_missing": "Hostile-list directions unblocked",
    # PAN-POL-018.
    "expresses_geographic_boundary": "Geography expressed anywhere",
    # PAN-POL-019.
    "has_port_matched_block_rule": "Port-matched block rule exists",
}

SPEC = findings_sheet.DeviceSettingSheet(
    title="Virtual System Rule Posture",
    control_types=(Control.ControlType.VSYS_RULE_POSTURE,),
    subject_columns=SUBJECT_COLUMNS,
    #: Derived from the five controls' clauses, in control order - so a sixth control on this
    #: subject brings its verdict column with it.
    auto_setting_columns=True,
    setting_labels=SETTING_LABELS,
    #: `Fires when` because every finding here is an ABSENCE and the cell beside it reads "No":
    #: without the failing condition a reader has the verdict and not the claim. `Provenance`
    #: because it reads "Derived" on every column, which is the one thing this tab must not
    #: leave a reader to assume.
    tested_columns=("Fires when (failing condition)", "Provenance"),
    #: Every column is computed at normalization and carries no provenance row - see the module
    #: docstring. A Template column would be blank on every row.
    source_columns=(),
    #: ONE ANSWER FOR THE WHOLE ROW, and the same word every other tab uses for a computed
    #: value. The default cell answers per tested field through the remediation walk, which on
    #: this model resolves to "Not recorded" for every verdict - see the module docstring for
    #: why that is wrong rather than merely terse.
    provenance_cell=lambda posture, provenance_of, fields: (
        findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label),
    #: A vsys spans both members of an HA pair: there is no one appliance to link to.
    appliance_of=lambda posture: None,
    subject_select_related=("enforcement_point__appliance_group", "enforcement_point__appliance"),
    #: The HA pair the Firewalls column lists.
    subject_prefetch=("enforcement_point__appliance_group__appliances",),
    description=("What each virtual system's policy does not do, taken as a whole: whether "
                 "anything refuses the traffic no rule allowed and records it, whether named "
                 "applications and the vendor's own hostile-address lists are refused at all, "
                 "and whether the policy says anything about geography or about ports. These "
                 "are findings about a MISSING rule, so they name the virtual system rather "
                 "than a rule."),
)


def write_sheet(build) -> SheetInfo:
    return findings_sheet.write_sheet(build, SPEC)
