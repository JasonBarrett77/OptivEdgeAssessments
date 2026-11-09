"""Finding generation for one zone protection profile. PAN-ZON-002, -003, -004, -005, -006.

FIVE CONTROLS, ONE MODEL, ONE TYPE - the ordinary case a one-to-one type map describes. Each of
the five asserts on a disjoint column of the same row, so one profile can legitimately carry five
findings, and `generate_object_findings` creates one per control per matched object.

THE DISPATCH BELOW DEFAULTS TO `()` AND THAT IS DELIBERATE. Measured across all 28 generators
that key a dispatch by control id, 2026-11-01: eighteen default to another control's arm tuple,
five to `()` and five to `None` and then deliberately say everything. A default that is another
control's arms is how a control reusing a type gets its finding described with someone else's
claims - this domain repaired exactly that in `zone_findings` for PAN-ZON-001, where
`_subject(zone, "PAN-ZON-001")` returned PAN-IOT-002's three device-identification arms BYTE FOR
BYTE. `()` makes the same mistake visible instead: a control with no entry gets the subject
sentence and no claim, which reads as incomplete rather than as an answer to a different question.

WHAT NO FINDING ON THIS MODEL MAY SAY, and all three are stage 5's words rather than this
module's:

- WHICH ZONE TYPE THE PROFILE IS ATTACHED TO. The profile holds no record of it - a single profile
  may be in force on an internal zone and an internet-facing one at once - and the vendor disables
  three of its mechanisms on an external zone (help p.663). So three of these columns can read
  true on a profile that enforces none of them there, and no column of any subject can say so.
- WHETHER THE SPOOFED-ADDRESS DROP IS EVEN WANTED HERE. The vendor asks for it on INTERNAL zones
  only, twice, and the predicate needs a fact no configuration holds. PAN-ZON-005 therefore fires
  on every profile in force, which is the fail-safe direction, and stage 3 requires the finding to
  SAY that the population was not established rather than imply it was. `_spoof_drop_off` carries
  that sentence; nothing downstream adds it.
- WHETHER THE NON-SYN REFUSAL IS UNDER A VENDOR-REQUIRED EXCEPTION. Three vendor documents say to
  disable it on a zone that controls the security policy for traffic a tunnel inspection rule
  opens, when session rematch is on - and the predicate needs three facts no column of this
  subject holds, the third of which is a judgment rather than a value. Same treatment:
  fire, and say the exception was not excluded.

THE RATES ARE NOT ASSERTED ANYWHERE AND THE SENTENCES SAY SO. Stage 5 discharges both rate halves
onto a question for a person - the zone's measured average and peak new-connection rates over a
full business week - because the vendor's own formulas are expressed in terms of them and stage 4
refused to license the documented defaults: it measured them from the dataplane ONLY for a flood
type whose enable had been set, the numbers differ by ACTION BRANCH, and for one flood type they
differ by firmware model across nine values. A clause comparing against the documented numbers
would pass a profile holding the vendor's own figures and fail one holding the right ones. And a
fact no column holds at all: a firewall with several dataplane processors divides a threshold
EQUALLY ACROSS THEM, so a stored 20,000 on a five-processor firewall fires at 4,000 per processor.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_zone_protection_profile_control_queries,
)
from assessments.models import (
    Control,
    ZoneProtectionProfileFinding,
    ZoneProtectionProfileFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import ZoneProtectionProfile

#: The four volumetric flood types PAN-ZON-003 rolls into one verdict, as the vendor's own tab
#: labels them. Named here so the finding can say WHICH of the four is off, which the derived
#: column cannot: it is a disjunction and holds no record of which arm made it true.
_VOLUMETRIC = (
    ("udp_flood_enabled", "UDP flood"),
    ("icmp_flood_enabled", "ICMP flood"),
    ("icmpv6_flood_enabled", "ICMPv6 flood"),
    ("other_ip_flood_enabled", "other-IP flood"),
)

#: The four packet drops PAN-ZON-006's second half asserts, which are the four the catalogue
#: row's DESCRIPTION names and not the six its longer prose does. `discard_record_route` and
#: `discard_timestamp` are the other two and NO VENDOR HARDENING LINE asks for either, so stage 3
#: does not assert them and neither does this sentence.
_PACKET_DROPS = (
    ("discard_malformed_option", "malformed IP option"),
    ("discard_strict_source_routing", "strict source routing"),
    ("discard_loose_source_routing", "loose source routing"),
    ("discard_overlapping_tcp_segment_mismatch", "mismatched overlapping TCP segment"),
)

#: The four scan types the profile can carry, in the FIXED id order the device uses. The entry's
#: id is a REFERENCE - `scan/entry[@name='8004']` is refused `'8004' is not a valid reference` -
#: so this is a closed set of four and not a sample of a child table.
_SCAN_TYPES = (
    ("scan_tcp_port_action", "TCP port scan", "8001"),
    ("scan_udp_port_action", "UDP port scan", "8002"),
    ("scan_host_sweep_action", "host sweep", "8003"),
    ("scan_ip_protocol_action", "IP protocol scan", "8006"),
)


def _syn_flood_off(obj) -> list[str]:
    """PAN-ZON-002's only configurational half: is SYN flood protection switched on."""
    if obj.syn_flood_enabled:
        return []
    return [
        "SYN FLOOD PROTECTION IS OFF on this profile, so the zones it is in force on meter no "
        "half-open TCP connection rate at all and a SYN flood reaches the firewall's own session "
        "table unthrottled",
        "the ABSENCE of the enable key reads as off, which is a vendor fact rather than an "
        "assumption here: stage 4 measured it as `no` on two independent oracles, one of them "
        "operational, so an untouched profile is genuinely unprotected rather than unread",
        "WHAT TO SET THE RATES TO IS NOT ASSERTED BY THIS FINDING and cannot be read off the "
        "configuration. The vendor's formulas are expressed in terms of this zone's own measured "
        "average and peak new-connection rates over at least a full business week, and the "
        "documented defaults differ by which response branch is configured - so switching the "
        "protection on with the shipped numbers is not the end of this remediation",
    ]


def _volumetric_flood_gap(obj) -> list[str]:
    """PAN-ZON-003's only configurational half: are the four volumetric flood types on."""
    if not obj.volumetric_flood_gap:
        return []
    off = [label for field, label in _VOLUMETRIC if not getattr(obj, field)]
    # The column is a DISJUNCTION and holds no record of which arm set it, so the arms are
    # re-read here. An empty list means the verdict and the four columns disagree, which is a
    # renormalisation window rather than a state of the device, and the sentence says that
    # instead of naming nothing.
    which = ", ".join(off) if off else (
        "a flood type this row's verdict column and its four enable columns disagree about, "
        "which happens only between a migration and the pass that recomputes them")
    return [
        f"AT LEAST ONE VOLUMETRIC FLOOD TYPE IS NOT PROTECTED on this profile: {which}",
        "each of the four is an independent leaf with its own response branch and its own three "
        "rates, so switching one on protects against one flood - which is why this is asserted "
        "four ways and not one. The catalog row carries a path for only the datagram flood, so "
        "a reading taken from the row alone audits a QUARTER of this control",
        "THE STREAM-CONTROL TRANSPORT'S INITIATION FLOOD IS NOT INCLUDED and must not be read "
        "into the other-IP arm: the vendor excludes it from that branch by its own definition, it "
        "has a branch of its own on this object, and no control anywhere asserts it",
        "the rates are not asserted here, for the reason the SYN flood arm gives: they rest on "
        "this zone's own measured traffic and the documented defaults differ per flood type",
    ]


def _scan_detection_gap(obj) -> list[str]:
    """PAN-ZON-004's first half: does detection fire on every scan type the profile can carry."""
    if not obj.scan_detection_gap:
        return []
    missing = [f"{label} (entry {entry_id})" for field, label, entry_id in _SCAN_TYPES
               if not getattr(obj, field)]
    weakest = obj.scan_weakest_action
    parts = []
    if missing:
        parts.append(
            "RECONNAISSANCE DETECTION IS NOT CONFIGURED FOR EVERY SCAN TYPE THIS PROFILE CAN "
            f"CARRY - no entry exists for {', '.join(missing)} - so those scans are not detected "
            "at all. THE DEVICE OFFERS FOUR SCAN TYPES AND THE CATALOG ROW NAMES THREE, so an "
            "audit taken from the row leaves the IP protocol scan entirely unexamined")
    if weakest:
        parts.append(
            f"the weakest action across the entries that DO exist is `{weakest}`, which does not "
            "record or stop the scan to the standard this control asserts")
    else:
        parts.append(
            "the weakest action reads as the EMPTY SENTINEL, which means a scan type with no "
            "entry rather than an entry with no action - the two are different states and the "
            "device treats the second as `alert`")
    parts.append(
        "AN ENTRY'S `Enable` CHECKBOX IS NOT A FIELD: a scan entry has exactly three children and "
        "no enable key, so the box is the ENTRY'S EXISTENCE and the remediation is to create the "
        "missing entry rather than to tick something on it")
    return parts


def _scan_sensitivity_unread(obj) -> list[str]:
    """PAN-ZON-004's second clause group, which stage 5 states in prose rather than in clauses.

    IT CAN FIRE TOGETHER WITH THE DETECTION GAP ABOVE AND THAT IS DELIBERATE, which is the
    opposite of the usual shape in this domain. A profile can have a detection gap AND an unread
    sensitivity, the two are separate remediations - create the missing entry, and read the
    thresholds - so reporting both is right rather than a duplicate.
    """
    if obj.scan_sensitivity_known:
        return []
    return [
        "AND THE SENSITIVITY OF THE DETECTION THAT DOES EXIST COULD NOT BE READ: the interval and "
        "threshold on this profile's scan entries are stored as a genuine absence, so whether the "
        "action is ever actually reached is unknown rather than answered",
        "it is reported rather than passed because NO OPERATOR IN THIS QUERY LANGUAGE REACHES AN "
        "ABSENT NUMBER - there is no is-null operator - so a threshold comparison would have "
        "silently passed every unedited profile in the estate, which is the whole estate. This "
        "arm is what makes the silence visible",
        "stage 3 asserts detection at the vendor's own default sensitivity OR TIGHTER precisely "
        "so that the action can be reached: an entry whose threshold sits at its ceiling detects "
        "almost nothing while reading as configured",
    ]


def _scan_exemptions_present(obj) -> list[str]:
    """PAN-ZON-004's SECOND assertion record: does the exemption list hand the protection back.

    A CONFIRMATION REQUEST AND NOT AN ACCUSATION, and stage 5 requires the finding to say so in
    those words. The control cannot establish that any exempted source is wrong, because no
    configuration says which hosts are the customer's own vulnerability-testing hosts.
    """
    if not obj.scan_white_list_count:
        return []
    return [
        f"RECONNAISSANCE DETECTION ON THIS PROFILE EXEMPTS {obj.scan_white_list_count} SOURCE "
        f"ADDRESS{'ES' if obj.scan_white_list_count != 1 else ''}, and every one of them is a "
        "source this profile will not detect a scan from however the entries above are set",
        "THIS IS A REQUEST FOR CONFIRMATION RATHER THAN A DEFECT: the vendor's bound is that only "
        "trusted internal groups performing vulnerability testing belong here, and nothing in any "
        "configuration says which addresses those are - so confirm each exempted source is a "
        "testing host you own",
        "the count is of ADDRESSES and not of list entries, which matters because the vendor's own "
        "help describes ONE address field and the configuration holds TWO separate leaves - a "
        "count that reads one of them sees half the list, and half a list on an exemption surface "
        "reports a blind spot as clean",
        "how BROAD each exemption is, is not asserted: a very wide netmask is visible in the "
        "stored list and no column carries it, so a breadth test is not part of this finding",
    ]


def _spoof_drop_off(obj) -> list[str]:
    """PAN-ZON-005's only half: is the spoofed-address drop on."""
    if obj.discard_ip_spoof:
        return []
    return [
        "THE SPOOFED IP ADDRESS DROP IS OFF on this profile, so a packet arriving on a zone this "
        "profile protects is forwarded even where this firewall's own routing table says its "
        "source address belongs somewhere else",
        "THE POPULATION FOR THIS CONTROL WAS NOT ESTABLISHED AND THIS FINDING DOES NOT IMPLY THAT "
        "IT WAS. The vendor asks for this drop on INTERNAL zones only, in two documents that "
        "agree, and the profile holds NO RECORD of which zone type it is attached to - one "
        "profile may be in force on an internal zone and an internet-facing one at once. So this "
        "reports every profile in force, and which of those sit on internal zones is yours to "
        "confirm",
        "AND THERE IS A REASON A CUSTOMER MAY HAVE TURNED IT OFF DELIBERATELY, which belongs with "
        "the remediation rather than with the assertion: the check consults the ROUTING TABLE "
        "ONLY and ignores policy-based forwarding, so on a zone whose return path is chosen by "
        "policy rather than by route this setting discards legitimate traffic",
        "the absence of the key reads as off as a vendor fact rather than an assumption: stage 4 "
        "measured it as `no` on two independent oracles, one of them operational",
    ]


def _non_syn_reject(obj) -> list[str]:
    """PAN-ZON-006's first half: may a TCP session begin in the middle."""
    if obj.non_syn_reject_effective == "yes":
        return []
    configured = obj.non_syn_reject_configured
    parts = []
    if configured == "global":
        parts.append(
            "THIS PROFILE DEFERS THE NON-SYN TCP REFUSAL TO THE DEVICE-WIDE SETTING and that "
            "setting does NOT reject non-SYN TCP, so the deferral resolves to permitted. The "
            "profile's own leaf reads `global`, which is neither the asserted state nor a "
            "readable refusal - it is a POINTER, and it is the schema default, so an untouched "
            "profile reads here")
        parts.append(
            "THE REMEDY IS A SECOND READING BEFORE IT IS A CHANGE: the device-wide session "
            "setting is where this resolves, it holds only two values with no deferral of its "
            "own, and changing it moves every profile pointing at it rather than this zone alone")
    elif configured == "no":
        parts.append(
            "NON-SYN TCP IS EXPLICITLY ACCEPTED on this profile, so the firewall will build a "
            "session from a packet whose connection opening it never saw - which the catalog "
            "row's own notes call a material degradation of TCP state security requiring a formal "
            "exception")
    else:
        resolved = obj.non_syn_reject_effective or "nothing readable"
        parts.append(
            f"THE NON-SYN TCP REFUSAL RESOLVES TO `{resolved}` on this profile, so a TCP session "
            "may begin in the middle")
    parts.append(
        "THE VENDOR DOCUMENTS ONE CASE WHERE THIS SHOULD BE OFF AND THIS FINDING DOES NOT EXCLUDE "
        "IT: a zone that controls the security policy for traffic a tunnel inspection rule opens, "
        "on a firewall where session rematch is enabled. Establishing that needs three facts no "
        "column of this profile holds - whether a tunnel inspection policy exists, whether "
        "rematch is on, and WHICH zones control that policy's rules - and the third is a "
        "judgment rather than a value, so the exception is yours to apply")
    parts.append(
        "AND THE VENDOR'S OWN TEXT POINTS BOTH WAYS ON THIS FIELD, which is recorded rather than "
        "resolved: the same page that explains why permitting non-SYN TCP breaks file blocking "
        "also instructs the reader to disable the refusal on the zone class above, and no vendor "
        "line PRESCRIBES switching it on")
    return parts


def _packet_drop_gap(obj) -> list[str]:
    """PAN-ZON-006's second half: are the option and segment drops on."""
    if not obj.packet_drop_gap:
        return []
    off = [label for field, label in _PACKET_DROPS if not getattr(obj, field)]
    which = ", ".join(off) if off else (
        "a drop this row's verdict column and its four drop columns disagree about, which "
        "happens only between a migration and the pass that recomputes them")
    return [
        f"AT LEAST ONE OF THE PACKET DROPS THIS CONTROL ASSERTS IS OFF on this profile: {which}",
        "these four are the drops the catalog row's description names, and they are NOT the "
        "same list as its longer prose, which adds the Record Route and network-layer Timestamp "
        "option drops. No vendor hardening line asks for those two, so they are not asserted here "
        "and are not part of this finding either way",
        "THREE THINGS THE VENDOR ASKS FOR ON THIS SAME TAB ARE NOT ASSERTED BY ANY CONTROL AT "
        "ALL, and they are named because the vendor names them beside the four above: the unknown "
        "IP option drop, the TCP split-handshake drop, and stripping the transport-layer TCP "
        "timestamp. No path was derived for any of the three, so none of them is in this finding",
    ]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE, keyed by control id. THE DEFAULT IS `()` - see
#: the module docstring. PAN-ZON-004 is the only control here with two entries, because stage 5
#: gives it two assertion records over one model and the second group of its first record can
#: fire on the same row as the first.
PARTS_BY_CONTROL = {
    "PAN-ZON-002": (_syn_flood_off,),
    "PAN-ZON-003": (_volumetric_flood_gap,),
    "PAN-ZON-004": (_scan_detection_gap, _scan_sensitivity_unread, _scan_exemptions_present),
    "PAN-ZON-005": (_spoof_drop_off,),
    "PAN-ZON-006": (_non_syn_reject, _packet_drop_gap),
}


def _owner(obj) -> str:
    """The appliance this profile is defined on. ONE SCOPE, measured.

    `network/profiles/zone-protection-profile` has exactly one scope on a firewall, so there is no
    vsys or shared copy to name - which is why this reads the appliance directly where every
    policy-object generator reads an enforcement point.
    """
    return str(obj.appliance.hostname or obj.appliance.serial_number)


def _subject(obj, control_id: str) -> str:
    attached = obj.attached_zone_count
    in_force = (f"in force on {attached} zone{'s' if attached != 1 else ''}" if obj.is_in_force
                else "attached to no zone, so it enforces nothing as it stands")
    parts = [f"zone protection profile {obj.profile_name} on {_owner(obj)}, {in_force}"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_zone_protection_profile_finding_summary(obj, matched_queries) -> str:
    # The control id comes off the first matched query, which is safe for the reason
    # `object_findings.generate_object_findings` makes it safe: it iterates `for control in
    # controls` and creates the finding with that same control, so `matched_queries` can only
    # ever hold one control's queries. The loop is a spelling of `control.control_id`.
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="zone protection profile",
    control_type=Control.ControlType.ZONE_PROTECTION_PROFILE,
    finding_model=ZoneProtectionProfileFinding,
    link_model=ZoneProtectionProfileFindingControlQuery,
    subject_fk="zone_protection_profile",
    link_fk="zone_protection_profile_finding",
    queryset=lambda: ZoneProtectionProfile.objects.select_related("appliance"),
    evaluate=evaluate_zone_protection_profile_control_queries,
    summary=build_zone_protection_profile_finding_summary,
    # The profile's own entry name. NOT `obj.name`, which this model does not have.
    subject_name=lambda obj: obj.profile_name,
    # The appliance, and nothing finer. A profile name is unique per appliance - the shipped
    # constraint is `(appliance, profile_name)` - and this collection has one scope, so the
    # appliance is the whole of what a reader needs to find the row.
    subject_scope=lambda obj: _owner(obj)[:128],
)


def generate_zone_protection_profile_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_zone_protection_profile_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
