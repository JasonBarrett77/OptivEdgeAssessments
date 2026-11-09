"""Finding generation for one vsys's User-ID discovery include/exclude list. PAN-UID-002.

THE SUBJECT IS A VERDICT OVER THE WHOLE LIST AND THE COMMONEST FAILING STATE IS AN EMPTY ONE.
Help p.981 says a collector with no in-force entry performs discovery in ALL subnetworks, so with
nothing configured every address reachable through a monitored server is eligible to become a
named user in policy and in the log. A finding keyed on a list ENTRY would have no row to report
in exactly that case, which is why the row is per enforcement point and the conclusion is a
column.

FOUR SHAPES, AND THE SENTENCE HAS TO SAY WHICH ONE, because they are three different faults and a
reader who has seen one expects the others to look like it:

* `no_entries` - the vendor default and stage 3's baseline failure: discovery is unbounded.
* `exclude_only` - THE OPPOSITE FAULT, and the one most likely to be misread as a mild version
  of the first. Guide p.975 and help p.982 both say an exclude-only list excludes EVERY
  subnetwork and not only the ones named, so user mapping stops entirely. Identity enforcement
  then matches nobody rather than the wrong body - a functional fault rather than an exposure,
  which is why stage 3 grades it BELOW the baseline rather than above.
* `include_covers_public` - the one configuration that aims the firewall's credentialed probes at
  the Internet. Help p.981 says the collector excludes public addresses from probing and that
  naming a public subnetwork with Discovery set to Include is what re-enables WMI probing of it,
  so this is PAN-UID-003's harm triggered through this control's object. Graded ABOVE the
  baseline.
* the EMPTY STRING - nobody looked. See below.

AN UNCOLLECTED ROW FIRES HERE RATHER THAN PASSING, which is the opposite of what an unknown
normally does. Stage 5 states this control as `list_shape equals include_present` with
`sign: finding_when_clauses_fail`, so the baseline fires on the NEGATION - and the empty string
is not equal to `include_present`, so a negated equality reaches it without an `is_empty` member.
The sentence names that state explicitly instead of describing a shape, because "discovery is
unbounded" would be a claim about a configuration nobody read.

WHAT THIS CONTROL CANNOT SAY, and it is the reason the finding prints the members. Whether an
include list that EXISTS actually bounds discovery to the right subnets is site-specific: stage 3
records the ranks and the vendor's own guidance, and nothing on the firewall says which subnets
carry the organization's user population. So an in-force include list passes here and the members
are printed for a reviewer to confirm against the site's addressing.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_user_id_discovery_bound_control_queries
from assessments.models import (
    Control,
    UserIdDiscoveryBoundFinding,
    UserIdDiscoveryBoundFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import UserIdDiscoveryBound

#: How many list members a finding prints before it stops. The members are what a reviewer checks
#: the bound against, so they are the point of the sentence - but a vsys scoped to a long literal
#: list would otherwise push the summary past anything readable. Same limit and same reason as
#: `zone_findings._MEMBER_PRINT_LIMIT`.
_MEMBER_PRINT_LIMIT = 12


def _members(values) -> str:
    values = list(values or [])
    shown = ", ".join(f"`{value}`" for value in values[:_MEMBER_PRINT_LIMIT])
    if len(values) > _MEMBER_PRINT_LIMIT:
        shown += f" and {len(values) - _MEMBER_PRINT_LIMIT} more"
    return shown


def _unbounded(obj) -> list[str]:
    if obj.list_shape != "no_entries":
        return []
    return [
        "NO IN-FORCE INCLUDE OR EXCLUDE ENTRY bounds User-ID discovery on this vsys, which is "
        "the vendor's default state: the collector performs discovery in ALL subnetworks, so "
        "every address reachable through a monitored server is eligible to become a named user "
        "in policy and in the log",
        "an entry that exists but carries `disabled yes` counts as absent here, because a "
        "disabled entry bounds nothing - this vsys holds "
        f"{obj.include_entry_count} in-force include and {obj.exclude_entry_count} in-force "
        "exclude entries",
    ]


def _exclude_only(obj) -> list[str]:
    if obj.list_shape != "exclude_only":
        return []
    return [
        "THIS LIST HOLDS EXCLUDE ENTRIES AND NO INCLUDE ENTRY, WHICH STOPS USER MAPPING "
        "ENTIRELY and is not a milder form of an unbounded list. An exclude-only list excludes "
        "EVERY subnetwork rather than only the ones it names, so the collector maps nobody and "
        "identity-based policy on this vsys matches nobody",
        "it is reported as the lesser rank because it is a functional fault rather than an "
        "exposure - enforcement fails closed on identity rather than leaking it - and the "
        "remedy is an include list, not a shorter exclude list. This vsys holds "
        f"{obj.exclude_entry_count} in-force exclude entries and no include entry",
        "THE EXCLUDED RANGES THEMSELVES ARE NOT PRINTED and could not be: the model stores the "
        "include members as a list and the excludes only as a COUNT, because no clause of this "
        "domain rests on an excluded range and stage 5 marks the member list `not_searchable`. "
        "Read them at Device > User Identification > User Mapping, the Include/Exclude Networks "
        "tab on the vsys named above",
    ]


def _covers_public(obj) -> list[str]:
    if obj.list_shape != "include_covers_public":
        return []
    return [
        "AN INCLUDE ENTRY ON THIS VSYS NAMES A PUBLIC ADDRESS RANGE, which is the one "
        "configuration that aims the firewall's credentialed probes at the Internet. The "
        "collector excludes public addresses from probing by default, and naming a public "
        "subnetwork with Discovery set to Include is what re-enables probing of it",
        "so this is reported ABOVE the baseline rank: it is not merely an unbounded discovery "
        "scope, it is the WMI client-probing exposure PAN-UID-003 asserts against, reached "
        f"through this object instead. Included: {_members(obj.include_networks)}",
    ]


def _never_read(obj) -> list[str]:
    if obj.list_shape:
        return []
    return [
        "THE DISCOVERY BOUND OF THIS VSYS COULD NOT BE ESTABLISHED: no shape was computed for "
        "the include/exclude list, so whether discovery is bounded is unknown rather than "
        "answered",
        "it is reported rather than passed because this control's assertion is inverted - it "
        "fires on everything that is not an in-force include list - and an unread list is "
        "stored as no shape at all. Without this arm a vsys nobody collected would have read "
        "as having an unbounded discovery scope, which is a claim about a configuration that "
        "was never seen",
    ]


#: WHICH FACTS THIS CONTROL'S FINDING MAY STATE. One control and four arms over four mutually
#: exclusive shapes, so no row can match more than one. Keyed by control id and read with NO
#: DEFAULT, for the reason `user_id_collector_findings` gives at length: a per-control dispatch
#: that falls back to some other control's arms is a measured defect in a shipped module.
_PARTS_BY_CONTROL = {
    "PAN-UID-002": (_unbounded, _exclude_only, _covers_public, _never_read),
}


def _scope(obj) -> str:
    point = obj.enforcement_point
    appliance = point.appliance
    return str(appliance.hostname if appliance is not None else point.appliance_group)


def _subject(obj, control_id: str) -> str:
    parts = [f"the User-ID discovery bound on {_scope(obj)} {obj.enforcement_point.vsys_name}"]
    for build in _PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_user_id_discovery_bound_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="User-ID discovery bound",
    control_type=Control.ControlType.USER_ID_DISCOVERY_BOUND,
    finding_model=UserIdDiscoveryBoundFinding,
    link_model=UserIdDiscoveryBoundFindingControlQuery,
    subject_fk="user_id_discovery_bound",
    link_fk="user_id_discovery_bound_finding",
    queryset=lambda: UserIdDiscoveryBound.objects.select_related(
        "enforcement_point", "enforcement_point__appliance",
        "enforcement_point__appliance_group"),
    evaluate=evaluate_user_id_discovery_bound_control_queries,
    summary=build_user_id_discovery_bound_finding_summary,
    # The VSYS name, with the appliance as scope - the row has no entry name of its own.
    subject_name=lambda obj: obj.enforcement_point.vsys_name,
    subject_scope=_scope,
)


def generate_user_id_discovery_bound_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_user_id_discovery_bound_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
