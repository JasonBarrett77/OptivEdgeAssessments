"""Finding generation for the Session settings controls. PAN-NET-002 and PAN-NET-005.

TWO CONTROLS, ONE ROW, AND OPPOSITE EVIDENTIAL POSITIONS ON THE SAME SHAPE OF ABSENCE. Both
assert that a device-wide capability is on; for one of them an absent key is unmeasured and for
the other it is measured as ON. Getting that backwards inverts the control for every appliance
in an estate, so the sentence says which it is every time:

* `session_rematch` STORES NOTHING for an absent key. The vendor says the capability is enabled
  by default and says so twice and consistently, and no oracle on the appliance moves for it -
  `show session info` carries about sixty dataplane settings and no rematch field, `show system
  state filter *rematch*` answers NO_MATCHES on all four lab appliances, and `show session
  rematch` reports whether a rematch has EXECUTED rather than the setting. So the finding on a
  null row says the setting was never established, NOT that it is switched off.
* `ipv6_firewalling` STORES A MEASURED DEFAULT OF TRUE. The device's own dataplane was paid in
  both directions on a committed state - key absent reads on, `no` committed reads off, the leaf
  deleted and committed reads on again - and corroborated on four appliances across two
  platforms, two major versions and both vsys modes. So an absent key here is COMPLIANT, and the
  naive reading of the same absence would have raised a finding on every appliance in this
  estate. A finding on this control therefore means the key is stored as `no`.

AND THE ONE THING NEITHER SENTENCE MAY SAY: that the column is false when it is null. SQL
answers every positive comparison over a null with no match, so a clause written positively
would pass it; what reaches it here is the NEGATED clause, which inverts at the pk-set level and
so does match a row absent from the positive subquery. The sentence reads the column itself
rather than inferring the state from the fact that a query matched.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_session_settings_control_queries
from assessments.models import (
    Control, SessionSettingsFinding, SessionSettingsFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import PanOsSessionSettings


def _rematch(obj) -> list[str]:
    if obj.session_rematch is True:
        return []
    if obj.session_rematch is None:
        return ["whether the firewall re-evaluates running sessions against policy on commit was "
                "never established on this appliance - no key is stored and no oracle on the "
                "device reports the setting, so this is a reading nobody has taken rather than a "
                "capability known to be off"]
    return ["the firewall does not re-evaluate running sessions against policy when a policy "
            "change is committed, so withdrawing a rule does not withdraw the access it granted: "
            "every connection open at the time keeps it until it ends by itself"]


def _ipv6_firewalling(obj) -> list[str]:
    if obj.ipv6_firewalling:
        return []
    return ["session-level inspection of IPv6 traffic is switched off, so the firewall ignores "
            "every IPv6 rule it holds wherever it routes IPv6 - the rules are present and have "
            "no effect, which is worse than their absence because the policy reads as covering "
            "the traffic"]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. Two controls on one screen: a rematch finding
#: that also reported IPv6 firewalling would be two findings for one condition.
PARTS_BY_CONTROL = {
    "PAN-NET-002": (_rematch,),
    "PAN-NET-005": (_ipv6_firewalling,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"Session settings on {obj.appliance}"]
    builders = PARTS_BY_CONTROL.get(control_id)
    if builders is None:
        builders = (_rematch, _ipv6_firewalling)
    for build in builders:
        parts.extend(build(obj))
    return "; ".join(parts)


def build_session_settings_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="session settings",
    control_type=Control.ControlType.SESSION_SETTINGS,
    finding_model=SessionSettingsFinding,
    link_model=SessionSettingsFindingControlQuery,
    subject_fk="session_settings",
    link_fk="session_settings_finding",
    queryset=lambda: PanOsSessionSettings.objects.select_related("appliance"),
    evaluate=evaluate_session_settings_control_queries,
    summary=build_session_settings_finding_summary,
    #: The subject has no name of its own - one row per appliance - so the appliance IS the name.
    subject_name=lambda obj: obj.appliance.hostname or obj.appliance.serial_number,
)


def generate_session_settings_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_session_settings_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
