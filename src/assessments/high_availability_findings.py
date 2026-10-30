"""Finding generation for the high-availability controls. PAN-HAP-001 to 004.

THE SENTENCE HAS TO SURVIVE THE DEVICE'S OWN DEFAULTS, and on this subject they read the
reassuring way round. Three measurements from stage 4 of the `ha-panorama` domain govern every
sentence below:

* AN ABSENT MONITORING KEY ASSERTS THAT MONITORING IS ON. `show high-availability all` answers
  `link-monitoring: {enabled: yes, failure-condition: any, groups: null}` on an appliance holding
  no `group/monitoring` node at all. So the ordinary state of an estate is MONITORING ENABLED AND
  MONITORING NOTHING, a sentence saying "link monitoring is disabled" would report a gap the
  device denies, and the finding has to name the GROUPS rather than the switch.
* `enabled: yes` IS NOT A FORMED RELATIONSHIP. This lab's pair answers `state-sync: User-disabled`
  and `conn-ha2: down` while both members hold `configuration-synchronization/enabled: yes`, so a
  sentence reading the switch would call that pair redundant.
* THE ENCRYPTION SWITCH CANNOT TAKE EFFECT WITHOUT AN IMPORTED HA KEY. `validate full` refuses
  the commit without one, in the device's own words, so the remediation is two steps and the
  finding says which one is missing.

FOUR THINGS THE SENTENCE IS NOT ALLOWED TO SAY, each because the reading behind it was never
taken:

* THAT THE PEER RELATIONSHIP IS BROKEN WHEN NOBODY READ THE RUNTIME. `ha_runtime_state_collected`
  is false until a collector issues `show high-availability all`, and no collector issues it
  today, so PAN-HAP-001 fires on every HA-enabled appliance in every estate. The sentence says
  the relationship was NOT ESTABLISHED rather than that it failed, and names the read that
  would settle it.
* THAT THE CONTROL LINK IS UNENCRYPTED when the runtime half is missing: the configuration switch
  can read `yes` on a link that is not encrypted, and the absence of the confirming read is a
  different statement from a confirmed `no`.
* THAT A PORT IS ANYTHING when `interface/ha1/port` is absent and no runtime reply names one.
  The exposure band is then `unencrypted-port-unknown`, which is the baseline severity, and the
  sentence says the port was not established instead of naming a default.
* THAT ANY OF THIS IS THE PAIR'S STATE. Every column here is one appliance's, and encryption and
  keepalive independence are properties of the PAIR. A pair with the key imported on one member
  only produces two findings, and the sentence says it is reporting one member.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_high_availability_config_control_queries
from assessments.models import (
    Control, HighAvailabilityFinding, HighAvailabilityFindingControlQuery)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import HighAvailabilityConfig

#: The read that would settle PAN-HAP-001 and the runtime half of PAN-HAP-002, named every time
#: it is missing. No collector issues it today, which is why this is a standing sentence and not
#: an exceptional one.
RUNTIME_READ = "`show high-availability all`"

#: What each exposure band says about where the peer conversation travels. The band is a
#: classification this layer computes, not a value the device offers, so the prose carries the
#: reasoning the band name compresses.
EXPOSURE_PROSE = {
    HighAvailabilityConfig.EXPOSURE_MANAGEMENT_PORT: (
        "the control link is assigned to the appliance's management port, so the peer "
        "conversation shares the out-of-band management network and every host that can route "
        "to management can reach it"),
    HighAvailabilityConfig.EXPOSURE_IN_BAND: (
        "the control link is assigned to an in-band data interface, so it travels wherever that "
        "interface's segment travels - which on a virtual firewall is the ordinary case, "
        "because the platform takes a free interface name here rather than a dedicated port"),
    HighAvailabilityConfig.EXPOSURE_DEDICATED_HA_PORT: (
        "the control link is on a dedicated high-availability or auxiliary port, which is where "
        "the vendor says to cable it - but the port value does not say the cable is direct, and "
        "the vendor's cross-site case runs over these ports too"),
    HighAvailabilityConfig.EXPOSURE_PORT_UNKNOWN: (
        "which port carries the control link was not established: the configuration holds no "
        f"`interface/ha1/port` key and {RUNTIME_READ}, which would answer it, was not collected "
        "- so this reports at the control's own severity rather than at a graded one"),
}

#: What each keepalive band says. `backup-link-without-peer-address` is the state of both
#: PA-5220s in the lab this was built against, and the one an existence test at the container's
#: own path would have passed.
KEEPALIVE_PROSE = {
    HighAvailabilityConfig.KEEPALIVE_NEITHER: (
        "neither a backup control link nor management-path heartbeat backup is configured, so "
        "the peers have exactly one way of telling each other they are alive"),
    HighAvailabilityConfig.KEEPALIVE_BACKUP_WITHOUT_PEER: (
        "a backup control link is begun and not finished - the `interface/ha1-backup` container "
        "exists with no backup address for the peer, so configuration that reads as a second "
        "path has no far end. A check for the container alone passes this appliance"),
    HighAvailabilityConfig.KEEPALIVE_ONE_COMPLETE: (
        "one of the two keepalive mechanisms is complete and the other is not"),
    HighAvailabilityConfig.KEEPALIVE_UNKNOWN: (
        "the high-availability configuration was not collected for this appliance, so how many "
        "keepalive paths the peers have was not established"),
}

#: What each monitoring band says. `enabled-with-no-group` is both the device's default reading
#: and the state that passes a configuration review while monitoring nothing.
MONITORING_PROSE = {
    HighAvailabilityConfig.MONITORING_NEITHER_ENABLED: (
        "both link monitoring and path monitoring are explicitly switched off, so only the "
        "peer's death will move the active role"),
    HighAvailabilityConfig.MONITORING_ENABLED_NO_GROUP: (
        "monitoring reports itself as enabled and watches nothing: no link group and no path "
        "group holds anything. This is what the device reports when the monitoring keys are "
        "ABSENT - the switch does nothing without a group, which the vendor says twice on this "
        "screen - so it is the state an unconfigured appliance is actually in and the state a "
        "query over the two enables would have passed"),
    HighAvailabilityConfig.MONITORING_LINK_ONLY: (
        "link monitoring has a populated group and path monitoring does not, so a next hop "
        "dying behind an interface that stays up is invisible"),
    HighAvailabilityConfig.MONITORING_UNKNOWN: (
        "the high-availability configuration was not collected for this appliance, so what "
        "triggers a handover was not established"),
}


def _not_collected(obj) -> list[str]:
    """THE COVERAGE SENTENCE, and it says we could not see rather than you are wrong.

    This is what the companion query on `ha_config_collected` reports, and the distinction is
    the whole reason stage 5 asked for a separate query: the remediation for this one is ours
    and not the customer's.
    """
    return ["the `deviceconfig/high-availability` subtree was not collected for this appliance, "
            "so nothing here is a statement about its configuration - this reports that the "
            "setting was NOT ESTABLISHED, and it is cleared by collecting the appliance rather "
            "than by changing anything on it"]


def _redundant_peer(obj) -> list[str]:
    if not obj.no_live_redundant_peer:
        return []
    if not obj.ha_config_collected:
        return _not_collected(obj)
    if not obj.ha_enabled:
        return ["this appliance is configured for no high-availability relationship at all: the "
                "`deviceconfig/high-availability` node holds no `enabled` key, or holds it off, "
                "so a hardware or software fault here is an outage of everything behind it "
                "rather than a failover. WHETHER IT OUGHT TO BE IN A PAIR IS NOT READ FROM THE "
                "CONFIGURATION - nothing in a firewall's own configuration distinguishes a "
                "branch office from a data-centre perimeter - so this is reported for a person "
                "to decide rather than suppressed"]
    if not obj.ha_runtime_state_collected:
        return ["high availability is switched on and the relationship was NOT SHOWN to be "
                f"formed: {RUNTIME_READ}, which is the only read that says whether a peer is "
                "answering and state is being exchanged, was not collected for this appliance. "
                "The switch alone does not make a pair, so this reports an unestablished "
                "relationship rather than a failed one"]
    missing = []
    if obj.state_sync_enabled is False:
        missing.append("state synchronisation is switched off, so no session state is being "
                       "exchanged and a failover drops every session in flight")
    if obj.config_sync_enabled is False:
        missing.append("configuration synchronisation is switched off, so the peers do not hold "
                       "the same ruleset")
    detail = ("high availability is switched on and the relationship is not formed and "
              "exchanging state")
    if missing:
        detail += " - " + "; ".join(missing)
    detail += (". This names ONE MEMBER: the reply carries no identifier that would let the two "
               "members' rows be joined, so a pair in this state produces two findings")
    return [detail]


def _control_link(obj) -> list[str]:
    if not obj.ha1_control_link_not_encrypted:
        return []
    if not obj.ha_config_collected:
        return _not_collected(obj)
    parts = []
    if obj.ha1_encryption_enabled is not True:
        parts.append("the HA1 control link is not encrypted: "
                     "`interface/ha1/encryption/enabled` is absent or off, so the configuration "
                     "and session-ownership state the peers exchange crosses the link in clear")
    elif not obj.ha_runtime_state_collected:
        parts.append("the HA1 encryption switch is on and the link was NOT SHOWN to be "
                     f"encrypted: {RUNTIME_READ} was not collected, and the switch can read "
                     "`yes` on a link that is not encrypted")
    elif obj.ha1_encryption_key_imported is not True:
        # The switch is on AND the runtime says enabled AND no key is imported. Unreachable on a
        # real device - `validate full` refuses the commit without the key - so the sentence must
        # not attribute the verdict to the runtime read, which said the opposite.
        parts.append("the HA1 encryption switch is on and the prerequisite it cannot take effect "
                     "without is missing")
    else:
        parts.append("the HA1 encryption switch is on and the link is not encrypted in force, "
                     f"per {RUNTIME_READ}")
    if obj.ha1_encryption_key_imported is False:
        parts.append("AND THE REMEDIATION IS TWO STEPS: no high-availability key is imported on "
                     "this appliance, and without one the device refuses to commit the "
                     "encryption switch at all - `validate full` answers \"High-availability ha1 "
                     "encryption requires an import of the high-availability-key\". Export and "
                     "import the key between the peers first")
    elif obj.ha1_encryption_key_imported is None:
        parts.append("whether a high-availability key is imported was not established, and the "
                     "switch cannot take effect without one")
    band = EXPOSURE_PROSE.get(obj.ha1_control_link_exposure)
    if band:
        parts.append(band)
    return ["; ".join(parts)]


def _keepalive(obj) -> list[str]:
    if not obj.no_independent_second_keepalive_path:
        return []
    if not obj.ha_config_collected:
        return _not_collected(obj)
    detail = KEEPALIVE_PROSE.get(
        obj.second_keepalive_path_state,
        "no second, independent keepalive path to the peer was established")
    return [detail + ". Losing the single path while both peers live leaves each believing the "
                      "other is dead, and two members claiming the active role fight over the "
                      "same addresses and sessions until a person intervenes"]


def _monitoring(obj) -> list[str]:
    if not obj.ha_monitors_nothing:
        return []
    if not obj.ha_config_collected:
        return _not_collected(obj)
    detail = MONITORING_PROSE.get(
        obj.ha_monitoring_state,
        "no interface and no destination is under high-availability monitoring")
    tail = (". So a forwarding path that dies while the peer stays alive does not move the "
            "active role, and the pair sits through a blackhole with both members reporting "
            "healthy")
    # Stage 4's limit, carried onto the row rather than left to be rediscovered: a populated
    # count is not a monitored interface.
    if obj.ha_monitoring_state == HighAvailabilityConfig.MONITORING_ENABLED_NO_GROUP:
        tail += (". Note that a link group carrying NO interface is valid configuration the "
                 "device accepts, so a populated group count would not settle this either")
    return [detail + tail]


#: WHICH FACTS EACH CONTROL'S FINDING MAY STATE. A finding describes what ITS OWN control
#: asserts: a monitoring finding that also reported the control link would send a reader to the
#: wrong screen, and two controls reporting one fact is two findings for one condition.
PARTS_BY_CONTROL = {
    "PAN-HAP-001": (_redundant_peer,),
    "PAN-HAP-002": (_control_link,),
    "PAN-HAP-003": (_keepalive,),
    "PAN-HAP-004": (_monitoring,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"high availability on {obj.appliance}"]
    builders = PARTS_BY_CONTROL.get(control_id)
    if builders is None:
        # An unmapped control on this model: say everything rather than nothing, because a
        # finding with no detail is indistinguishable from a finding about a sound appliance.
        builders = (_redundant_peer, _control_link, _keepalive, _monitoring)
    for build in builders:
        parts.extend(build(obj))
    if len(parts) == 1:
        # The companion query matched and the control's own verdict did not - the row is the
        # one nobody collected. Without this the finding would carry no detail at all.
        parts.extend(_not_collected(obj))
    return "; ".join(parts)


def build_high_availability_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="high availability",
    control_type=Control.ControlType.HIGH_AVAILABILITY,
    finding_model=HighAvailabilityFinding,
    link_model=HighAvailabilityFindingControlQuery,
    subject_fk="high_availability_config",
    link_fk="high_availability_finding",
    queryset=lambda: HighAvailabilityConfig.objects.select_related("appliance"),
    evaluate=evaluate_high_availability_config_control_queries,
    summary=build_high_availability_finding_summary,
    subject_name=lambda obj: str(obj.appliance),
)


def generate_high_availability_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_high_availability_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
