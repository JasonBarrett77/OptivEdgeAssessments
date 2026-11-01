"""Finding generation for one appliance's dynamic content update schedule.

PAN-UPD-001, -002, -004 and -005. FOUR CONTROLS OVER ONE MODEL AND ONE ROW PER APPLIANCE, so the
sentence has to say WHICH CONTENT TYPE it is about before anything else - a reader meeting
"retrieves nothing automatically" needs to know whether that is antivirus or the clientless VPN
content, because the five differ by an order of magnitude in what they cost.

`none` AND THE EMPTY STRING ARE DIFFERENT ANSWERS AND THE SENTENCE REFUSES TO MERGE THEM. `none`
is an absence that WAS read - no branch element under `recurring`, or an explicit `<none/>` - and
says this appliance retrieves nothing for this content type until a person installs by hand. `""`
is an absence NOBODY READ: the appliance's `deviceconfig/system` node came back empty, the
normaliser writes the empty string to all ten columns rather than `none`, and
`update_schedule_collected` is false. Both fire, and they carry different remediations: the first
is a schedule to create, the second is a collection to fix. A generator that printed "no
schedule" for both would tell a customer their firewall is misconfigured on the strength of a
reply nobody received.

TWO HALVES PER CONTENT TYPE WHERE STAGE 5 STATES TWO RECORDS, and either alone produces this
finding because `evaluate_queryset_control_queries` ORs every active query. The cadence half asks
how long new content can sit unretrieved; the action half asks whether the scheduled run APPLIES
what it fetches. A schedule that runs hourly and only downloads is a real failing and is reported
by the second half alone - the cadence is faultless - so the sentence names which half failed
rather than leaving a reader to infer it from a severity the two halves often share.

THE ACTION HALF'S `none` IS NOT THE CADENCE'S `none`, and this is the one place in the domain
where the same token means two things. On an action column, `none` means the in-force branch
carries no `action` key at all: measured on a committed timed branch holding `at` and nothing
else, where `show config running` showed `daily: {at: "23:50"}`, the screen rendered `(None, ...)`
and the dialog's OK button wrote nothing. What such a run DOES when it fires was never measured -
no schedule was allowed to fire in the lab - and reading it as "retrieves nothing" is the safe
direction, which the sentence states rather than implies.

WILDFIRE IS THE ONE CONTROL WHOSE SEVERITY MOVES, and the direction is worth stating because it
reads backwards at first glance. PAN-UPD-004 accepts `real-time` alone, and the graded placements
run monotonically in DELAY rather than in frequency: `every-min` is `low`, `every-15-mins` is
`medium`, and `every-30-mins`, `every-hour` and `none` are all at the control's own `high`. So a
schedule that updates more often is graded more gently, never more harshly - there is no
"too often" failing on this content type, because the exposure being graded is the time between a
cloud verdict existing and the firewall being able to enforce it.

THREE THINGS NO SENTENCE HERE MAY CLAIM, each a stage 5 limit rather than caution added here:

* THAT THE VALUE IS THE FIREWALL'S OWN TO CHANGE. The merged configuration carries a pushed
  template's value, so the column is right about what the firewall runs and silent about who owns
  it. The store holds no row for the template's copy, so a remediation may send an engineer to
  the local node when the value is owned by a template on Panorama. Stage 4 measured the sharp
  half: a value already set locally SURVIVES a push of a different value, so a template holding
  the right schedule is not evidence the firewall runs it.
* THAT THE SCHEDULE HAS EVER RUN. This is a schedule and not an outcome. PAN-PLT-002 owns the
  runtime symptom - whether installed content is actually recent - and both controls will report
  on a firewall with no schedule and stale content. Stage 3 chose that visible duplicate over a
  silent gap.
* THAT THE CONTENT IT FETCHES WAS VERIFIED. Stage 3 records a `depends_on` for PAN-MGT-009 on
  both action records - the firewall validating the update server's identity before content is
  accepted - because an unattended install is exactly the mechanism by which an unverified
  package reaches enforcement with nobody in the loop. That control is another domain's and no
  query here can carry it, so a clean row says nothing about it.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_content_update_schedule_control_queries
from assessments.models import (
    Control,
    ContentUpdateScheduleFinding,
    ContentUpdateScheduleFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import ContentUpdateSchedule

#: The cadence a reader would call acceptable, per content type, straight off stage 5's
#: `no_finding` placements. Used only to phrase the shortfall, never to decide it - the queries
#: decide, and a disagreement between this and them would be a bug in the sentence and not in the
#: finding.
ACCEPTABLE = {
    "av": "daily or hourly",
    "threats": "daily, hourly or every 30 minutes",
    "wildfire": "real-time",
    "gp_datafile": "any recurring cadence - weekly, daily or hourly",
    "gp_clientless_vpn": "any recurring cadence - weekly, daily or hourly",
}

#: How a reader names each content type. The SCREEN's words where the screen has any, because
#: that is what an engineer will go looking for - and the config node's name is what the column
#: follows. Applications and Threats is the sharp case: the screen says "Applications and
#: Threats", the config node says `threats`, and the operational command says `content`.
READABLE = {
    "av": "Antivirus",
    "threats": "Applications and Threats",
    "wildfire": "WildFire",
    "gp_datafile": "GlobalProtect data file",
    "gp_clientless_vpn": "GlobalProtect clientless VPN",
}


def _unread(obj) -> str:
    return ("this appliance's `deviceconfig/system` node came back EMPTY, so nothing below is a "
            "measurement of what it is scheduled to do - `update_schedule_collected` is false "
            "and every cadence and action column holds the empty string. The work is to make the "
            "appliance readable, not to change a schedule")


def _cadence(obj, stem: str) -> list[str]:
    """The cadence half: how long new content can sit unretrieved for one content type."""
    value = getattr(obj, f"{stem}_recurrence") or ""
    name = READABLE[stem]
    if not value:
        return [f"{name}: " + _unread(obj)]
    if value == "none":
        return [f"{name}: NO AUTOMATIC RETRIEVAL AT ALL - the `update-schedule` node carries no "
                f"recurrence branch for this content type, or carries an explicit `none`. "
                f"Nothing is checked for, nothing is downloaded and nothing is installed, so "
                f"what the appliance holds ages until somebody installs it by hand. The "
                f"acceptable posture is {ACCEPTABLE[stem]}"]
    return [f"{name}: the schedule runs `{value}`, against an acceptable posture of "
            f"{ACCEPTABLE[stem]}"]


def _action(obj, stem: str) -> list[str]:
    """The action half: whether the scheduled run APPLIES what it fetches."""
    value = getattr(obj, f"{stem}_action") or ""
    name = READABLE[stem]
    if not value:
        return [f"{name} action: " + _unread(obj)]
    if value == "download-and-install":
        return []
    if value == "download-only":
        return [f"{name} action: the scheduled run is `download-only`, so new content is "
                f"RETRIEVED AND NEVER APPLIED. The appliance goes on enforcing with the content "
                f"it already had, and the schedule's own success is not evidence of anything - "
                f"an operator reading `download-only` on the screen sees a schedule that works"]
    if value == "none":
        return [f"{name} action: the in-force branch carries NO `action` key at all, which the "
                f"screen renders as `None`. Read as taking neither action - the safe direction, "
                f"and the limit of what was measured: the configuration was read on a committed "
                f"branch holding only a time, and no schedule was allowed to fire in the lab, so "
                f"what such a run actually does is not established here"]
    return [f"{name} action: the action column reads `{value}`, which this generator has no "
            f"sentence for - a token reached the column that is not one of the two the device's "
            f"grammar was measured to offer, nor `none`, nor the unread empty string. Treat the "
            f"verdict as unexplained and re-read the appliance"]


def _av(obj) -> list[str]:
    """PAN-UPD-001: both records. Cadence, then whether the run installs what it fetches."""
    return _cadence_and_action(obj, "av")


def _threats(obj) -> list[str]:
    """PAN-UPD-002: both records, the same shape as PAN-UPD-001 over a different content type."""
    return _cadence_and_action(obj, "threats")


def _cadence_and_action(obj, stem: str) -> list[str]:
    """Two records over one content type, where the APPLICABILITY of the action half is the
    cadence not being `none`.

    Stage 5 gates the action record on `<stem>_recurrence is not none`, and that gate is in every
    query carrying it - so an appliance with no schedule at all is reported by the cadence half
    ALONE and the action half says nothing about it. That is correct and is why the sentence does
    not add "and it does not install either": there is no run to take an action.
    """
    parts = _cadence(obj, stem)
    if (getattr(obj, f"{stem}_recurrence") or "") != "none":
        parts.extend(_action(obj, stem))
    return parts


def _wildfire(obj) -> list[str]:
    """PAN-UPD-004: ONE record, the cadence alone.

    The apply half is SUBSUMED rather than claused and the reason is measured: `real-time` and
    `none` carry no `action` child, so `wildfire_action` holds `none` on the single compliant
    configuration. A conjunct over it would fire on exactly the rows this control means to pass.
    """
    value = obj.wildfire_recurrence or ""
    if value == "real-time":
        return []
    if not value:
        return ["WildFire: " + _unread(obj)]
    if value == "none":
        return ["WildFire: NO SIGNATURE RETRIEVAL AT ALL - a verdict the cloud has already "
                "reached never reaches this firewall, and this is the value the column holds for "
                "an appliance with no `update-schedule` node whatsoever. Streaming delivery "
                "(`real-time`) is what the assertion asks for"]
    delay = {
        "every-hour": "up to an HOUR between a cloud verdict existing and this firewall being "
                      "able to act on it",
        "every-30-mins": "up to HALF AN HOUR between a cloud verdict existing and this firewall "
                         "being able to act on it",
        "every-15-mins": "up to a QUARTER OF AN HOUR, which MEETS the floor the assertion names "
                         "and misses the other half of the same assertion - the fastest cadence "
                         "the deployment offers. On the public service that is `real-time`, so "
                         "this is a real shortfall and the gentlest one",
        "every-min": "up to a MINUTE, comfortably inside the floor and still short of streaming "
                     "on a public-service deployment. The residual exposure is a minute, which "
                     "is the lowest severity above informational this store can express",
    }.get(value)
    if delay is None:
        return [f"WildFire: the schedule runs `{value}`, which this generator has no sentence "
                f"for - a cadence reached the column that is not one of the six measured. Treat "
                f"the verdict as unexplained"]
    return [f"WildFire: the schedule runs `{value}` rather than streaming, so there is {delay}"]


def _gp_datafile(obj) -> list[str]:
    """PAN-UPD-005 record 0. An INVERTED sign: stage 5 states the PASSING condition, so the
    finding fires on the DISJUNCTION of a missing cadence OR a run that does not install.

    AND THIS CONTENT TYPE HAS NO CONTROL ON ANY SCREEN, which the remediation has to account for.
    Stage 4 measured Device > Dynamic Updates as carrying six groups with no GlobalProtect data
    file group at all - in the DOM over the whole document after scrolling, and confirmed in a
    screenshot - so an engineer cannot be sent to a screen for this one and the fix is the API or
    the CLI.
    """
    parts = _cadence(obj, "gp_datafile")
    parts.extend(_action(obj, "gp_datafile"))
    if parts:
        parts.append("NOTE FOR WHOEVER ACTS ON THIS: the GlobalProtect data file has NO group on "
                     "the Device > Dynamic Updates screen - measured over the whole document - "
                     "so this one is changed through the API or the CLI and not on a panel")
    return parts


def _gp_clientless_vpn(obj) -> list[str]:
    """PAN-UPD-005 record 1. The same inverted shape over the other GlobalProtect content type,
    and the screen inversion runs the OPPOSITE way from its sibling: the vendor's Help never
    names this content type on the Dynamic Updates screen while naming the data file in its
    opening sentence, and the DEVICE gives this one a group and the data file none. So a
    remediation here CAN point at a screen.
    """
    parts = _cadence(obj, "gp_clientless_vpn")
    parts.extend(_action(obj, "gp_clientless_vpn"))
    return parts


#: One reading per control, because four controls share this model and each owns one content
#: type. A control absent from this map would fall back to the antivirus reading, which would be
#: wrong rather than merely unhelpful - so the fallback is deliberately the empty tuple and the
#: subject sentence then names the appliance alone.
PARTS_BY_CONTROL = {
    "PAN-UPD-001": (_av,),
    "PAN-UPD-002": (_threats,),
    "PAN-UPD-004": (_wildfire,),
    "PAN-UPD-005": (_gp_datafile, _gp_clientless_vpn),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"content update schedule on {obj.appliance} "
             f"(serial {obj.appliance.serial_number})"]
    for build in PARTS_BY_CONTROL.get(control_id, ()):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_content_update_schedule_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="content update schedule",
    control_type=Control.ControlType.CONTENT_UPDATE_SCHEDULE,
    finding_model=ContentUpdateScheduleFinding,
    link_model=ContentUpdateScheduleFindingControlQuery,
    subject_fk="content_update_schedule",
    link_fk="content_update_schedule_finding",
    queryset=lambda: ContentUpdateSchedule.objects.select_related(
        "appliance", "appliance_group"),
    evaluate=evaluate_content_update_schedule_control_queries,
    summary=build_content_update_schedule_finding_summary,
    # A DEVICE-WIDE SINGLETON under `deviceconfig/system`, so the appliance IS the subject name
    # and this model declares no `subject_scope`. ON AN HA PAIR THIS IS TWO ROWS FOR WHAT AN
    # OPERATOR CALLS ONE SCHEDULE, and that is a fact rather than an artefact: the schedule does
    # not sync across peers, so the two rows can legitimately differ and the hostname is what
    # tells them apart.
    subject_name=lambda obj: str(obj.appliance),
)


def generate_content_update_schedule_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_content_update_schedule_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
