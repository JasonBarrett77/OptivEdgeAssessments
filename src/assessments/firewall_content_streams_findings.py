"""Finding generation for one appliance's content streams, taken as a set. PAN-PLT-002.

THE FINDING NAMES WHICH STREAM AND WHY THE ARITHMETIC CAME OUT AS IT DID, because the verdict
column alone cannot distinguish five different remediations. "Behind its window", "never installed
at all" and "the appliance reports no publication date" are three different conversations with a
customer, and two of them are not about content at all.

IT IS THE AGE OF WHAT IS INSTALLED AND NEVER THE DISTANCE FROM THE NEWEST RELEASE. Establishing
that a version is current needs the publication date of the newest AVAILABLE release, which the
appliance does not hold and no collector fetches; stage 5 records it in `not_stored`. So every
sentence below is about the appliance's OWN reported release date against the windows stage 3
named - fourteen days minimum and seven preferred for applications and threats, seven and one for
the malware stream - and the half that needs the vendor's catalogue is absent rather than guessed.

TWO SPELLINGS OF "NEVER INSTALLED" AND BOTH ARE TRUTHY, which the sentence spells out rather than
leaving to a reader who may go on to write a clause by hand: the four content streams answer `0`
and the URL filtering stream answers `0000.00.00.000`. A truthiness test passes an uninstalled
stream and a numeric comparison ranks `0` as the lowest version rather than as no version.

THREE THINGS NO SENTENCE HERE MAY CLAIM, each a stage 3 or stage 5 limit rather than caution added
here:

* THAT A DEVIATION ALERT IS WIRED TO ANYBODY WHO WOULD ACT ON IT. Stage 3's acceptable rank
  requires one and no column of any subject can hold it, so a clean row means the DEVICE-READABLE
  half of acceptable and nothing about the alerting half.
* THAT THE ESTATE IS INTERNALLY CONSISTENT. PAN-UPD-006 owns the relative comparison - no device
  more than one release behind - and this control owns the absolute age per device. An estate
  uniformly a month stale satisfies that test and fails this one; an estate spread across two
  releases published inside a week fails that one and satisfies this.
* THAT AN UNLICENSED STREAM IS EXEMPT. Stage 3 scopes each stream to an entitlement the
  organisation has held, which is a fact on another model, so no query here carries it - and stage
  5 is explicit that a LAPSED ENTITLEMENT DOES NOT SUPPRESS THE STREAM: the vendor keeps part of it
  flowing at a slower cadence after expiry. The absence over-reports on an appliance never licensed
  for a stream and under-reports nothing.
"""

from __future__ import annotations

from assessments.control_queries import (
    evaluate_firewall_content_streams_control_queries,
)
from assessments.models import (
    Control,
    FirewallContentStreamsFinding,
    FirewallContentStreamsFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import FirewallContentStreams

#: The streams this control asserts, as (column stem, the name a reader would use). Stage 3 scopes
#: it to applications, antivirus and threats; WildFire is read for the never-installed sentinel
#: because it has no release-date key in the reply at all, so it can say "absent" and never
#: "behind". The device dictionary and URL filtering streams are stored and NOT graded.
ASSERTED = (("app", "applications"), ("av", "antivirus"), ("threat", "threats"))


def _version(obj, stem: str) -> str:
    return (getattr(obj, f"{stem}_version", "") or "").strip()


def _never_installed(version: str) -> bool:
    return version in FirewallContentStreams.NEVER_INSTALLED_VERSIONS


def _and_list(names: list[str]) -> str:
    """`a`, `a and b`, `a, b and c` - this is customer-visible prose, not a debug line."""
    if not names:
        return ""
    if len(names) == 1:
        return names[0]
    return ", ".join(names[:-1]) + " and " + names[-1]


def _currency(obj) -> list[str]:
    """PAN-PLT-002's record: is the installed content recent enough to enforce with."""
    state = obj.content_currency_state or ""
    if state == "current":
        return []
    parts = []

    if not obj.content_streams_collected:
        parts.append(
            "THIS APPLIANCE'S CONTENT STATE WAS NEVER READ, and that is reported rather than "
            "resolved. The configuration this finding was computed from exists, so the appliance "
            "was reached - but `show system info` carried nothing for it, so every stream version "
            "and every publication date below is this row's materialised default and not a "
            "measurement. An unknown fires here: a customer told their content is current on the "
            "strength of a reply nobody received has been told they are safe on the strength of "
            "nothing")
        return parts

    if state == "stream_never_installed":
        absent = [name for stem, name in (*ASSERTED, ("wildfire", "WildFire"))
                  if _never_installed(_version(obj, stem))]
        parts.append(
            f"the {_and_list(absent) if absent else 'content'} stream"
            f"{'s' if len(absent) != 1 else ''} "
            f"{'have' if len(absent) != 1 else 'has'} NEVER BEEN INSTALLED on this appliance - the "
            f"version the device reports is its own spelling of nothing (`0` for a content stream, "
            f"`0000.00.00.000` for URL filtering), not a low version number. There are no "
            f"signatures of that kind on the box at all, which is rank 1's consequence without "
            f"rank 1's qualification: nothing is merely out of date, nothing is loaded")
    elif state == "release_date_not_reported":
        undated = [name for stem, name in ASSERTED
                   if _version(obj, stem) and not (
                       getattr(obj, f"{stem}_release_date", "") or "").strip()]
        parts.append(
            f"THE STALENESS ARITHMETIC COULD NOT BE PERFORMED ON THIS APPLIANCE and that is what "
            f"is being reported, not a conclusion about its content. The "
            f"{_and_list(undated) if undated else 'asserted'} stream"
            f"{'s' if len(undated) != 1 else ''} report a version and NO PUBLICATION DATE, so there "
            f"is no date to measure an age against. This is reported at the control's own severity "
            f"rather than lower because the stream whose currency cannot be established may BE the "
            f"applications-and-threats stream, and reporting below rank 1 for a row that might be "
            f"rank 1 would under-report")
    elif state == "applications_and_threats_behind":
        parts.append(
            "the APPLICATIONS AND THREATS content on this appliance is older than the fourteen-day "
            "window stage 3 sets as its minimum. That stream carries the vulnerability and spyware "
            "signatures and the emergency releases for vulnerabilities being exploited now, so its "
            "staleness converts directly into enforcement the firewall is not performing - traffic "
            "that would have been blocked passes, and nothing in the logs says why")
    elif state == "malware_stream_behind":
        parts.append(
            "the ANTIVIRUS content on this appliance is older than the seven-day window stage 3 "
            "sets as its minimum for a malware stream. Stage 3 puts this at the same severity as a "
            "stale applications-and-threats stream and says why: a malware stream frozen for days "
            "is the same class of gap, and nothing in its evidence justifies separating them")
    elif state == "inside_minimum_outside_preferred":
        parts.append(
            "the content on this appliance is inside stage 3's MINIMUM windows and outside its "
            "PREFERRED ones - seven days for applications and threats, one for the malware stream. "
            "What is exposed is hours of newly published signatures rather than an absent stream, "
            "which is why this is graded one tier below the control's own severity")
    else:
        parts.append(
            f"this appliance's content currency reads `{state or '(empty)'}`, which this generator "
            f"has no sentence for - a token was added to the column and not to this control. Treat "
            f"the verdict as unexplained rather than as any of the states named above")

    # WHAT IS ACTUALLY ON THE BOX, printed because the verdict token does not carry it and the
    # version plus its publication date is what an engineer checks the vendor's catalogue against.
    # A stream whose date is absent is spelled out as such rather than left blank, because blank
    # and "nobody looked" are the same empty string in this column.
    installed = []
    for stem, name in ASSERTED:
        version = _version(obj, stem)
        if not version or _never_installed(version):
            continue
        published = (getattr(obj, f"{stem}_release_date", "") or "").strip()
        installed.append(f"{name} {version} published {published}" if published
                         else f"{name} {version} with NO publication date reported")
    if installed:
        parts.append("installed: " + _and_list(installed))
    if not obj.release_date_reported:
        parts.append(
            "AND NOT EVERY INSTALLED STREAM REPORTED A PUBLICATION DATE, which is a separate fact "
            "from the content being old: on this estate both PA-5220s report no date for ANY "
            "stream while one of them carries a real non-zero applications version, so a reader "
            "must not take a missing date as evidence that nothing is installed")
    parts.append(
        "WHAT A CLEAN ROW WOULD NOT HAVE MEANT, so a reader does not over-read this one. Stage 3's "
        "acceptable rank also requires a deviation alert wired to whoever would act on it, and no "
        "column anywhere holds that - so this control asserts the device-readable half only. It "
        "also says nothing about whether the rest of the estate agrees with this appliance; "
        "PAN-UPD-006 owns that comparison and fails in the opposite direction")
    parts.append(
        "AND A LAPSED SUBSCRIPTION IS NOT AN EXEMPTION FROM THIS FINDING. The vendor keeps part of "
        "a content stream flowing at a slower cadence after an entitlement expires, so a stream "
        "behind its window on an appliance whose licence ran out is still a finding here. Whether "
        "the entitlement is live is PAN-PLT-004's subject and is reported on its own row")
    return parts


#: One control, one reading. PAN-PLT-002 is the only control over this model.
PARTS_BY_CONTROL = {
    "PAN-PLT-002": (_currency,),
}


def _subject(obj, control_id: str) -> str:
    parts = [f"content streams on {obj.appliance} (serial {obj.appliance.serial_number})"]
    for build in PARTS_BY_CONTROL.get(control_id, (_currency,)):
        parts.extend(build(obj))
    return "; ".join(parts)


def build_firewall_content_streams_finding_summary(obj, matched_queries) -> str:
    control_id = ""
    for query in matched_queries:
        control_id = query.control.control_id
        break
    return matched_query_sentence(_subject(obj, control_id), matched_queries)


SPEC = ObjectFindingSpec(
    label="firewall content streams",
    control_type=Control.ControlType.FIREWALL_CONTENT_STREAMS,
    finding_model=FirewallContentStreamsFinding,
    link_model=FirewallContentStreamsFindingControlQuery,
    subject_fk="firewall_content_streams",
    link_fk="firewall_content_streams_finding",
    queryset=lambda: FirewallContentStreams.objects.select_related(
        "appliance", "appliance_group"),
    evaluate=evaluate_firewall_content_streams_control_queries,
    summary=build_firewall_content_streams_finding_summary,
    # A DEVICE-WIDE SINGLETON, so the appliance IS the subject name and this model declares no
    # `subject_scope` - the shipped precedent for the shape is `ManagementSshFinding`. On an HA
    # pair the two peers give two rows for one real configuration and the hostname tells them
    # apart; stage 5 records the duplication and nothing downstream deduplicates it.
    subject_name=lambda obj: str(obj.appliance),
)


def generate_firewall_content_streams_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_firewall_content_streams_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
