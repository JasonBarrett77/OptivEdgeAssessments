"""What the engagement assessed: the one definition every artifact lists devices from.

Jason, 2026-11-07, on the deliverables: *"In at least two of the artifacts ... the
firewalls/enforcement points being listed are outside of the list of in-scope enforcement
points"*, and then *"an out-of-scope firewall should vanish from Reviewed Devices"*.

WHERE AN OUT-OF-SCOPE FIREWALL COMES FROM. Not from collection: a device is only collected
through an in-scope enforcement point (`flows.collect_in_scope_configuration_snapshots` walks
`get_in_scope_appliances`), so one that never had an in-scope point has no snapshot of any
kind and no finding. It comes from the INVENTORY. Normalizing `show managed devices` does
`Appliance.objects.get_or_create` for every device Panorama manages, in scope or not, so the
row exists - and every artifact read `Appliance.objects` with no filter, so the row printed.
Jason, 2026-11-07: *"We shouldn't be collecting a device if the device never had an in-scope
enforcement point."* Nothing does. The lists were the defect, not the counts.

SCOPE IS RESOLVED BY COLLECTION'S OWN RULE, not by a second one written here.
`flows.get_in_scope_appliances` walks the in-scope points of one station and takes the point's
own appliance, else the appliances its nodes reach, else its group's - in that order, which is
not the same set as the three joined with OR: a point that has nodes does not also pull in
group members those nodes miss. That order is what decides which devices were collected, so it
is what decides which devices this engagement assessed, and `test_scope` holds the two
together on a seeded estate rather than trusting that a copy stayed honest.

RETIRED POINTS FALL OUT FOR FREE. An HA pair still negotiating reports no peer, so the first
sync builds standalone groups and the next builds the pair;
`normalization.panorama.retire_superseded_enforcement_points` carries scope to the new points
and clears `in_scope` on the ones left behind. Measured on the lab 2026-11-07: nine such
points, all `is_missing` since one retirement event, and nine enforcement nodes still joining
them to `fw-core-tpa-a` - which is why the Enforcement Points tab printed 29 rows for 20
enforcement points and showed `fw-core-tpa-a / vsys1 / edge` twice, once Yes and once No.
Filtering on `in_scope` drops them without this module having to know they are retired.
"""

from __future__ import annotations

from django.db.models import Q

from optivedge_integrations.integrations.models import (
    Appliance, EnforcementNode, EnforcementPoint, ManagementStation, Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.flows import get_in_scope_appliances

from assessments import finding_registry

from .errors import ArtifactBuildError


def scope_is_declared() -> bool:
    """Whether this estate models assessment scope at all.

    THREE STATES, NOT TWO. An estate with enforcement points and some of them ticked is the
    normal one and everything below filters on it. An estate with points and NONE ticked is an
    operator who has not chosen scope yet - `integrations.views` calls that
    `scope_needs_attention` - and a build there is refused rather than filtered down to an
    empty deliverable, which would read as "we found nothing".

    And an estate with NO enforcement points at all does not model scope, so there is nothing
    to filter by and everything it holds is in scope. That is not a hypothetical: nothing in
    this suite's fixtures creates an `EnforcementPoint`, because a control test seeds the
    configuration a control reads and an enforcement point is not part of it. Treating those
    appliances as out of scope would have made every artifact test build an empty workbook.

    The distinction matters because an out-of-scope firewall in production is NOT a firewall
    with no enforcement points - normalizing the inventory gives it one per vsys it observes,
    and `in_scope` defaults to False - so the fallback here cannot hide the case it was all
    written for.
    """
    return EnforcementPoint.objects.exists()


def check_scope_is_declared() -> None:
    """Refuse a build on an estate that models enforcement points and puts none in scope."""
    if EnforcementPoint.objects.exists() and not EnforcementPoint.objects.filter(
            in_scope=True).exists():
        raise ArtifactBuildError(
            f"none of the {EnforcementPoint.objects.count()} enforcement points on this estate "
            f"is in scope, so there is nothing for this artifact to report on. Choose the "
            f"virtual systems this engagement covers, then collect and re-run the findings.")


def appliances_in_scope():
    """The firewalls this engagement assessed, as a queryset so a sheet can still join.

    Resolved through `get_in_scope_appliances` for the reason the module docstring gives, then
    handed back as a queryset by primary key: the sheets need `select_related` and `count()`,
    and the resolution needs the precedence.
    """
    if not scope_is_declared():
        return Appliance.objects.all()
    pks = set()
    for station in ManagementStation.objects.all():
        pks.update(appliance.pk for appliance in get_in_scope_appliances(station))
    return Appliance.objects.filter(pk__in=pks)


def management_stations_in_scope():
    """The management stations that have something in scope on them.

    A station with no in-scope enforcement point collects nothing - the same filter
    `get_in_scope_appliances` opens with - so it has nothing to report and does not appear.
    """
    if not scope_is_declared():
        return ManagementStation.objects.all()
    return ManagementStation.objects.filter(enforcement_points__in_scope=True).distinct()


def enforcement_points_in_scope():
    return EnforcementPoint.objects.filter(in_scope=True)   # empty estate: nothing to list


def enforcement_nodes_in_scope():
    """The appliance-and-vsys pairs in scope: one row per appliance per in-scope point."""
    return EnforcementNode.objects.filter(enforcement_point__in_scope=True)


def snapshots_out_of_scope():
    """Snapshots whose enforcement point, or whose appliance, is no longer in scope."""
    return Snapshot.objects.filter(
        Q(enforcement_point__isnull=False, enforcement_point__in_scope=False)
        | (Q(appliance__isnull=False) & ~Q(appliance__in=appliances_in_scope())))


def check_findings_are_in_scope() -> None:
    """Refuse a build whose findings reach outside the engagement's scope.

    A GUARD AND NOT A FILTER, Jason 2026-11-07: there should never be a finding outside scope,
    because a device is only collected through an in-scope enforcement point. So one that
    exists is a question about the estate - a point unticked after it was collected, a sync
    that moved an appliance between groups without retiring the point it left - and quietly
    dropping it from the deliverable would answer that question by hiding it.

    IT IS THE FINDINGS THAT ARE CHECKED, NOT EVERY SNAPSHOT EVER COLLECTED. Snapshots
    accumulate: nothing in production deletes one, and the lab holds 47, 47, 72 and 1
    `show_merged_config` snapshots for its four appliances while its findings reference 10
    snapshots of the 1,062 there are. A first version of this guard asked whether any snapshot
    was out of scope, which would have refused a build over a collection from before scope last
    changed - a deliverable blocked by history rather than by anything in it. So the snapshots
    are narrowed first, which is one query and almost always empty, and only then is each
    finding model asked whether it points at one.
    """
    check_scope_is_declared()
    if not scope_is_declared():
        return
    stale = set(snapshots_out_of_scope().values_list("pk", flat=True))
    if not stale:
        return
    named = []
    for kind in finding_registry.FINDING_KINDS:
        snapshot = (Snapshot.objects
                    .filter(pk__in=kind.model.objects.filter(snapshot_id__in=stale)
                            .values_list("snapshot_id", flat=True))
                    .select_related("appliance", "enforcement_point")
                    .first())
        if snapshot is None:
            continue
        where = (snapshot.appliance.hostname or snapshot.appliance.serial_number
                 if snapshot.appliance else "no appliance")
        if snapshot.enforcement_point:
            where += f" / {snapshot.enforcement_point.vsys_name}"
        named.append(f"{kind.label} on {where}")
        if len(named) == 6:
            break
    if named:
        raise ArtifactBuildError(
            "findings reach outside the engagement's scope, so this build would report on "
            "something nobody asked for: " + "; ".join(named) + ". An enforcement point "
            "unticked after it was collected keeps the configuration read through it, and "
            "nothing re-checks scope when findings are generated - so re-running the findings "
            "on its own will not clear this. Put the point back in scope if it belongs there, "
            "or collect and renormalize so the configuration behind these findings is retired.")
