"""A findings tab over a subject model that tracks NO per-field provenance. P436.

THE FAILURE THIS PINS, from Jason's dev server on 2026-11-02 building run 147's stored tables:

    Could not store the security-zones table for run 147
      File ".../artifacts/sheets/findings.py", line 694, in provenance_of
        if row is None and field in _model.DERIVED_FIELDS:
    AttributeError: type object 'Zone' has no attribute 'DERIVED_FIELDS'

`DERIVED_FIELDS` is declared by `ProvenancedMixin`. `integrations.Zone` is a `SyncTrackedModel`
and not a `ProvenancedMixin`, so it declares no such attribute, and nothing writes a
`FieldProvenance` row for a zone either - so `provenance_of` found no bulk-fetched row for any
field of any zone row and read the attribute every time. The whole tab failed to store.

WHY THE TAB'S OWN TESTS DID NOT CATCH IT. `build_rows` only reaches `remediation_of` for a tested
field with NO `ValueReader` (`findings.py:719`); a field whose column declares a reader takes the
branch above it. PAN-IOT-002's three tested fields are exactly the three readers the Security
Zones sheet declares, so the one combination that raises - non-provenanced model AND a reader-less
tested field - was never built.

WHY PAN-ZON-001 IS THE CONTROL HERE. That combination is not hypothetical and needs no invented
control: two SHIPPED controls reuse the `zone` control type and so land on this same tab with
tested fields the sheet declares no reader for - PAN-UID-001 on `enable_user_identification`, and
PAN-ZON-001 on `can_receive_traffic`, `zone_protection_unresolved` and `zone_type`. PAN-ZON-001 is
driven here, over the REAL `security-zones` spec and the real catalog entry, because the zone
whose Device-ID settings the other zone controls read is the same row: one normalized zone fires
it, so nothing about the subject has to be faked to reach the branch.
"""

from __future__ import annotations

import dataclasses

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from assessments import device_id_presentation as device_id
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import ALL_TESTED_COLUMNS, build_findings_table
from assessments.artifacts.stored import stored_findings_table
from assessments.models import AssessmentRun, ZoneFinding
from assessments.tests._seed import seed_controls
from assessments.zone_findings import generate_zone_findings
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementPoint, FieldProvenance, ManagementStation, Snapshot,
    Zone)
from optivedge_integrations.integrations.platforms.pan_os.normalization.zones import (
    normalize_zones)

#: One layer 3 zone carrying one interface and NO `zone-protection-profile` - which is what
#: `zone_can_receive_traffic` and `zone_attachment_verdict` turn into PAN-ZON-001's firing state.
PAYLOAD = {"config": {"devices": {"entry": [{
    "@name": "localhost.localdomain",
    "vsys": {"entry": [{"@name": "vsys1", "zone": {"entry": [
        {"@name": "oep-zon-z1", "network": {"layer3": {"member": ["ethernet1/1"]}}},
    ]}}]}}]}}}


class UnprovenancedSubjectFindingsTests(TestCase):
    """The Security Zones tab, built over a control whose tested fields have no reader."""

    def setUp(self):
        now = timezone.now()
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.zon")
        group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-zon",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=group,
            serial_number="013201009999", hostname="fw-zon-a")
        Snapshot.objects.create(management_station=self.station, appliance=appliance,
                                source_type="show_merged_config", collected_at=now,
                                payload=PAYLOAD)
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=group, appliance=appliance,
            vsys_name="vsys1", vsys_display_name="vsys1")
        Snapshot.objects.create(management_station=self.station, enforcement_point=self.point,
                                source_type="show_merged_config", collected_at=now,
                                payload=PAYLOAD)
        normalize_zones(self.point)
        self.zone = Zone.objects.get(name="oep-zon-z1")

        self.run = AssessmentRun.objects.create(
            name="Zone defense", status=AssessmentRun.Status.RUNNING, started_at=now)
        seed_controls(["PAN-ZON-001"])
        generate_zone_findings(self.run)
        self.spec = DOMAIN_BY_SLUG["security-zones"].spec

    def test_the_fixture_fires_the_control_whose_fields_have_no_reader(self):
        """The repro is worthless if the row it needs does not exist, so it is asserted."""
        self.assertTrue(self.zone.can_receive_traffic)
        self.assertTrue(self.zone.zone_protection_unresolved)
        finding = ZoneFinding.objects.get(control__control_id="PAN-ZON-001")
        self.assertEqual(self.zone.pk, finding.zone_id)
        # The combination that raised: a non-provenanced subject model, and tested fields the
        # sheet declares no `ValueReader` for.
        self.assertFalse(hasattr(Zone, "DERIVED_FIELDS"))
        self.assertEqual([], [f for f in ("can_receive_traffic", "zone_protection_unresolved",
                                          "zone_type") if f in self.spec.value_readers])

    def test_the_security_zones_table_stores_for_a_zone_control_with_no_reader(self):
        """`store_run_tables`' own call, which is where run 147 failed."""
        table = stored_findings_table(self.spec, subjects={}, allow_running=True)
        rows = [row for row in table.rows if row[1] == "PAN-ZON-001"]
        self.assertEqual(1, len(rows))
        row = rows[0]
        self.assertEqual("oep-zon-z1", row[table.headers.index("Object")])
        # The tab says in words what this model cannot record per field - the sheet's
        # `provenance_cell` answers once for the whole row.
        self.assertEqual(device_id.ZONE_PROVENANCE, row[table.headers.index("Provenance")])
        # And the row still presents the three settings the control tests.
        #
        # THE HEADING CHANGED AND THIS LINE HAD TO FOLLOW IT - 2026-11-02, stage 9 of
        # `zone-dos-protection`. It read `headers.index("zone_protection_unresolved")`, the raw
        # Django field name, because this control's three fields had no `setting_labels` entry
        # and so headed a customer-facing tab as code. That run gave all three a proposed
        # heading, and `headers.index` takes the HEADING rather than the field, so this raised
        # `ValueError: 'zone_protection_unresolved' is not in list` - a heading rename breaking
        # a test whose subject is the STORED PATH and not the wording, with nothing to warn that
        # the two were coupled.
        #
        # What this line is here to pin is unchanged: the row still carries the tested setting's
        # value after the tab stores. The field it reads is `zone_protection_unresolved`; the
        # column it reads it from is now headed in the customer's words.
        self.assertEqual("Yes", row[table.headers.index("Zone protection unresolved")])

    def test_an_unprovenanced_field_falls_back_to_the_objects_entry_row(self):
        """What `remediation_of` answers once "no row" is reached honestly.

        The shipped sheet overrides the Provenance cell for the whole row, so the walk's answer
        is read through a spec that does not - the per-field cell is what every other tab over a
        non-provenanced model would print.
        """
        # THE NORMALIZER NOW WRITES THIS ROW, so the row is RETYPED rather than created:
        # `normalize_zones` has recorded one `__entry__` row per zone since 2026-11-04 - `local`
        # for this unmarked fixture - and a second row for the same field is refused by the
        # model's own unique constraint. What the test needs is the TEMPLATE case, which is now
        # a property of the entry rather than something a test adds beside it.
        FieldProvenance.objects.filter(
            content_type=ContentType.objects.get_for_model(Zone), object_id=self.zone.pk,
            field_name="__entry__").update(
                provenance_type=FieldProvenance.ProvenanceType.TEMPLATE, raw_value="ptpl-zon")
        per_field = dataclasses.replace(self.spec, provenance_cell=None)

        table = build_findings_table(per_field, tested=ALL_TESTED_COLUMNS)

        row = next(r for r in table.rows if r[1] == "PAN-ZON-001")
        cell = row[table.headers.index("Provenance")]
        # Three tested fields, none of them stored against a provenance row of its own, each
        # answered by the location of the OBJECT.
        self.assertEqual(["Template", "Template", "Template"], cell.split("\n"))

    def test_with_no_entry_row_the_cell_says_nothing_tracks_the_field(self):
        """No `__entry__` row either: an empty `DERIVED_FIELDS` must not synthesise one.

        THE ROW IS DELETED TO REACH THIS STATE, and no longer arrives in it: `normalize_zones`
        records an entry row for every zone since 2026-11-04, so a zone in this estate always
        has one. What this still pins is the presentation of a subject whose own normalizer
        writes none - which is most of them - and that is worth keeping: the walk must print
        "nothing tracks this" rather than inventing a location.
        """
        FieldProvenance.objects.filter(
            content_type=ContentType.objects.get_for_model(Zone), object_id=self.zone.pk,
            field_name="__entry__").delete()
        per_field = dataclasses.replace(self.spec, provenance_cell=None)

        table = build_findings_table(per_field, tested=ALL_TESTED_COLUMNS)

        row = next(r for r in table.rows if r[1] == "PAN-ZON-001")
        cell = row[table.headers.index("Provenance")]
        self.assertEqual(["Not recorded"] * 3, cell.split("\n"))
