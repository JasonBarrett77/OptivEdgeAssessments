"""The Sources and Destinations cells, where a static address group is stored one row per member.

`resolve_static_group_members` flattens group membership onto the ref rows - one row per
resolved target, each carrying the GROUP's name in `raw_value` - so that an object reached only
through a nested group can be found without walking groups. The sheet's reader joined
`raw_value` down those rows and printed a three-member group's name three times, on the findings
tab, in the workbook and on the remediation page alike. The configuration explorer never did,
because it has always read the deduping helper in Integrations' `presentation`.

Jason, 2026-11-05, on a production estate: *"application groups appear to be duplicated in the
source field"* and then *"individual address objects are not duplicated, which is interesting"* -
which is the tell. An address object is one row; a static group is one row per member.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.artifacts.sheets.security_rules import (
    DESTINATIONS_READER, SOURCES_READER)
from optivedge_integrations.integrations.models import (
    AddressGroup,
    AddressGroupMember,
    AddressObject,
    ApplianceGroup,
    EnforcementPoint,
    ManagementStation,
    SecurityRule,
    SecurityRuleDestinationAddressRef,
    SecurityRuleSourceAddressRef,
    Snapshot,
)


class AddressCellTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.cells")
        group = ApplianceGroup.objects.create(management_station=self.station, name="g-cells")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=group,
            vsys_name="vsys1", vsys_display_name="edge")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_type="test", collected_at=timezone.now())
        self.rule = SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=1, rule_position=1, name="rule-with-a-group",
            action="allow", rule_type="universal", source_num_hosts=512,
            destination_num_hosts=3)

    def address(self, name):
        return AddressObject.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            name=name, namespace_type="local_vsys", namespace_value="vsys1",
            precedence_rank=10, raw_object={})

    def group_of(self, name, members):
        group = AddressGroup.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            name=name, namespace_type="local_vsys", namespace_value="vsys1",
            precedence_rank=10, dynamic_filter="", raw_group={})
        for position, member in enumerate(members, start=1):
            AddressGroupMember.objects.create(
                address_group=group, value=member, prov="local", position=position)
        return group

    def static_group_ref(self, group, objects, *, position=1, side="source"):
        """One ref row per resolved member, which is the stored shape the check constraint
        requires: a static group ref carries BOTH an address object and the group."""
        model = (SecurityRuleSourceAddressRef if side == "source"
                 else SecurityRuleDestinationAddressRef)
        for obj in objects:
            model.objects.create(
                security_rule=self.rule, raw_value=group.name,
                ref_type=model.RefType.STATIC_ADDRESS_GROUP,
                address_object=obj, address_group=group, position=position)

    def test_a_static_group_is_named_once_and_counted(self):
        objects = [self.address(name) for name in ("host-a", "host-b", "host-c")]
        self.static_group_ref(self.group_of("corp-group", ["host-a", "host-b", "host-c"]),
                              objects)

        self.assertEqual(SOURCES_READER.read(self.rule).splitlines(),
                         ["corp-group (3 members)", "(512 addresses)"])

    def test_a_one_member_group_still_says_it_is_a_group(self):
        """The count is not an annotation for the plural case only - a reader seeing a bare name
        would take a one-member group for an address object."""
        self.static_group_ref(self.group_of("solo-group", ["host-a"]), [self.address("host-a")])

        self.assertEqual(SOURCES_READER.read(self.rule).splitlines()[0], "solo-group (1 member)")

    def test_an_address_object_carries_no_count(self):
        """It is one row and always was, which is why the duplication was visible on groups
        alone."""
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=self.rule, raw_value="host-a",
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT,
            address_object=self.address("host-a"), position=1)

        self.assertEqual(SOURCES_READER.read(self.rule).splitlines(),
                         ["host-a", "(512 addresses)"])

    def test_two_groups_on_one_side_are_two_lines(self):
        first = self.group_of("group-one", ["host-a", "host-b"])
        second = self.group_of("group-two", ["host-c"])
        self.static_group_ref(first, [self.address("host-a"), self.address("host-b")],
                              position=1)
        self.static_group_ref(second, [self.address("host-c")], position=2)

        self.assertEqual(SOURCES_READER.read(self.rule).splitlines(),
                         ["group-one (2 members)", "group-two (1 member)", "(512 addresses)"])

    def test_the_destination_side_reads_the_same_way(self):
        """Not covered by the lab, where no rule happens to name a static group as a
        destination - and the ref model's shape is identical, so the bug was there too."""
        self.static_group_ref(self.group_of("dst-group", ["host-a", "host-b"]),
                              [self.address("host-a"), self.address("host-b")], side="destination")

        self.assertEqual(DESTINATIONS_READER.read(self.rule).splitlines(),
                         ["dst-group (2 members)", "(3 addresses)"])

    def test_a_side_with_no_refs_is_empty_rather_than_blank(self):
        self.assertEqual(SOURCES_READER.read(self.rule).splitlines(),
                         ["(empty)", "(512 addresses)"])
