"""`print_unknown_breadth` - which member made a rule side unmeasurable.

PAN-POL-002 reports an indeterminate side at medium and the surfaces print `(Unknown addresses)`
under the member names, which says nothing about WHICH member stopped the count. Jason, on a
production estate 2026-11-12: *"in sources I see address objects followed by '(Unknown
addresses)'. Three of the objects are ip_netmask kind, one object is an ip_range kind. Their
values look normal."* This command answers that, and the cases below are the shapes it has to
tell apart - because each one is a different repair, and one of them is not a configuration
fault at all.

The sides here are built with their counts set directly, the way `test_address_breadth_control`
builds them: the arithmetic that writes those columns is tested in OptivEdgeIntegrations, and
what is under test here is the attribution of a null to the member behind it.
"""

from __future__ import annotations

from django.core.management import call_command
from django.test import TestCase
from django.utils import timezone
from io import StringIO

from assessments.management.commands import print_unknown_breadth as command
from assessments.models import AssessmentRun, Control, ControlQuery, RuleFinding
from assessments.tests._seed import seed_controls
from assessments.findings import generate_rule_findings
from optivedge_integrations.integrations.models import (
    AddressObject,
    ApplianceGroup,
    Appliance,
    EnforcementPoint,
    ManagementStation,
    PolicyObjectNamespace,
    Region,
    SecurityRule,
    SecurityRuleAddressRef,
    SecurityRuleSourceAddressRef,
    Snapshot,
)


class _Estate(TestCase):
    """One firewall, one vsys, and whatever address objects a test needs."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.breadth")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-breadth",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            hostname="fw-breadth", serial_number="0001")
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance=self.appliance,
            appliance_group=self.group, vsys_name="vsys1", vsys_display_name="vsys1")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_type="test", collected_at=timezone.now())
        self.order = 0

    def object_of(self, name, *, address_type=AddressObject.TYPE_IP_NETMASK, value="10.0.0.0/24",
                  start=167772160, end=167772415, num_hosts=256, **fields):
        return AddressObject.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            name=name, namespace_type=PolicyObjectNamespace.LOCAL_VSYS,
            namespace_value="vsys1", precedence_rank=10, address_type=address_type,
            value=value, normalized_value=value, ipv4_start_int=start, ipv4_end_int=end,
            num_hosts=num_hosts, last_synced_at=self.snapshot.collected_at, **fields)

    def rule_with(self, name, members, *, source_num_hosts=None, negate_source=False):
        """One allow rule whose source names `members` - each (raw_value, ref kwargs)."""
        self.order += 1
        rule = SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=SecurityRule.SOURCE_LOCAL,
            effective_order=self.order, rule_position=self.order, name=name,
            action="allow", disabled=False, rule_type="universal",
            negate_source=negate_source,
            source_num_hosts=source_num_hosts, destination_num_hosts=1)
        for position, (raw_value, fields) in enumerate(members):
            SecurityRuleSourceAddressRef.objects.create(
                security_rule=rule, raw_value=raw_value, position=position, **fields)
        return rule

    def run_command(self, **options) -> str:
        out = StringIO()
        call_command("print_unknown_breadth", stdout=out, **options)
        return out.getvalue()


class CauseTests(_Estate):
    """One test per shape, because each shape is a different repair."""

    def test_an_unfetched_external_list_is_named_as_the_cause(self):
        """The commonest real one. An EDL the firewall has never fetched has no addresses to
        count, so the side it is on cannot be sized - and the repair is a cache refresh on the
        device, not a change to the rule."""
        edl = self.object_of("prod-edl", address_type=AddressObject.TYPE_EDL,
                             value="https://edl.invalid/list.txt", start=None, end=None,
                             num_hosts=None, is_edl=True)
        self.rule_with("edl-rule", [
            ("10.0.0.0/24", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                             "address_object": self.object_of("net-a")}),
            ("prod-edl", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                          "address_object": edl})])

        output = self.run_command()

        self.assertIn("whose content this firewall has never fetched", output)
        self.assertIn("unsized  'prod-edl'", output)
        self.assertIn("  sized  '10.0.0.0/24'", output)

    def test_a_region_is_named_as_the_cause(self):
        """A region's addresses are not in the configuration at all, so no collection can size
        it. The rule is doing what it says; the control's medium is the honest answer."""
        region = Region.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, name="US",
            namespace_type=PolicyObjectNamespace.LOCAL_VSYS, namespace_value="vsys1",
            precedence_rank=10, last_synced_at=self.snapshot.collected_at)
        self.rule_with("region-rule", [
            ("US", {"ref_type": SecurityRuleAddressRef.RefType.REGION, "region": region})])

        self.assertIn("a region", self.run_command())

    def test_an_object_with_no_ipv4_extent_is_named_with_its_value(self):
        """An `ip-wildcard` object is the lab's one example: a real, committed object this
        normalizer stores and does not size. The value is printed because the whole question
        Jason asked was about members whose values look normal."""
        self.rule_with("wildcard-rule", [
            ("wild", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                      "address_object": self.object_of(
                          "wild", address_type=AddressObject.TYPE_IP_WILDCARD,
                          value="10.0.0.0/0.0.0.255", start=None, end=None, num_hosts=None)})])

        output = self.run_command()

        self.assertIn("with no IPv4 extent", output)
        self.assertIn("'10.0.0.0/0.0.0.255'", output)

    def test_truncated_content_is_told_apart_from_content_nobody_fetched(self):
        """A truncated set is a KNOWN under-count, which is a different fact and a different
        repair - the collection ceiling, not the device's cache."""
        self.rule_with("truncated-rule", [
            ("big-edl", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                         "address_object": self.object_of(
                             "big-edl", address_type=AddressObject.TYPE_EDL, value="http://x",
                             start=None, end=None, num_hosts=None, is_edl=True,
                             resolved_content_truncated=True,
                             resolved_content_source_total=900_000)})])

        self.assertIn("truncated at the collection ceiling", self.run_command())

    def test_a_negated_side_that_permits_nothing_is_not_a_member_fault(self):
        """THE ONE THAT IS NOT A CONFIGURATION FAULT. A negated side covering the whole address
        space has an EMPTY complement, so `_materialize_negated_complement_ref` makes no
        complement and the count is left null - and PAN-POL-002 then reports at medium that the
        breadth could not be established. It was established: the rule permits 0 addresses,
        which is the narrowest rule there is. Every member of the side sizes, which is how this
        command tells it apart from the four shapes above."""
        self.rule_with("negated-any", [
            ("any", {"ref_type": SecurityRuleAddressRef.RefType.ANY,
                     "address_object": self.object_of(
                         "any", value="any", start=0, end=4294967295,
                         num_hosts=4294967296, is_any=True, is_builtin=True)})],
            negate_source=True)

        output = self.run_command()

        self.assertIn(command.NEGATED_EMPTY, output)
        self.assertIn("NEGATED", output)
        self.assertNotIn(command.UNEXPLAINED, output)
        # The recompute agrees, in the normalizer's own arithmetic: the complement of the whole
        # space is empty, which is zero addresses rather than an unknown number.
        self.assertIn("recomputed from these members now: 0 addresses", output)

    def test_a_null_side_whose_members_add_up_is_called_stale(self):
        """THE SHAPE PRODUCTION HAD. Jason ran this against his estate 2026-11-12 and both
        sides of one rule came back here: four members, every one sized, no negation, and both
        counts null. `source_num_hosts` is a stored column written once when the rule was
        normalized, so a side whose own members come to a number today is a column left behind
        by its data - nothing in the configuration needs changing and re-normalizing the
        enforcement point writes the count. It is reported in those words rather than left in a
        bucket with the regions, because the two send a reader to opposite places."""
        self.rule_with("mystery", [
            ("net-a", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                       "address_object": self.object_of("net-a")})])

        output = self.run_command()

        self.assertIn("so the stored count is STALE", output)
        self.assertIn("they come to 256 addresses", output)
        self.assertIn("recomputed from these members now: 256 addresses", output)
        self.assertNotIn(command.UNEXPLAINED, output)


class ReportTests(_Estate):
    def test_a_sized_side_is_not_reported_at_all(self):
        """A rule whose sides both have counts is not this command's subject, however broad."""
        self.rule_with("sized", [
            ("net-a", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                       "address_object": self.object_of("net-a")})],
            source_num_hosts=256)

        output = self.run_command()

        self.assertIn("Every side of every rule was sized", output)
        self.assertNotIn("sized  'net-a'", output)

    def test_the_name_filter_finds_a_member_by_name(self):
        """How Jason reaches his own case: the member he suspects is named `Range
        _172.16.205.63-64`, space and all, and the filter matches a member name as well as a
        rule name."""
        self.rule_with("wanted", [
            ("Range _172.16.205.63-64", {
                "ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                "address_object": self.object_of(
                    "Range _172.16.205.63-64", address_type=AddressObject.TYPE_IP_RANGE,
                    value="172.16.205.63-172.16.205.64", start=2886766399, end=2886766400,
                    num_hosts=2)})])
        self.rule_with("unwanted", [
            ("other", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                       "address_object": self.object_of("other")})])

        output = self.run_command(name="Range _172")

        self.assertIn("'wanted'", output)
        self.assertNotIn("'unwanted'", output)
        self.assertEqual(output.splitlines()[0],
                         "rule sides with no host count: 1 over 1 rules")

    def test_a_space_in_a_members_name_is_not_what_makes_a_side_unsized(self):
        """Jason's own observation, settled rather than carried: *"The only oddity is that the
        object's name is 'Range _172.16.205.63-64'. Notice the space in the name."* Nothing in
        the sizing reads a name - `_member_intervals_or_none` reads the object's intervals -
        and the resolver's lookups are exact dict hits, so a name with a space resolves or
        raises. This asserts the sized half of that: the object is found and counted."""
        rule = self.rule_with("spaced", [
            ("Range _172.16.205.63-64", {
                "ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                "address_object": self.object_of(
                    "Range _172.16.205.63-64", address_type=AddressObject.TYPE_IP_RANGE,
                    value="172.16.205.63-172.16.205.64", start=2886766399, end=2886766400,
                    num_hosts=2)})])

        output = self.run_command()

        self.assertIn("  sized  'Range _172.16.205.63-64'", output)
        self.assertIn("recomputed from these members now: 2 addresses", output)
        self.assertEqual(rule.source_address_refs.count(), 1)

    def test_it_says_which_of_the_rules_carry_a_finding(self):
        """The tie back to the report Jason is reading. A null side with no PAN-POL-002 finding
        behind it is not what he spot-checked, and the line says so per side."""
        seed_controls(["PAN-POL-002"], control_type=Control.ControlType.SECURITY_RULE)
        self.rule_with("graded", [
            ("wild", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                      "address_object": self.object_of(
                          "wild", address_type=AddressObject.TYPE_IP_WILDCARD, value="w",
                          start=None, end=None, num_hosts=None)})])
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_rule_findings(run)

        output = self.run_command()

        self.assertTrue(RuleFinding.objects.filter(
            control__control_id="PAN-POL-002").exists(), "the fixture raised no finding")
        self.assertIn("1 carry a PAN-POL-002 finding", output)
        self.assertNotIn("(no PAN-POL-002 finding)", output)

    def test_the_query_is_the_controls_own(self):
        """`BREADTH_UNKNOWN` is the breadth half of PAN-POL-002's own canonical query, and this
        is what stops the two drifting apart. A command that found a different set of rules
        from the control it explains would be answering a question nobody asked - and the
        drift would be silent, because both halves would still run."""
        seed_controls(["PAN-POL-002"], control_type=Control.ControlType.SECURITY_RULE)
        query = ControlQuery.objects.get(control__control_id="PAN-POL-002",
                                         name="A side's breadth could not be established")

        breadth = [clause for clause in query.canonical_query["clauses"]
                   if clause.get("operator") == "or"]

        def tested(clauses):
            # The stored query is the VALIDATED node, which carries `negated` and
            # `case_sensitive` defaults the catalogue's JSON does not write. What has to match
            # is what is asked of which field.
            return [(c["field"], c["op"], c["value"], c.get("negated", False))
                    for c in clauses]

        self.assertEqual(len(breadth), 1, "the control's query has changed shape")
        self.assertEqual(tested(breadth[0]["clauses"]),
                         tested(command.BREADTH_UNKNOWN["clauses"]))
        self.assertEqual(breadth[0]["operator"], command.BREADTH_UNKNOWN["operator"])
        self.assertEqual(command.BREADTH_UNKNOWN["model"], query.canonical_query["model"])

    def test_it_writes_nothing(self):
        """It is run against a production estate to explain a report, so it has to be safe to
        run there - the same contract `print_unattributed_findings` carries."""
        self.rule_with("mystery", [
            ("net-a", {"ref_type": SecurityRuleAddressRef.RefType.ADDRESS_OBJECT,
                       "address_object": self.object_of("net-a")})])
        before = (SecurityRule.objects.count(), AddressObject.objects.count(),
                  SecurityRuleSourceAddressRef.objects.count(),
                  list(SecurityRule.objects.values_list("id", "source_num_hosts",
                                                        "destination_num_hosts")))

        self.run_command()

        self.assertEqual(
            (SecurityRule.objects.count(), AddressObject.objects.count(),
             SecurityRuleSourceAddressRef.objects.count(),
             list(SecurityRule.objects.values_list("id", "source_num_hosts",
                                                   "destination_num_hosts"))),
            before)
