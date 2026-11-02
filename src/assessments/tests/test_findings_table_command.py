"""`print_findings_table` and the estate builder under it.

THE ARTIFACTS ARE NOT AVAILABLE HERE. The stage 6 and stage 8 files this command reads live in
OptivEdgeProbe and are gitignored, so they exist only on a machine that ran the pipeline. A test
that read them would pass on one developer's machine and error on everyone else's, and would
test the pipeline's data rather than this code. So the fixtures below are SYNTHETIC - small
artifacts in the real artifact shape, each shaped to pin one rule of the read-back grammar that
a real artifact exercises.

Every fixture key spelling here was copied from a real artifact and the comment says which, so
that a future change to the grammar fails against the shapes stage 6 actually writes rather than
against shapes invented to suit the parser.
"""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase

from assessments.tests._estate import (
    build_base_estate,
    device_name_of,
    entry_from_read_back,
    payloads_from_stage6,
    reconcile,
    run_supplemental_normalizers,
    subject_is_absent,
    vsys_names_from_stage6,
)

SERIAL = "691665AC334B458"
DEVICE = "/config/devices/entry[@name='localhost.localdomain']"


def _subject(xpath, read_back, **extra):
    subject = {
        "identity": {"device": SERIAL, "xpath": xpath},
        "verified": {"read_back": read_back},
    }
    subject["identity"].update(extra.pop("identity", {}))
    subject.update(extra)
    return subject


class ReadBackGrammarTests(SimpleTestCase):
    """The key grammar, rule by rule. Each case names the real subject it came from."""

    def test_a_plain_leaf_and_a_path_nest_as_written(self):
        # stage6-zone-dos-protection.json, oep-zdp6-p02
        entry = entry_from_read_back([
            {"key": "discard-ip-spoof", "value": "yes"},
            {"key": "flood/tcp-syn/enable", "value": "yes"},
        ])
        self.assertEqual(
            entry, {"discard-ip-spoof": "yes", "flood": {"tcp-syn": {"enable": "yes"}}})

    def test_a_null_value_is_an_empty_tag_and_not_a_null_leaf(self):
        """`<action><block/></action>`. This is the rule that makes PAN-OS choice nodes come out
        right without a schema, and getting it wrong hands the normaliser a null it reads as
        absent."""
        # stage6-zone-dos-protection.json, oep-zdp6-r01 and oep-zdp6-z01
        entry = entry_from_read_back([
            {"key": "action/protect", "value": None},
            {"key": "network/layer3", "value": None},
        ])
        self.assertEqual(entry, {"action": {"protect": {}}, "network": {"layer3": {}}})

    def test_a_list_value_is_wrapped_in_member(self):
        # stage6-url-filtering.json, oep-url-01
        entry = entry_from_read_back([{"key": "block", "value": ["malware", "phishing"]}])
        self.assertEqual(entry, {"block": {"member": ["malware", "phishing"]}})

    def test_a_list_under_an_explicit_member_key_is_not_wrapped_twice(self):
        """The two artifacts spell member lists differently and both must land identically."""
        # stage6-zone-dos-protection.json, oep-zdp6-r01
        entry = entry_from_read_back([{"key": "from/zone/member", "value": ["z01"]}])
        self.assertEqual(entry, {"from": {"zone": {"member": ["z01"]}}})

    def test_indexed_entries_become_a_list_in_index_order(self):
        # stage6-zone-dos-protection.json, oep-zdp6-p02 - its four `scan` entries
        entry = entry_from_read_back([
            {"key": "scan/entry[1]/@name", "value": "8002"},
            {"key": "scan/entry[0]/@name", "value": "8001"},
            {"key": "scan/entry[0]/action/block", "value": None},
        ])
        self.assertEqual(entry, {"scan": {"entry": [
            {"@name": "8001", "action": {"block": {}}}, {"@name": "8002"}]}})

    def test_attributes_and_text_coexist_on_one_node(self):
        """A template-pushed node carries `@ptpl`/`@src` beside its own text, and stage 6 spells
        the text `#text` for exactly that reason."""
        # stage6-zone-dos-protection.json, oep-zdp6-adopt-ztrust
        entry = entry_from_read_back([
            {"key": "network/log-setting/@src", "value": "tpl"},
            {"key": "network/log-setting/#text", "value": "default"},
        ])
        self.assertEqual(
            entry, {"network": {"log-setting": {"@src": "tpl", "#text": "default"}}})

    def test_an_indexed_member_with_attributes_keeps_its_text(self):
        # stage6-zone-dos-protection.json, oep-zdp6-adopt-ztrust
        entry = entry_from_read_back([
            {"key": "network/layer3/member[0]/@ptpl", "value": "ptpl-pan-fw-111"},
            {"key": "network/layer3/member[0]/#text", "value": "ethernet1/2"},
        ])
        self.assertEqual(entry["network"]["layer3"]["member"], [
            {"@ptpl": "ptpl-pan-fw-111", "#text": "ethernet1/2"}])

    def test_a_declared_choice_node_takes_its_value_as_a_child_tag(self):
        """The one construct the grammar cannot derive. stage6-url-filtering.json spells
        `credential-enforcement/mode` with the value `"ip-user"`, but the device holds
        `<mode><ip-user/></mode>`, so without this the normaliser reads the mode as absent."""
        entry = entry_from_read_back(
            [{"key": "credential-enforcement/mode", "value": "ip-user"},
             {"key": "credential-enforcement/log-severity", "value": "informational"}],
            choice_nodes=("credential-enforcement/mode",))
        self.assertEqual(entry["credential-enforcement"], {
            "mode": {"ip-user": {}}, "log-severity": "informational"})

    def test_without_the_declaration_the_same_key_stays_text(self):
        """The negative half: the declaration has to be what changes it, or the constant is
        decoration and a domain that needs it would pass by accident."""
        entry = entry_from_read_back(
            [{"key": "credential-enforcement/mode", "value": "ip-user"}])
        self.assertEqual(entry["credential-enforcement"], {"mode": "ip-user"})


class XpathPlacementTests(SimpleTestCase):
    def test_vsys_shared_and_predefined_route_to_their_own_reads(self):
        """Routing is on the xpath's first segment after `/config`, which is the artifact's own
        statement of where the object lives - not a per-domain table."""
        stage6 = {"domain": "d", "subjects": {
            "local": _subject(
                f"{DEVICE}/vsys/entry[@name='vsys1']/profiles/url-filtering/entry[@name='p1']",
                [{"key": "block", "value": ["malware"]}]),
            "shared": _subject(
                "/config/shared/profiles/url-filtering/entry[@name='sh1']",
                [{"key": "block", "value": ["phishing"]}]),
            "vendor": _subject(
                "/config/predefined/profiles/url-filtering/entry[@name='default']",
                [{"key": "local-inline-cat", "value": "yes"}]),
        }}
        payloads = payloads_from_stage6(stage6)
        config = payloads[SERIAL].merged["config"]
        vsys = config["devices"]["entry"][0]["vsys"]["entry"][0]
        self.assertEqual(vsys["@name"], "vsys1")
        self.assertEqual(
            vsys["profiles"]["url-filtering"]["entry"][0]["block"], {"member": ["malware"]})
        self.assertEqual(
            config["shared"]["profiles"]["url-filtering"]["entry"][0]["@name"], "sh1")
        # The predefined read is a DIFFERENT snapshot, rooted at `profiles` as
        # `security_profiles._predefined_root` accepts, and must not reach the merged config.
        self.assertEqual(
            payloads[SERIAL].predefined["profiles"]["url-filtering"]["entry"][0]["@name"],
            "default")
        self.assertNotIn("predefined", config)

    def test_two_subjects_under_one_node_land_as_two_entries(self):
        stage6 = {"domain": "d", "subjects": {
            name: _subject(
                f"{DEVICE}/network/profiles/zone-protection-profile/entry[@name='{name}']",
                [{"key": "discard-ip-spoof", "value": "yes"}])
            for name in ("p01", "p02")}}
        entries = (payloads_from_stage6(stage6)[SERIAL]
                   .merged["config"]["devices"]["entry"][0]["network"]["profiles"]
                   ["zone-protection-profile"]["entry"])
        self.assertEqual([e["@name"] for e in entries], ["p01", "p02"])

    def test_an_absence_subject_places_nothing(self):
        """Stage 6 records a subject with an empty read_back to prove nothing of that name
        exists. Building a row for it would turn its `no_finding` into a lie."""
        stage6 = {"domain": "d", "subjects": {"gone": _subject(
            f"{DEVICE}/vsys/entry[@name='vsys1']/profiles/url-filtering/entry[@name='nope']",
            [])}}
        self.assertTrue(subject_is_absent(stage6["subjects"]["gone"]))
        # The device and vsys skeleton is still built - without it the appliance pass raises for
        # every domain - but nothing of the absent subject's own name appears under it.
        vsys = (payloads_from_stage6(stage6)[SERIAL]
                .merged["config"]["devices"]["entry"][0]["vsys"]["entry"][0])
        self.assertEqual(vsys["@name"], "vsys1")
        self.assertNotIn("profiles", vsys)

    def test_a_settings_node_with_no_entry_predicate_places_at_the_node(self):
        # stage6-zone-dos-protection.json, oep-zdp6-sess
        stage6 = {"domain": "d", "subjects": {"sess": _subject(
            f"{DEVICE}/deviceconfig/setting/session",
            [{"key": "tcp-reject-non-syn", "value": "no"}])}}
        device = payloads_from_stage6(stage6)[SERIAL].merged["config"]["devices"]["entry"][0]
        self.assertEqual(
            device["deviceconfig"]["setting"]["session"], {"tcp-reject-non-syn": "no"})


class DeviceNameTests(SimpleTestCase):
    def test_the_entry_name_is_read_off_the_xpath_not_the_label(self):
        """In stage6-ipsec-crypto.json twenty-eight of thirty-one subjects are labelled
        differently from the entry they name. Each thrown-away seeder hard-coded the ones it
        needed; the xpath carries all of them."""
        subject = _subject(
            "/config/predefined/profiles/url-filtering/entry[@name='default']", [])
        self.assertEqual(device_name_of(subject), "default")

    def test_a_subject_that_is_not_entry_grain_has_no_entry_name(self):
        """`/deviceconfig/setting/session`'s last `entry[@name=]` is the DEVICE's, and returning
        it would match a finding about the wrong row."""
        self.assertIsNone(device_name_of(_subject(f"{DEVICE}/deviceconfig/setting/session", [])))
        self.assertIsNone(device_name_of(_subject(
            f"{DEVICE}/vsys/entry[@name='vsys1']/profiles/custom-url-category", [])))

    def test_vsys_names_come_from_the_subjects_and_default_to_vsys1(self):
        stage6 = {"domain": "d", "subjects": {
            "a": _subject(f"{DEVICE}/vsys/entry[@name='vsys3']/zone/entry[@name='z']", []),
            "b": _subject(f"{DEVICE}/deviceconfig/setting/session", []),
        }}
        self.assertEqual(vsys_names_from_stage6(stage6), {SERIAL: {"vsys3"}})
        only_device_local = {"domain": "d", "subjects": {
            "b": _subject(f"{DEVICE}/deviceconfig/setting/session", [])}}
        # An appliance with no enforcement point is an appliance nothing normalises, because
        # every in-scope selector in flows.py reads through the points.
        self.assertEqual(vsys_names_from_stage6(only_device_local), {SERIAL: {"vsys1"}})


class BaseEstateTests(TestCase):
    """The three traps that cost the five thrown-away seeders the most."""

    def setUp(self):
        self.stage6 = {"domain": "zone-dos-protection", "devices": {
            SERIAL: {"software_version": "11.2.5"}}, "subjects": {
            "p01": _subject(
                f"{DEVICE}/network/profiles/zone-protection-profile/entry[@name='p01']",
                [{"key": "discard-ip-spoof", "value": "yes"}]),
            "z01": _subject(
                f"{DEVICE}/vsys/entry[@name='vsys1']/zone/entry[@name='z01']",
                [{"key": "network/layer3", "value": None}]),
        }}

    def test_trap_one_every_enforcement_point_is_in_scope(self):
        """`in_scope` DEFAULTS FALSE, and `flows.get_in_scope_appliances`,
        `get_in_scope_appliance_groups` and `get_in_scope_enforcement_points` ALL select through
        `filter(in_scope=True)`. Leave it default and the whole command normalises nothing and
        reports a clean estate - which cost one run a wrong row count it read as a finding."""
        from optivedge_integrations.integrations.platforms.pan_os.flows import (
            get_in_scope_appliance_groups, get_in_scope_appliances,
            get_in_scope_enforcement_points)

        station, appliances, points = build_base_estate(self.stage6)
        self.assertTrue(points)
        for point in points.values():
            self.assertTrue(point.in_scope)
        # Not just the flag - the selectors that read it must actually return the estate.
        self.assertEqual(len(get_in_scope_appliances(station)), len(appliances))
        self.assertEqual(len(get_in_scope_enforcement_points(station)), len(points))
        self.assertEqual(len(get_in_scope_appliance_groups(station)), 1)

    def test_trap_two_every_point_has_an_enforcement_node(self):
        """Required or the workbook refuses to build, on a tab belonging to no domain under
        test. `snapshots.choose_local_appliance` walks them too."""
        _station, _appliances, points = build_base_estate(self.stage6)
        for point in points.values():
            self.assertEqual(point.nodes.count(), 1)

    def test_trap_three_the_merged_snapshot_exists_before_anything_normalises(self):
        """`source_snapshot` is NOT NULL on both subject models, and every committed reader
        anchors to the merged read."""
        from optivedge_integrations.integrations.platforms.pan_os.normalization.snapshots import (
            latest_merged_snapshot)

        _station, _appliances, points = build_base_estate(self.stage6)
        for point in points.values():
            snapshot = latest_merged_snapshot(point)
            self.assertIsNotNone(snapshot)
            self.assertIn("config", snapshot.payload)

    def test_the_estate_normalises_through_the_committed_pipeline(self):
        """End to end: the payload the artifact describes reaches real subject rows, with no
        device contacted. This is the claim the whole command rests on."""
        from optivedge_integrations.integrations.models import Zone, ZoneProtectionProfile
        from optivedge_integrations.integrations.platforms.pan_os.flows import (
            renormalize_in_scope_configuration)

        station, _appliances, _points = build_base_estate(self.stage6)
        renormalize_in_scope_configuration(station)
        self.assertEqual(list(Zone.objects.values_list("name", flat=True)), ["z01"])
        # THE FLOW DOES NOT BUILD THIS ONE. Of the 57 normaliser wrappers in
        # `normalization/__init__.py`, exactly two appear nowhere in `flows.py`, and both are
        # zone-dos-protection's - so the committed renormalisation leaves the zone PROTECTION
        # profiles behind while building the zones that reference them.
        self.assertEqual(ZoneProtectionProfile.objects.count(), 0)
        self.assertEqual(run_supplemental_normalizers(station), [])
        self.assertEqual(
            list(ZoneProtectionProfile.objects.values_list("profile_name", flat=True)), ["p01"])

    def test_the_software_version_is_carried_off_the_artifact(self):
        """Not decoration: `security_profiles.resolve_max_version` grades a decryption
        profile's ceiling against the appliance's own top version."""
        _station, appliances, _points = build_base_estate(self.stage6)
        self.assertEqual(appliances[SERIAL].software_version, "11.2.5")


class ReconcileTests(TestCase):
    """Reconciliation is the command's oracle, so its own matching has to be pinned."""

    def _stage6(self):
        return {"domain": "d", "subjects": {
            # A subject whose LABEL differs from the entry it names, which is the common case.
            "label-not-name": _subject(
                f"{DEVICE}/network/profiles/zone-protection-profile/entry[@name='p01']",
                [{"key": "discard-ip-spoof", "value": "no"}]),
        }}

    def _stage8(self, produces, severity):
        return {"domain": "d", "controls": {"PAN-ZON-002": {"diff": {"subjects": [
            {"stage6_subject": "label-not-name",
             "expected": {"produces": produces, "severity": severity},
             "actual": {"produces": produces, "severity": severity},
             "agrees": True}]}}}}

    def test_a_verdict_with_no_finding_reconciles_when_stage8_declared_none(self):
        verdicts = reconcile(self._stage6(), self._stage8("no_finding", None))
        self.assertEqual(len(verdicts), 1)
        self.assertTrue(verdicts[0].ok)
        self.assertEqual(verdicts[0].device_name, "p01")

    def test_a_declared_finding_that_the_build_does_not_produce_is_a_mismatch(self):
        """The failure the whole step exists to catch: without it a run reads its own seeding
        mistakes and cannot tell them from presentation defects."""
        verdicts = reconcile(self._stage6(), self._stage8("finding_at_severity", "high"))
        self.assertEqual(len(verdicts), 1)
        self.assertFalse(verdicts[0].ok)
        self.assertEqual(verdicts[0].got_produces, "no_finding")

    def test_reconciliation_reads_stage8s_measured_actual_and_not_its_expected(self):
        """On the domains where the two disagree it is stage 8 that was right, and `agrees` is
        carried through so a reader can see which rows those were."""
        stage8 = self._stage8("no_finding", None)
        row = stage8["controls"]["PAN-ZON-002"]["diff"]["subjects"][0]
        row["expected"] = {"produces": "finding_at_severity", "severity": "critical"}
        row["agrees"] = False
        verdicts = reconcile(self._stage6(), stage8)
        self.assertTrue(verdicts[0].ok)
        self.assertFalse(verdicts[0].agrees)


class CommandArgumentTests(SimpleTestCase):
    """The refusals. A command that silently handles four of eleven remaining domains is worse
    than one that says which four, because the fifth run will trust it."""

    def test_it_refuses_a_domain_slug_with_nowhere_to_resolve_it(self):
        with self.assertRaises(CommandError) as caught:
            call_command("print_findings_table", "url-filtering", stdout=StringIO())
        self.assertIn("OEP_ARTIFACTS_DIR", str(caught.exception))

    def test_it_refuses_a_stage6_and_stage8_pair_for_different_domains(self):
        with TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "s6.json").write_text(json.dumps({"domain": "a", "subjects": {}}))
            (base / "s8.json").write_text(json.dumps({"domain": "b", "controls": {}}))
            with self.assertRaises(CommandError) as caught:
                call_command("print_findings_table", stage6=str(base / "s6.json"),
                             stage8=str(base / "s8.json"), stdout=StringIO())
        self.assertIn("artifact mismatch", str(caught.exception))

    def test_it_names_the_subjects_it_cannot_place_rather_than_seeding_a_partial_estate(self):
        """The coverage boundary, enforced rather than documented: a subject with no xpath or no
        device is a subject this command cannot place, and a partial estate would read as a
        clean one."""
        with TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "s6.json").write_text(json.dumps({"domain": "a", "subjects": {
                "fine": _subject(f"{DEVICE}/deviceconfig/setting/session", []),
                "no-xpath": {"identity": {"device": SERIAL}, "verified": {"read_back": []}},
                "no-device": {"identity": {"xpath": DEVICE}, "verified": {"read_back": []}},
            }}))
            (base / "s8.json").write_text(json.dumps({"domain": "a", "controls": {}}))
            with self.assertRaises(CommandError) as caught:
                call_command("print_findings_table", stage6=str(base / "s6.json"),
                             stage8=str(base / "s8.json"), stdout=StringIO())
        message = str(caught.exception)
        self.assertIn("NOT COVERED", message)
        self.assertIn("no-xpath", message)
        self.assertIn("no-device", message)
        self.assertNotIn("fine", message)


class XpathSlashInNameTests(SimpleTestCase):
    """A PAN-OS interface name contains a slash, and splitting the xpath on `/` breaks inside
    the quoted predicate. Measured across the 28 stage 6 artifacts on disk, the naive split
    costs `management-services` and `network-hardening` entirely - 112 subjects and 95 declared
    verdicts - so this is the difference between 26 domains covered and 28."""

    def test_an_interface_subject_places_under_its_full_name(self):
        # stage6-network-hardening.json, and the same shape in stage6-management-services.json
        stage6 = {"domain": "d", "subjects": {"eth": _subject(
            f"{DEVICE}/network/interface/ethernet/entry[@name='ethernet1/1']/layer3",
            [{"key": "interface-management-profile", "value": "mgmt-allow"}])}}
        device = payloads_from_stage6(stage6)[SERIAL].merged["config"]["devices"]["entry"][0]
        entry = device["network"]["interface"]["ethernet"]["entry"][0]
        self.assertEqual(entry["@name"], "ethernet1/1")
        self.assertEqual(entry["layer3"]["interface-management-profile"], "mgmt-allow")

    def test_the_entry_name_of_an_interface_subject_is_not_truncated(self):
        self.assertEqual(
            device_name_of(_subject(
                f"{DEVICE}/network/interface/ethernet/entry[@name='ethernet1/9']", [])),
            "ethernet1/9")


class SupplementalNormalizerTests(SimpleTestCase):
    """`_estate.SUPPLEMENTAL_NORMALIZERS` against the flow it claims to supplement.

    The list is a claim about `flows.py` - that these normalisers are unreachable from it - and
    a claim about another repository goes stale silently. The first version of the list was read
    off a naming convention, found two of the seven, and left `ipsec-crypto` with every subject
    model empty and 64 reconciliation mismatches. So the claim is checked rather than asserted.
    """

    def _flows_source(self):
        from optivedge_integrations.integrations.platforms.pan_os import flows
        return Path(flows.__file__).read_text()

    def test_every_listed_normaliser_exists_and_takes_the_grain_declared(self):
        import inspect

        from optivedge_integrations.integrations.platforms.pan_os import normalization
        from assessments.tests._estate import SUPPLEMENTAL_NORMALIZERS

        self.assertTrue(SUPPLEMENTAL_NORMALIZERS)
        for grain, name in SUPPLEMENTAL_NORMALIZERS:
            normalize = getattr(normalization, name, None)
            self.assertTrue(callable(normalize), f"{name} is not exported any more")
            first = list(inspect.signature(normalize).parameters)[0]
            self.assertEqual(first, grain, f"{name} takes {first}, not {grain}")

    def test_none_of_them_is_reachable_from_the_flow(self):
        """If one becomes reachable, running it here would normalise the same subtree twice. The
        passes replace wholesale rather than upsert, so a double run is not harmful - but the
        list would then be claiming something false, and the next entry added on that basis
        would be wrong."""
        import re

        from optivedge_integrations.integrations.platforms.pan_os import normalization
        from assessments.tests._estate import SUPPLEMENTAL_NORMALIZERS

        source = self._flows_source()
        for _grain, name in SUPPLEMENTAL_NORMALIZERS:
            self.assertIsNone(
                re.search(r"\b%s\b" % re.escape(name), source),
                f"{name} is referenced in flows.py now, so it is no longer supplemental")
            # And not through a wrapper the flow calls, which is the hole the first version of
            # this list fell through.
            for wrapper, delegate in self._wrappers(normalization).items():
                if name in delegate and re.search(r"\b%s\b" % re.escape(wrapper), source):
                    self.fail(f"{name} is reached from flows.py via {wrapper}")

    def _wrappers(self, normalization):
        import re

        source = Path(normalization.__file__).read_text()
        out = {}
        for match in re.finditer(
                r"\ndef (normalize_\w+)\(.*?\)(?:\s*->[^:]*)?:\n(.*?)(?=\ndef |\Z)",
                source, re.S):
            out[match.group(1)] = set(re.findall(r"return (normalize_\w+)\(", match.group(2)))
        return out

    def test_the_flow_still_does_not_mention_ipsec_at_all(self):
        """The measurement that made the gap obvious, kept as a tripwire: three of the seven are
        this domain's, and the flow has never referred to it."""
        self.assertNotIn("ipsec", self._flows_source().lower())
