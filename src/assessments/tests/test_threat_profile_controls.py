"""What PAN-SPY-004/005 and PAN-VLN-003/004 read off a profile.

Two profile kinds that are nearly - but not quite - the same shape, and the near-misses are
what these tests pin:

    the inline engines differ        five detectors against two, and spyware's action
                                     accepts `drop` where vulnerability's does not
    the exception surfaces differ    four on anti-spyware, two on vulnerability, because
                                     the latter has no botnet tree

THESE ARE PROFILE SEMANTICS, NOT FINDINGS. The four controls became rule-based on 2026-10-12
and their findings are tested in test_security_profile_controls.py, which builds rules. What
stays here is the layer underneath: the properties a per-rule verdict reads to decide whether
the profile in force satisfies the assertion. They are tested directly because that is where
the subtlety is - `alert` runs a detector and lets the traffic through, an unmentioned detector
does not run at all, and an exception on a surface the corpus does not name still counts.

Scope - which profile reaches which rule, and what happens when none does - moved to the rule
side with the controls, and is not retested here.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    ManagementStation,
    PolicyObjectNamespace,
    SecurityProfile,
    SecurityProfileInlineDetector,
    Snapshot,
)

SPY = SecurityProfile.KIND_SPYWARE
VLN = SecurityProfile.KIND_VULNERABILITY
DETECTORS = {SPY: SecurityProfileInlineDetector.SPYWARE_DETECTORS,
             VLN: SecurityProfileInlineDetector.VULNERABILITY_DETECTORS}


class ThreatProfileSemanticsTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.spy")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-spy",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number="S-SPY", hostname="fw-spy")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=self.appliance,
            source_type="test", collected_at=timezone.now())
        self.rank = 0

    def _profile(self, name, kind, *, actions=None, exceptions=None, predefined=False,
                 used=True):
        """`actions` maps detector name -> inline-policy-action; absent means unmentioned."""
        self.rank += 1
        namespace = (PolicyObjectNamespace.PREDEFINED if predefined
                     else PolicyObjectNamespace.LOCAL_SHARED)
        surfaces = exceptions or {}
        profile = SecurityProfile.objects.create(
            management_station=self.station, appliance_group=self.group,
            source_snapshot=self.snapshot, config_source="local", name=name,
            namespace_type=namespace,
            namespace_value="predefined" if predefined else "shared",
            precedence_rank=self.rank, kind=kind, is_predefined=predefined,
            is_used=used, referrer_count=1 if used else 0,
            threat_exception_count=sum(surfaces.values()), exception_surfaces=surfaces)
        # A row per detector the CONTENT release knows about, mentioned or not - an
        # unmentioned detector does not run and must have a row saying so.
        for detector in DETECTORS[kind]:
            action = (actions or {}).get(detector, "")
            SecurityProfileInlineDetector.objects.create(
                security_profile=profile, name=detector, configured_action=action,
                enabled=bool(action),
                blocks=action in SecurityProfileInlineDetector.BLOCKING_ACTIONS)
        return profile

    def _not_blocking(self, profile):
        """What PAN-SPY-004 / PAN-VLN-003's verdict reads: detectors that do not stop traffic."""
        return set(profile.inline_detectors_not_blocking)

    # --- inline cloud analysis: PAN-SPY-004 and PAN-VLN-003 ---------------------------------

    def _all(self, kind, action):
        return {d: action for d in DETECTORS[kind]}

    def test_a_profile_mentioning_no_detector_fires(self):
        """Every lab profile is in this state: the predefined profiles carry zero entries
        for this engine, so nothing runs. Without a detector row per catalogued detector
        there would be nothing to report and it would read as fine."""
        spy = self._profile("none-spy", SPY)
        vln = self._profile("none-vln", VLN)

        self.assertEqual(len(self._not_blocking(spy)), 5)
        self.assertEqual(len(self._not_blocking(vln)), 2)

    def test_every_detector_blocking_is_silent(self):
        spy = self._profile("hard-spy", SPY, actions=self._all(SPY, "reset-both"))
        vln = self._profile("hard-vln", VLN, actions=self._all(VLN, "reset-both"))

        self.assertEqual(self._not_blocking(spy), set())
        self.assertEqual(self._not_blocking(vln), set())

    def test_alert_runs_and_still_fires(self):
        """`enable(alert-only)` from PAN-AVW-002 under another name: the detector runs, the
        traffic passes. Reading it as enabled would pass a profile that only watches."""
        profile = self._profile("alert-spy", SPY, actions=self._all(SPY, "alert"))

        self.assertEqual(len(self._not_blocking(profile)), 5)
        self.assertTrue(all(d.enabled for d in profile.inline_detectors.all()),
                        "alert RUNS the detector - enabled and blocks are two facts")

    def test_one_detector_left_behind_is_enough(self):
        actions = self._all(SPY, "reset-both")
        actions["SSL Command and Control detector"] = "alert"
        profile = self._profile("almost", SPY, actions=actions)

        self.assertEqual(self._not_blocking(profile), {"SSL Command and Control detector"})

    def test_drop_blocks_on_spyware(self):
        """Spyware's action accepts `drop`; vulnerability's does not. Treating the two
        engines as one enum would offer a value the device rejects."""
        profile = self._profile("drops", SPY, actions=self._all(SPY, "drop"))

        self.assertEqual(self._not_blocking(profile), set())

    def test_each_kind_carries_only_its_own_detectors(self):
        """Treating the two engines as one catalogue would give a vulnerability profile the
        five C2 detectors and report every one of them as missing."""
        spy = self._profile("spy-bad", SPY)
        vln = self._profile("vln-bad", VLN)

        self.assertEqual({d.name for d in spy.inline_detectors.all()},
                         set(DETECTORS[SPY]))
        self.assertEqual({d.name for d in vln.inline_detectors.all()},
                         set(DETECTORS[VLN]))

    # --- exception hygiene: PAN-SPY-005 and PAN-VLN-004 -------------------------------------

    def test_a_profile_with_no_exceptions_is_silent(self):
        spy = self._profile("clean-spy", SPY, actions=self._all(SPY, "reset-both"))
        vln = self._profile("clean-vln", VLN, actions=self._all(VLN, "reset-both"))

        self.assertEqual((spy.threat_exception_count, vln.threat_exception_count), (0, 0))

    def test_one_signature_exception_fires(self):
        profile = self._profile("one", SPY, exceptions={"threat-exception": 1})

        self.assertEqual(profile.threat_exception_count, 1)
        self.assertEqual(profile.exception_detail, "1 in threat-exception")

    def test_an_exception_on_a_surface_the_corpus_does_NOT_name_fires(self):
        """The reason the count was widened. Before 2026-10-10 only `threat-exception` was
        counted, so a profile exempting addresses from inline analysis counted zero."""
        profile = self._profile("inline-exempt", SPY,
                                exceptions={"inline-exception-ip-address": 12})

        self.assertEqual(profile.threat_exception_count, 12)
        self.assertEqual(profile.exception_detail, "12 in inline-exception-ip-address")

    def test_the_detail_names_the_surface_because_the_fix_differs(self):
        profile = self._profile("spread", SPY, exceptions={
            "threat-exception": 2, "botnet-whitelist": 1,
            "inline-exception-ip-address": 3})

        self.assertEqual(profile.threat_exception_count, 6)
        self.assertEqual(
            profile.exception_detail,
            "1 in botnet-whitelist, 3 in inline-exception-ip-address, 2 in threat-exception")

    def test_both_kinds_count_exceptions_the_same_way(self):
        """The two hygiene controls are separate because the NODES differ - the vulnerability
        exception entry carries `time-attribute` and there is no botnet tree - but the count
        they read is one column with one meaning."""
        spy = self._profile("spy-exc", SPY, exceptions={"threat-exception": 1})
        vln = self._profile("vln-exc", VLN, exceptions={"threat-exception": 1})

        self.assertEqual((spy.threat_exception_count, vln.threat_exception_count), (1, 1))
