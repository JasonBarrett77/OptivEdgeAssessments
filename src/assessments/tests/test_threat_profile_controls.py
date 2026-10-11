"""PAN-SPY-004, PAN-SPY-005, PAN-VLN-003, PAN-VLN-004.

Four controls over two profile kinds that are nearly - but not quite - the same shape, and
the near-misses are what these tests pin:

    the inline engines differ        five detectors against two, and spyware's action
                                     accepts `drop` where vulnerability's does not
    the exception surfaces differ    four on anti-spyware, two on vulnerability, because
                                     the latter has no botnet tree
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.models import AssessmentRun, Control, SecurityProfileFinding
from assessments.security_profile_findings import generate_security_profile_findings
from assessments.tests._seed import seed_controls
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


class ThreatProfileControlTests(TestCase):
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
        seed_controls(["PAN-SPY-004", "PAN-SPY-005", "PAN-VLN-003", "PAN-VLN-004"],
                      control_type=Control.ControlType.SECURITY_PROFILE)
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

    def _fired(self, control_id):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_security_profile_findings(run)
        return {f.security_profile.name for f in
                SecurityProfileFinding.objects.filter(
                    control__control_id=control_id, assessment_run=run)
                .select_related("security_profile")}

    # --- inline cloud analysis: PAN-SPY-004 and PAN-VLN-003 ---------------------------------

    def _all(self, kind, action):
        return {d: action for d in DETECTORS[kind]}

    def test_a_profile_mentioning_no_detector_fires(self):
        """Every lab profile is in this state: the predefined profiles carry zero entries
        for this engine, so nothing runs. Without a detector row per catalogued detector
        there would be nothing to report and it would read as fine."""
        self._profile("none-spy", SPY)
        self._profile("none-vln", VLN)

        self.assertEqual(self._fired("PAN-SPY-004"), {"none-spy"})
        self.assertEqual(self._fired("PAN-VLN-003"), {"none-vln"})

    def test_every_detector_blocking_is_silent(self):
        self._profile("hard-spy", SPY, actions=self._all(SPY, "reset-both"))
        self._profile("hard-vln", VLN, actions=self._all(VLN, "reset-both"))

        self.assertEqual(self._fired("PAN-SPY-004"), set())
        self.assertEqual(self._fired("PAN-VLN-003"), set())

    def test_alert_runs_and_still_fires(self):
        """`enable(alert-only)` from PAN-AVW-002 under another name: the detector runs, the
        traffic passes. Reading it as enabled would pass a profile that only watches."""
        self._profile("alert-spy", SPY, actions=self._all(SPY, "alert"))

        self.assertEqual(self._fired("PAN-SPY-004"), {"alert-spy"})

    def test_one_detector_left_behind_is_enough(self):
        actions = self._all(SPY, "reset-both")
        actions["SSL Command and Control detector"] = "alert"
        self._profile("almost", SPY, actions=actions)

        self.assertEqual(self._fired("PAN-SPY-004"), {"almost"})

    def test_drop_blocks_on_spyware(self):
        """Spyware's action accepts `drop`; vulnerability's does not. Treating the two
        engines as one enum would offer a value the device rejects."""
        self._profile("drops", SPY, actions=self._all(SPY, "drop"))

        self.assertEqual(self._fired("PAN-SPY-004"), set())

    def test_the_two_controls_do_not_report_each_others_profiles(self):
        self._profile("spy-bad", SPY)
        self._profile("vln-bad", VLN)

        self.assertEqual(self._fired("PAN-SPY-004"), {"spy-bad"})
        self.assertEqual(self._fired("PAN-VLN-003"), {"vln-bad"})

    def test_an_unused_predefined_profile_is_out_of_scope(self):
        self._profile("shelf", SPY, predefined=True, used=False)

        self.assertEqual(self._fired("PAN-SPY-004"), set())

    # --- exception hygiene: PAN-SPY-005 and PAN-VLN-004 -------------------------------------

    def test_a_profile_with_no_exceptions_is_silent(self):
        self._profile("clean-spy", SPY, actions=self._all(SPY, "reset-both"))
        self._profile("clean-vln", VLN, actions=self._all(VLN, "reset-both"))

        self.assertEqual(self._fired("PAN-SPY-005"), set())
        self.assertEqual(self._fired("PAN-VLN-004"), set())

    def test_one_signature_exception_fires(self):
        self._profile("one", SPY, exceptions={"threat-exception": 1})

        self.assertEqual(self._fired("PAN-SPY-005"), {"one"})

    def test_an_exception_on_a_surface_the_corpus_does_NOT_name_fires(self):
        """The reason the count was widened. Before 2026-10-10 only `threat-exception` was
        counted, so a profile exempting addresses from inline analysis counted zero."""
        self._profile("inline-exempt", SPY,
                      exceptions={"inline-exception-ip-address": 12})

        self.assertEqual(self._fired("PAN-SPY-005"), {"inline-exempt"})

    def test_the_detail_names_the_surface_because_the_fix_differs(self):
        profile = self._profile("spread", SPY, exceptions={
            "threat-exception": 2, "botnet-whitelist": 1,
            "inline-exception-ip-address": 3})

        self.assertEqual(profile.threat_exception_count, 6)
        self.assertEqual(
            profile.exception_detail,
            "1 in botnet-whitelist, 3 in inline-exception-ip-address, 2 in threat-exception")

    def test_the_two_hygiene_controls_stay_on_their_own_kind(self):
        self._profile("spy-exc", SPY, exceptions={"threat-exception": 1})
        self._profile("vln-exc", VLN, exceptions={"threat-exception": 1})

        self.assertEqual(self._fired("PAN-SPY-005"), {"spy-exc"})
        self.assertEqual(self._fired("PAN-VLN-004"), {"vln-exc"})
