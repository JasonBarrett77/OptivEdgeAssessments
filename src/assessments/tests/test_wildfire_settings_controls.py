"""PAN-AVW-004 and PAN-AVW-005 - the device-wide WildFire settings.

Two controls over one model with OPPOSITE polarities, which is the thing worth testing
together: 004 fires when nothing has been TUNED, 005 when something is WITHHELD. Both fire on
an untouched device, so the silent cases are the ones that had no example until these.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.models import (
    AssessmentRun, Control, WildfireSettingsFinding)
from assessments.tests._seed import seed_controls
from assessments.wildfire_settings_findings import (
    generate_wildfire_settings_findings)
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    ManagementStation,
    Snapshot,
    WildfireSettings,
)

#: What the control ASSERTS - ten, not eleven. `eml` is excluded because a
#: template cannot set it; see WildfireSettings.TEMPLATE_UNSETTABLE.
DEFAULTS = WildfireSettings.ASSERTED_SIZE_LIMITS
#: Every type moved off its default, which is the only fully-tuned state.
TUNED = {k: v + 1 for k, v in DEFAULTS.items()}


class WildfireSettingsControlTests(TestCase):
    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.wf")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-wf",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        seed_controls(["PAN-AVW-004", "PAN-AVW-005"],
                      control_type=Control.ControlType.WILDFIRE_SETTINGS)
        self.n = 0

    def _settings(self, name, *, limits=None, excluded=(), benign=True, grayware=True):
        self.n += 1
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{self.n}", hostname=name)
        snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="test", collected_at=timezone.now())
        limits = DEFAULTS if limits is None else limits
        untuned = sorted(t for t, d in DEFAULTS.items() if limits.get(t, d) == d)
        return WildfireSettings.objects.create(
            management_station=self.station, appliance=appliance,
            appliance_group=self.group, source_snapshot=snapshot,
            size_limits=limits, untuned_file_types=untuned,
            size_limits_untuned=bool(untuned),
            session_info_excluded=list(excluded),
            shares_full_session_info=not excluded,
            report_benign_file=benign, report_grayware_file=grayware)

    def _fired(self, control_id):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_wildfire_settings_findings(run)
        return {f.wildfire_settings.appliance.hostname: f.summary for f in
                WildfireSettingsFinding.objects.filter(
                    control__control_id=control_id, assessment_run=run)
                .select_related("wildfire_settings__appliance")}

    # --- PAN-AVW-004 is DEACTIVATED ---------------------------------------------------------

    def test_PAN_AVW_004_is_deactivated_and_reports_nothing(self):
        """It was built and switched off the same day, 2026-10-09.

        It compared each per-type file size limit against a recorded PAN-OS default, and
        those values are not defaults - they are configuration held by the template STACK on
        the lab they were measured from. All six TEMPLATES were checked and none held a
        wildfire node; the conclusion that nothing set them skipped the STACK, which holds
        its own configuration and overrides its member templates.

        So the comparison was against one lab's stack config: wrong on that lab, meaningless
        anywhere else. Off until the real defaults are measured, which needs the UI - a
        device where nothing sets them shows no node in configuration at all.

        The COMPUTATION is still covered, in OptivEdgeIntegrations' `untuned` tests. What is
        asserted here is that nothing reaches an assessor until the reference values do.
        """
        from assessments.controls_catalog.registry import load_seed_payload

        spec = next(c for cat in load_seed_payload()["catalogs"]
                    for c in cat["controls"] if c["control_id"] == "PAN-AVW-004")
        self.assertFalse(spec["is_active"])
        self.assertIn("DEACTIVATED", spec["description"])

        self._settings("untouched")
        self.assertEqual(self._fired("PAN-AVW-004"), {})

    # --- PAN-AVW-005, session information and verdict reporting -----------------------------

    def test_full_sharing_with_both_reports_is_silent(self):
        self._settings("open", limits=TUNED)

        self.assertEqual(self._fired("PAN-AVW-005"), {})

    def test_withholding_anything_fires_and_names_it(self):
        """The config stores EXCLUSIONS, so a non-empty list is the gap. Reading the UI's
        ticked checkbox as a stored value would invert this."""
        self._settings("withholds", limits=TUNED, excluded=["exclude-url"])

        fired = self._fired("PAN-AVW-005")
        self.assertIn("withholds", fired)
        self.assertIn("exclude-url", fired["withholds"])

    def test_either_report_flag_off_fires(self):
        self._settings("no-benign", limits=TUNED, benign=False)
        self._settings("no-grayware", limits=TUNED, grayware=False)

        fired = self._fired("PAN-AVW-005")
        self.assertIn("benign verdicts not reported", fired["no-benign"])
        self.assertIn("grayware verdicts not reported", fired["no-grayware"])

    def test_an_untouched_device_fires_on_both_report_flags(self):
        """Both are implicitly NO, measured 2026-10-09 - so the default state fails this
        half even though it passes the session-information half."""
        settings = self._settings("default-reports", limits=TUNED,
                                  benign=False, grayware=False)

        self.assertTrue(settings.shares_full_session_info)
        fired = self._fired("PAN-AVW-005")
        self.assertIn("benign", fired["default-reports"])
        self.assertIn("grayware", fired["default-reports"])

    def test_only_the_active_control_reports_on_a_shared_model(self):
        """Two controls share WildfireSettings and only one is active. The sentence builder
        picks per control, so the risk when 004 comes back is that the wrong sentence is
        written for a row both match - which is what this guards."""
        self._settings("both-bad", benign=False)

        self.assertEqual(self._fired("PAN-AVW-004"), {})
        self.assertIn("benign", self._fired("PAN-AVW-005")["both-bad"])
