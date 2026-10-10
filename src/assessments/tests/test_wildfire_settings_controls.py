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
from optivedge_integrations.integrations.models.wildfire_settings import (
    defaults_for_version,
)

#: PAN-OS's own declared defaults, from Panorama's Size Limit tooltip. Release-invariant for
#: what this control asserts: 11.2 adds `eml`, which is excluded on two counts.
ESTABLISHED = "11.1.13-h3"
UNESTABLISHED = "11.2.3-h3"
DEFAULTS = defaults_for_version(ESTABLISHED)
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

    def _settings(self, name, *, limits=None, excluded=(), benign=True, grayware=True,
                  version=ESTABLISHED):
        self.n += 1
        appliance = Appliance.objects.create(
            management_station=self.station, appliance_group=self.group,
            serial_number=f"S-{self.n}", hostname=name, software_version=version)
        snapshot = Snapshot.objects.create(
            management_station=self.station, appliance=appliance,
            source_type="test", collected_at=timezone.now())
        table = defaults_for_version(version) or {}
        limits = dict(table) if limits is None else limits
        untuned = sorted(t for t, d in table.items() if limits.get(t, d) == d)
        return WildfireSettings.objects.create(
            management_station=self.station, appliance=appliance,
            appliance_group=self.group, source_snapshot=snapshot,
            size_limits=limits, untuned_file_types=untuned,
            size_limits_untuned=bool(untuned) or not table,
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

    # --- PAN-AVW-004, the tuning check ------------------------------------------------------

    def test_an_untouched_device_fires(self):
        """What the PA-5220s actually look like: no file-size-limit node at all, so every
        type is at its default. The sentence says "has not sized ANY", because a finding that
        reads like a misconfiguration when it is an unset default sends an assessor looking
        for who changed it."""
        self._settings("untouched")

        fired = self._fired("PAN-AVW-004")
        self.assertIn("untouched", fired)
        self.assertIn("has not sized ANY", fired["untouched"])

    def test_every_type_moved_off_its_default_is_silent(self):
        self._settings("tuned", limits={k: v + 1 for k, v in DEFAULTS.items()})

        self.assertEqual(self._fired("PAN-AVW-004"), {})

    def test_tuning_DOWN_counts_as_tuning(self):
        """Help p.774 advises lowering against buffer space, so a reduced limit is evidence
        of a decision exactly as a raised one is. A control asserting the maximum would call
        the vendor's own advice a finding."""
        self._settings("lowered", limits={k: 1 for k in DEFAULTS})

        self.assertEqual(self._fired("PAN-AVW-004"), {})

    def test_one_type_left_at_its_default_still_fires_and_is_named(self):
        limits = {k: v + 1 for k, v in DEFAULTS.items()}
        limits["pe"] = DEFAULTS["pe"]
        self._settings("partial", limits=limits)

        fired = self._fired("PAN-AVW-004")
        self.assertIn("pe", fired["partial"])

    def test_a_11_2_device_is_assessed_the_same_way(self):
        """11.2 adds `eml` to the key set and nothing else, and `eml` is excluded - so the
        asserted set does not vary by release and an 11.2 device is judged on the same ten."""
        self._settings("on-11-2", version=UNESTABLISHED)

        self.assertIn("on-11-2", self._fired("PAN-AVW-004"))

    def test_a_single_kilobyte_off_the_default_counts_as_tuned(self):
        """The lab's stack held ms-office at 16385 against a default of 16384, and that one
        kilobyte is the difference between "nobody sized this" and "somebody did". The rule
        Jason set is deliberately literal, so this is recorded rather than smoothed over."""
        limits = dict(DEFAULTS)
        limits["ms-office"] = 16385
        self._settings("one-kb", limits=limits)

        fired = self._fired("PAN-AVW-004")
        self.assertIn("one-kb", fired)
        self.assertNotIn("ms-office", fired["one-kb"])

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

    def test_the_two_controls_report_separately_on_one_appliance(self):
        """One model, two controls, two findings - and each sentence has to be about its own
        question or an engineer cannot tell which thing to fix."""
        self._settings("both-bad", benign=False)

        self.assertIn("file size limit", self._fired("PAN-AVW-004")["both-bad"])
        self.assertIn("benign", self._fired("PAN-AVW-005")["both-bad"])
