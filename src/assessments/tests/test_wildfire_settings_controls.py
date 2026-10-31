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
# THE NORMALIZER'S OWN DERIVATIONS, imported rather than restated. All three columns the
# fixture gained on 2026-10-31 are computed from values it already has, and a second copy of
# that arithmetic here would be free to drift from the one production uses - which is the
# defect `_seed.py` records about its own field list, one layer down.
from optivedge_integrations.integrations.platforms.pan_os.normalization.wildfire_settings import (
    verdict_reporting_gap as derive_verdict_reporting_gap,
    wholly_untuned as derive_wholly_untuned,
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
            # THE THREE DERIVED COLUMNS ARE SET HERE, because each one's migration default is
            # the FIRING side and none of those defaults is a state a collection can produce:
            # `normalize_wildfire_settings` writes all three on every row it touches, in the
            # same call that writes the columns above. Leaving them out meant a fully tuned
            # appliance still carried `size_limits_wholly_untuned=True` and an appliance
            # reporting both verdict kinds still carried `verdict_reporting_gap="both"`, so
            # three tests asserting SILENCE fired the moment PAN-AVW-004 and -005 began
            # claiming on them - correct behaviour against an unreachable fixture.
            size_limits_wholly_untuned=derive_wholly_untuned(limits, table),
            session_info_excluded=list(excluded),
            shares_full_session_info=not excluded,
            # True unconditionally, exactly as the normalizer sets it: control only reaches
            # that line when a merged snapshot AND a device entry were both found, so a row
            # this fixture writes is a row whose node was read. `session_info_read=False` is
            # reachable only on a row nothing has normalized, and a test about THAT state
            # should set it explicitly rather than inherit it.
            session_info_read=True,
            report_benign_file=benign, report_grayware_file=grayware,
            verdict_reporting_gap=derive_verdict_reporting_gap(benign, grayware))

    def _fired(self, control_id):
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_wildfire_settings_findings(run)
        return {f.wildfire_settings.appliance.hostname: f.summary for f in
                WildfireSettingsFinding.objects.filter(
                    control__control_id=control_id, assessment_run=run)
                .select_related("wildfire_settings__appliance")}

    def _severities(self, control_id):
        """{hostname: severity}. The graded half of PAN-AVW-005 is about WHICH tier, and the
        summary-keyed helper above cannot see one."""
        run = AssessmentRun.objects.create(
            name="run", status=AssessmentRun.Status.RUNNING, started_at=timezone.now())
        generate_wildfire_settings_findings(run)
        return {f.wildfire_settings.appliance.hostname: f.severity for f in
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

    def test_one_type_left_at_its_default_is_SILENT(self):
        """NINE OF TEN MOVED IS AN ANSWER, and this is the assertion that changed on
        2026-10-31 when the control moved from `size_limits_untuned` to
        `size_limits_wholly_untuned`.

        The two columns are the ANY and the ALL quantifier over the same comparison and the
        store has always carried both. This test asserted the ANY reading - a device with nine
        types moved and `pe` left alone fired, and the finding named `pe`.

        STAGE 3 ASSERTS THE OTHER ONE, in its own words: the largest file the firewall will
        send has been sized for this platform "rather than left WHOLLY as the software shipped
        it", and the pipeline's stage 5 record for this control clauses the ALL column
        deliberately, naming the dispute rather than resolving it quietly - "the control exists
        to ask whether anybody sized these, and an estate that moved nine of ten has answered
        that".

        The finding SENTENCE was always on that side too, which is the cheapest evidence that
        the ANY column was the mistake: it reads "has not sized ANY", which is simply false
        about this device. See `test_an_untouched_device_fires`, which pins that wording.
        """
        limits = {k: v + 1 for k, v in DEFAULTS.items()}
        limits["pe"] = DEFAULTS["pe"]
        self._settings("partial", limits=limits)

        self.assertEqual(self._fired("PAN-AVW-004"), {})

    def test_a_11_2_device_is_assessed_the_same_way(self):
        """11.2 adds `eml` to the key set and nothing else, and `eml` is excluded - so the
        asserted set does not vary by release and an 11.2 device is judged on the same ten."""
        self._settings("on-11-2", version=UNESTABLISHED)

        self.assertIn("on-11-2", self._fired("PAN-AVW-004"))

    def test_a_single_kilobyte_off_the_default_counts_as_tuned(self):
        """The lab's stack held ms-office at 16385 against a default of 16384, and that one
        kilobyte is the difference between "nobody sized this" and "somebody did". The rule
        Jason set is deliberately literal, so this is recorded rather than smoothed over.

        UNDER THE ALL QUANTIFIER THAT MAKES THE WHOLE DEVICE SILENT, which is the sharpest
        case in this file and the reason the measurement is kept. One kilobyte on one of ten
        types is somebody having touched these settings, so the control that asks whether
        anybody sized them has its answer. It is also the case most likely to be called a
        false negative later: nine types really are at their defaults on that appliance. The
        answer is that PAN-AVW-004 asks one question and not ten - an estate wanting per-type
        coverage is asking for a different control, and `untuned_file_types` on the row carries
        the nine names for whoever writes it.
        """
        limits = dict(DEFAULTS)
        limits["ms-office"] = 16385
        self._settings("one-kb", limits=limits)

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

    def test_the_two_controls_report_separately_on_one_appliance(self):
        """One model, two controls, two findings - and each sentence has to be about its own
        question or an engineer cannot tell which thing to fix."""
        self._settings("both-bad", benign=False)

        self.assertIn("file size limit", self._fired("PAN-AVW-004")["both-bad"])
        self.assertIn("benign", self._fired("PAN-AVW-005")["both-bad"])

    # --- PAN-AVW-005's verdict-reporting GRADING, added 2026-10-31 --------------------------
    #
    # The reporting half ranks its two gaps differently - unwanted-file verdicts low,
    # harmless-file verdicts informational - and a disjunction over the two source booleans
    # cannot carry two severities. So the baseline carries the session-information half alone
    # and the reporting half is three calibration queries over `verdict_reporting_gap`, whose
    # four members are mutually exclusive on a single-valued column.

    def test_the_grayware_gap_alone_reports_at_low(self):
        """The near-miss tier, and the half the corpus entry's own xpath names."""
        self._settings("gray-gap", limits=TUNED, benign=True, grayware=False)

        self.assertEqual(self._severities("PAN-AVW-005"), {"gray-gap": "low"})

    def test_the_benign_gap_alone_reports_at_INFORMATIONAL(self):
        """Graded BELOW the other half: the volume is high and the hunting value lower, and a
        record of what was examined and cleared is still how an estate knows the submission
        path works at all. `informational` is a severity stage 3 cannot express and the store
        can."""
        self._settings("benign-gap", limits=TUNED, benign=False, grayware=True)

        self.assertEqual(self._severities("PAN-AVW-005"), {"benign-gap": "informational"})

    def test_neither_report_flag_reports_at_the_WORSE_of_the_two(self):
        """NOT a sum. A severity is not cumulative, so the state with both gaps is graded at
        the worse of them rather than above either - and it is also the state an untouched
        appliance is in, since both source booleans are implicitly no."""
        self._settings("no-reports", limits=TUNED, benign=False, grayware=False)

        self.assertEqual(self._severities("PAN-AVW-005"), {"no-reports": "low"})

    def test_both_reports_on_matches_no_calibration_at_all(self):
        """`none` is where the assertion's boundary falls and it compiles to NO query: a query
        for it would report the most compliant configuration in the estate."""
        settings = self._settings("reporting-on", limits=TUNED, benign=True, grayware=True)

        self.assertEqual(settings.verdict_reporting_gap, "none")
        self.assertEqual(self._severities("PAN-AVW-005"), {})

    def test_the_session_half_AND_a_benign_gap_report_at_informational(self):
        """THE MEASURED UNDER-REPORT, asserted so it cannot change silently.

        `derive_control_query_severity_value` returns the control's default only while NO
        non-baseline query with an `adjusted_severity` has matched; the moment one does, the
        worst matched calibration wins and the baseline tier is DISCARDED. This appliance
        fails both halves - it withholds session context, which the baseline reports at the
        control's own `low`, and it is missing only harmless-file reporting, which calibrates
        to `informational` - so the finding comes out BELOW the tier the session half alone
        would have given it.

        That is a real under-report and it is recorded rather than worked around: the fix is a
        decision about whether these two halves belong in one control, which is stage 3's and
        not this layer's. Filed in the stage 8 av-wildfire artifact's `needs_human`.
        """
        self._settings("both-halves", limits=TUNED, excluded=["exclude-username"],
                       benign=False, grayware=True)

        self.assertEqual(self._severities("PAN-AVW-005"), {"both-halves": "informational"})

    def test_a_row_nobody_normalized_passes_the_session_half_in_silence(self):
        """THE COVERAGE STATEMENT THIS CONTROL CARRIES FORWARD RATHER THAN MAKING.

        `shares_full_session_info` is `BooleanField(default=True)` and `true` is the COMPLIANT
        side, so a row the normalizer never wrote - one from before the column existed, or an
        appliance nothing has collected - passes the baseline clause with nothing to say so.
        There is no is-null operator to ask with. `session_info_read` is the column that
        answers it and this run registered it as a searchable field, but stage 5 declared the
        decision NOT to report it and that decision is carried forward deliberately.

        So this test asserts the SILENCE, not a finding. It is the shape a coverage control
        over this subject would take if one is ever commissioned, and it exists so the silence
        is a recorded fact rather than an untested assumption.
        """
        settings = self._settings("never-read", limits=TUNED)
        settings.session_info_read = False
        settings.shares_full_session_info = True
        settings.save(update_fields=["session_info_read", "shares_full_session_info"])

        self.assertEqual(self._severities("PAN-AVW-005"), {})
