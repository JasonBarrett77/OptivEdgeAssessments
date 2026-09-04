"""Graded severity from the corpus scales.

Thirty controls reported `default_severity` for every finding, so a 4-character password and
an 11-character one arrived identical. Twenty-five corpus controls carry bands; four were
already built when this was added.

The three things worth pinning are the three that are easy to get backwards: sentinels beat
bands, `direction` selects the band KEY rather than describing the semantics, and a band can
never report worse than the control itself.
"""

from __future__ import annotations

from django.test import TestCase

from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import Control

FAILED_ATTEMPTS = {
    "kind": "numeric", "direction": "lower-is-worse",
    "bands": [{"max": 5, "severity": None}, {"max": 10, "severity": "medium"},
              {"max": None, "severity": "high"}],
    "sentinels": [{"value": "0", "severity": "high"}],
}
IDLE_TIMEOUT = {
    "kind": "numeric", "direction": "higher-is-worse",
    "bands": [{"min": 61, "severity": "high"}, {"min": 11, "severity": "medium"},
              {"min": 1, "severity": None}],
    "sentinels": [{"value": "0", "severity": "high"}],
}
TLS = {
    "kind": "ranked",
    "ranks": [{"value": "tls1-0", "severity": "high"}, {"value": "tls1-1", "severity": "high"},
              {"value": "tls1-2", "severity": None}, {"value": "tls1-3", "severity": None}],
}


def _control(scale, severity="high", control_id="X-1"):
    return Control(control_id=control_id, name="c", description="d",
                   control_type=Control.ControlType.DEVICE_CONFIGURATION,
                   default_severity=severity, severity_scale=scale)


class SeverityForMeasureTests(TestCase):
    def test_a_control_with_no_scale_never_grades(self):
        self.assertIsNone(_control({}).severity_for_measure(3))

    def test_max_keyed_bands_are_walked_best_first(self):
        control = _control(FAILED_ATTEMPTS)
        self.assertIsNone(control.severity_for_measure(3))       # 1-5 meets baseline
        self.assertEqual(control.severity_for_measure(5), None)
        self.assertEqual(control.severity_for_measure(6), "medium")
        self.assertEqual(control.severity_for_measure(10), "medium")
        self.assertEqual(control.severity_for_measure(11), "high")
        self.assertEqual(control.severity_for_measure(9999), "high")

    def test_min_keyed_bands_are_walked_worst_first(self):
        control = _control(IDLE_TIMEOUT)
        self.assertIsNone(control.severity_for_measure(10))
        self.assertEqual(control.severity_for_measure(11), "medium")
        self.assertEqual(control.severity_for_measure(60), "medium")
        self.assertEqual(control.severity_for_measure(61), "high")

    def test_a_sentinel_beats_the_bands_it_would_otherwise_win(self):
        """The reason sentinels exist. PAN-OS overloads 0, and on both scales the band lookup
        would rank it as the BEST possible value - fewest failed attempts, shortest idle
        timeout - when it actually means the protection is switched off."""
        self.assertIsNone(_control(FAILED_ATTEMPTS).severity_scale["bands"][0]["severity"])
        self.assertEqual(_control(FAILED_ATTEMPTS).severity_for_measure(0), "high")
        self.assertEqual(_control(IDLE_TIMEOUT).severity_for_measure(0), "high")

    def test_a_band_never_reports_worse_than_the_control(self):
        """The corpus promises the headline severity is safe to report unmeasured."""
        control = _control(FAILED_ATTEMPTS, severity="low")
        self.assertEqual(control.severity_for_measure(0), "low")
        self.assertEqual(control.severity_for_measure(99), "low")

    def test_a_band_may_report_better_than_the_control(self):
        control = _control(FAILED_ATTEMPTS, severity="critical")
        self.assertEqual(control.severity_for_measure(7), "medium")

    def test_ranked_scales_match_on_the_value(self):
        control = _control(TLS)
        self.assertEqual(control.severity_for_measure("tls1-0"), "high")
        self.assertIsNone(control.severity_for_measure("tls1-2"))
        self.assertIsNone(control.severity_for_measure("tls1-9"))

    def test_unparseable_and_missing_measures_fall_back(self):
        control = _control(IDLE_TIMEOUT)
        self.assertIsNone(control.severity_for_measure(None))
        self.assertIsNone(control.severity_for_measure("not a number"))


class SeededScaleTests(TestCase):
    def test_the_seed_carries_every_scale_the_corpus_has_for_a_built_control(self):
        """Four controls shipped before grading existed and were backfilled; three more
        arrived with theirs. PAN-AUTH-015 has none in the corpus, which is right - its finding
        range is a 14-minute window with nothing to grade inside it."""
        controls = {c["control_id"]: c
                    for cat in load_seed_payload()["catalogs"] for c in cat["controls"]}
        scaled = {cid for cid, c in controls.items() if c.get("severity_scale")}
        self.assertEqual(
            scaled, {"PAN-AUTH-002", "PAN-AUTH-009", "PAN-AUTH-010", "PAN-CRT-005",
                     "PAN-AUTH-014", "PAN-AUTH-016", "PAN-AUTH-017"},
            "a built control gained or lost a scale - update this list deliberately")

    def test_every_seeded_scale_is_shaped_the_way_the_grader_reads_it(self):
        controls = {c["control_id"]: c
                    for cat in load_seed_payload()["catalogs"] for c in cat["controls"]}
        for control_id, payload in controls.items():
            scale = payload.get("severity_scale")
            if not scale:
                continue
            with self.subTest(control_id):
                kind = scale.get("kind")
                self.assertIn(kind, {"numeric", "ranked"})
                if kind == "ranked":
                    self.assertTrue(scale.get("ranks"))
                    continue
                key = "min" if scale.get("direction") == "higher-is-worse" else "max"
                bands = scale.get("bands") or []
                self.assertTrue(bands)
                # Every band must carry the key its direction selects, or it is unreachable.
                for band in bands:
                    self.assertIn(key, band,
                                  f"{control_id} band {band} lacks {key!r}, so the grader "
                                  f"would fall through it")
