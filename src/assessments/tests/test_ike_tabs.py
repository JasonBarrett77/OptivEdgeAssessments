"""The two IKE tabs as a customer reads them: what the columns are called, and which cell is marked.

WHY THIS FILE EXISTS. The stage 9 run of the `ike-crypto` domain built both tabs and read every
row, and the three things it could not settle were all report content: what the setting columns are
headed, whether `gateway_is_active` belongs among them, and which cell carries the value-at-fault
fill. Nothing in this repo held any of the three, so each was a judgment that the next change
could undo in silence.

THE ROW THIS FILE IS REALLY ABOUT is PAN-IKE-008 on `oep-ike6-g03`. It used to color five cells,
one of them `ike_version = ikev2` - which the baseline clause EXCLUDES and the matched query
REQUIRES, so the row named as the fault the single setting that gateway had right. It now colors
one. That is the behavior `ControlQuery.asserted_fields` exists for and this is the only test of
it on a real row.
"""
from __future__ import annotations

from assessments.artifacts.domains import DOMAINS
from assessments.artifacts.sheets.findings import build_findings_table
from assessments.tests.test_ike_crypto_controls import IkeControlTestCase


def _table(slug):
    return build_findings_table(next(d.spec for d in DOMAINS if d.slug == slug))


def _headers(table):
    return [c[0] if isinstance(c, (list, tuple)) else str(c) for c in table.columns]


class TheMarkedCellIsTheOneAtFault(IkeControlTestCase):
    """One row, pinned by name, because this is the defect's own instance."""

    def test_gw03_marks_only_the_liveness_probe(self):
        self.whole_lab()
        table = _table("ike-gateways")
        headers = _headers(table)
        rows = [(i, r) for i, r in enumerate(table.rows)
                if r[1] == "PAN-IKE-008" and "oep-ike6-g03" in map(str, r)]
        self.assertEqual(1, len(rows), "expected exactly one PAN-IKE-008 row for oep-ike6-g03")
        index, row = rows[0]
        self.assertEqual(["IKEv2 idle liveness probe switched off"],
                         row[headers.index("Matched queries")].split("\n"))
        marked = sorted(headers[col] for (r, col) in table.implicated if r == index)
        self.assertEqual(["IKEv2 liveness check"], marked,
                         "the fault is the idle probe being off, and nothing else on this row is")
        # The four it no longer marks, named so a regression says which one came back.
        for heading in ("IKE version configured", "IKEv1 DPD set?", "IKEv1 DPD enabled",
                        "IKEv2 idle probe set?"):
            self.assertNotIn(heading, marked)

    def test_the_applicability_clause_is_never_marked_anywhere_in_the_domain(self):
        """`gateway_is_active` is the clause EVERY control here carries and none of them asserts.
        Marked, it reads Active with the value-at-fault fill on every row of the tab."""
        self.whole_lab()
        table = _table("ike-gateways")
        headers = _headers(table)
        marked = {headers[col] for (_r, col) in table.implicated}
        self.assertNotIn("Gateway state", marked)
        self.assertTrue(marked, "nothing was marked at all, so this proves nothing")


class NoCustomerReadsAFieldName(IkeControlTestCase):
    """`setting_columns` is derived, so its headings were the raw snake_case field names - 23 of
    31 tabs still carry at least one. These two do not."""

    def test_neither_tab_heads_a_column_with_a_field_name(self):
        self.whole_lab()
        for slug in ("ike-gateways", "ike-crypto-profiles"):
            for heading in _headers(_table(slug)):
                self.assertNotIn("_", heading, f"{slug} heads a column `{heading}`")


class AProseColumnThatNamesItsFieldSuppressesTheRawOne(IkeControlTestCase):
    """Three columns name a field that `tested_fields` also derives. Naming it is what keeps the
    tab from carrying two columns for one setting - and what makes the readable one markable.

    THIS BECAME POSSIBLE ON 2026-10-28 and was impossible before: `tested_fields` read the
    baseline query alone, so no column derived for a field only a non-baseline query asserts, and
    these prose columns existed to compensate. The union over active queries landed that day.
    """

    def test_the_three_named_fields_appear_once_each(self):
        self.whole_lab()
        for slug, pairs in (
            ("ike-gateways", (("IKEv2 liveness check", "IKEv2 idle probe enabled"),
                              ("Gateway state", "Gateway state"))),
            ("ike-crypto-profiles", (("IKEv2 re-authentication",
                                      "IKEv2 re-authentication bounded"),)),
        ):
            headers = _headers(_table(slug))
            for prose, derived_label in pairs:
                self.assertIn(prose, headers)
                self.assertEqual(1, headers.count(prose))
                if derived_label != prose:
                    self.assertNotIn(derived_label, headers,
                                     f"{slug} carries both {prose} and {derived_label}")
