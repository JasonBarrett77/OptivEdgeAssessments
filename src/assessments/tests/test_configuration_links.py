""""View query results" must open the page that can ANSWER the query.

It was hard-coded to the security rules page for every control on the control detail page, so a
certificate, NTP or password-complexity query opened a builder that then refused it: "This query
targets integrations.NtpSettings and cannot be applied to security rules." The query was fine;
the link was wrong, and the page said it in a way that blamed the query.

The destination follows the query's own model. Where one model has two pages - anti-spyware and
vulnerability protection over SecurityProfile, because PAN-OS lists them separately - the page is
the one whose `scope` the query already carries, and a query naming neither gets no link at all
rather than a plausible wrong one.
"""

from __future__ import annotations

from django.test import TestCase
from django.urls import reverse

from assessments import configuration_navigation as config_nav
from assessments.configuration_results import (
    RESULTS,
    object_for_canonical_query,
    query_results_url,
)
from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import Control
from assessments.tests._seed import seed_control, seed_specs


def _seeded_controls():
    return [c for cat in load_seed_payload()["catalogs"] for c in cat["controls"]]


class QueryDestinationTests(TestCase):
    def test_every_query_in_the_shipped_catalog_has_somewhere_to_go(self):
        """The whole point. A control whose link goes nowhere is one an assessor cannot check."""
        homeless = [
            f'{control["control_id"]} / {query["name"]}'
            for control in _seeded_controls()
            for query in control["queries"]
            if not query_results_url(query["canonical_query"])
        ]
        self.assertEqual(homeless, [], f"queries with no results page: {homeless}")

    def test_the_destination_queries_the_same_model_as_the_query(self):
        """A link that resolves is not enough - it has to resolve to a page over the right
        object, which is the failure this replaced."""
        for control in _seeded_controls():
            for query in control["queries"]:
                model = query["canonical_query"]["model"]
                obj = object_for_canonical_query(query["canonical_query"])
                with self.subTest(control=control["control_id"], query=query["name"]):
                    if obj is None:
                        # Only an object with no rail item yet may fall through, and only to the
                        # page that presents it in the meantime.
                        from assessments.configuration_results import LEGACY_SURFACE
                        self.assertIn(model, LEGACY_SURFACE)
                    else:
                        self.assertEqual(obj.search_model, model)

    def test_the_two_security_profile_pages_each_take_their_own_control(self):
        """One model, two rail items, split by `kind` - the case that makes this a rule rather
        than a lookup. Sent to the wrong one the page returns nothing, because the scope filters
        the rows before the query does, and empty reads as "no profile is like this"."""
        by_id = {c["control_id"]: c for c in _seeded_controls()}
        for control_id, expected_slug in (("PAN-SPY-001", "anti-spyware"),
                                          ("PAN-VLN-001", "vulnerability-protection")):
            query = by_id[control_id]["queries"][0]["canonical_query"]
            self.assertEqual(object_for_canonical_query(query).slug, expected_slug, control_id)

    def test_an_ambiguous_query_gets_no_link_rather_than_a_plausible_one(self):
        shared = {"model": "integrations.SecurityProfile", "operator": "and",
                  "clauses": [{"field": "name", "op": "contains", "value": "x"}]}
        self.assertIsNone(object_for_canonical_query(shared))
        self.assertEqual(query_results_url(shared), "")

    def test_a_model_no_page_presents_gets_no_link(self):
        self.assertEqual(query_results_url(
            {"model": "integrations.Zone", "operator": "and", "clauses": []}), "")

    def test_security_rule_queries_reach_the_rules_page_until_policies_lands(self):
        """The one documented fallback. It goes away with `Policies > Security`."""
        query = {"model": "integrations.SecurityRule", "operator": "and",
                 "clauses": [{"field": "action", "op": "eq", "value": "allow"}]}
        self.assertEqual(query_results_url(query, control_query_pk=7),
                         f"{reverse('assessment_security_rule_list')}?control_query=7")

    def test_a_scoped_page_is_only_chosen_when_the_scope_matches_exactly(self):
        """`negated` is part of a clause's identity: "kind is spyware" and "kind is NOT spyware"
        must not resolve to the same page."""
        negated = {"model": "integrations.SecurityProfile", "operator": "and",
                   "clauses": [{"field": "kind", "op": "eq", "value": "spyware", "negated": True}]}
        self.assertIsNone(object_for_canonical_query(negated))

    def test_every_rail_item_with_a_model_can_be_reached_by_a_query_over_it(self):
        """The reverse direction: a page nothing routes to is a page nobody arrives at."""
        for obj in config_nav.CONFIG_OBJECTS:
            if not obj.search_model:
                continue
            scope = RESULTS[obj.slug].scope
            query = {"model": obj.search_model, "operator": "and",
                     "clauses": list(scope["clauses"]) if scope else
                     [{"field": "name", "op": "contains", "value": ""}]}
            with self.subTest(obj.slug):
                self.assertEqual(object_for_canonical_query(query).slug, obj.slug)


class ControlDetailLinkTests(TestCase):
    """The page the defect was seen on."""

    def _control(self, control_id):
        return seed_control(seed_specs()[control_id])

    def test_a_non_rule_control_links_to_its_own_object_page(self):
        control = self._control("PAN-SVC-010")
        html = self.client.get(f"/assessments/controls/{control.pk}/").content.decode()
        expected = reverse("assessment_configuration_object", args=["device", "system-identity"])
        query = control.queries.get()
        self.assertIn(f'href="{expected}?control_query={query.pk}"', html)
        self.assertNotIn("/assessments/security-rules/?control_query=", html)

    def test_a_rule_control_still_links_to_the_rules_page(self):
        control = self._control("PAN-POL-004")
        html = self.client.get(f"/assessments/controls/{control.pk}/").content.decode()
        query = control.queries.get()
        self.assertIn(f'href="/assessments/security-rules/?control_query={query.pk}"', html)

    def test_the_control_level_button_goes_to_the_controls_own_object(self):
        """It applies the WHOLE control - the union of its queries at worst-wins severity - which
        every object page can now do, not the rules page alone."""
        rule_control = self._control("PAN-POL-004")
        html = self.client.get(f"/assessments/controls/{rule_control.pk}/").content.decode()
        self.assertIn(f"/assessments/security-rules/?control={rule_control.pk}", html)

        other = self._control("PAN-SVC-010")
        html = self.client.get(f"/assessments/controls/{other.pk}/").content.decode()
        expected = reverse("assessment_configuration_object", args=["device", "system-identity"])
        self.assertIn(f'href="{expected}?control={other.pk}"', html)

    def test_a_control_that_declares_no_target_offers_no_preview(self):
        """It generates no findings - findings are made per control TYPE - so "what would this
        report" has no answer. Keyed on the declared target, not on the query's model, which is
        the one place those two must not be treated as the same thing."""
        control = self._control("PAN-SVC-010")
        control.control_type = Control.ControlType.CONFIG
        control.save()
        html = self.client.get(f"/assessments/controls/{control.pk}/").content.decode()
        self.assertNotIn(f"?control={control.pk}", html)
        # The per-query link still works: a query is previewable wherever it can run.
        self.assertIn(f"?control_query={control.queries.get().pk}", html)

    def test_a_query_with_no_destination_renders_a_disabled_marker_not_a_gap(self):
        control = self._control("PAN-SVC-010")
        control.queries.update(canonical_query={
            "model": "integrations.Zone", "operator": "and",
            "clauses": [{"field": "name", "op": "eq", "value": "trust"}]})
        html = self.client.get(f"/assessments/controls/{control.pk}/").content.decode()
        self.assertIn("No query view for this object yet", html)
