"""The configuration explorer's query pages: build a query, read what matches.

A different surface from the findings tabs. Those answer "what did the controls find"; these
answer "which objects look like this", which is also how a control's query gets tried out
before it is a control.
"""

from __future__ import annotations

import json
import re

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from assessments import configuration_navigation as config_nav
from assessments import configuration_results as config_results
from assessments.models import ConfigurationSearchState
from assessments.search.exceptions import SearchSyntaxError
from assessments.search.registry import MODEL_REGISTRY
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, InterfaceManagementProfile, ManagementStation, Snapshot)

MODEL = "integrations.InterfaceManagementProfile"


def make_profile(station, group, hostname, name, bound):
    """The model is appliance-scoped and carries its station, group and source snapshot. Every
    one of those is NOT NULL, so a two-field create fails at the database rather than in a way
    that says what is missing."""
    appliance, _ = Appliance.objects.get_or_create(
        management_station=station, serial_number=f"S-{hostname}",
        defaults={"hostname": hostname, "appliance_group": group})
    snapshot = Snapshot.objects.create(
        management_station=station, appliance=appliance,
        source_type="show_merged_config", collected_at=timezone.now(), payload={})
    return InterfaceManagementProfile.objects.create(
        management_station=station, appliance=appliance, appliance_group=group,
        source_snapshot=snapshot, name=name,
        bound_interface_names=[f"ethernet1/{i + 1}" for i in range(bound)],
        bound_interface_count=bound)


class InterfaceManagementProfileQueryTests(TestCase):
    """The first object wired to the frame, and the smallest: four searchable fields."""

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.q")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-q",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        for hostname, name, bound in (("fw-a", "bound", 2), ("fw-a", "orphan", 0),
                                      ("fw-b", "orphan", 1)):
            make_profile(self.station, self.group, hostname, name, bound)
        self.url = reverse("assessment_configuration_object", args=["network", "interface-mgmt"])

    def _names(self, response):
        body = re.search(r"<tbody>(.*?)</tbody>", response.content.decode(), re.S)
        if body is None:
            return []
        return [re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)[1].strip()
                for row in re.findall(r"<tr>(.*?)</tr>", body.group(1), re.S)]

    def _apply(self, node):
        response = self.client.post(self.url, {"search": json.dumps(node)})
        self.assertEqual(response.status_code, 302, response.content[:400])
        return self.client.get(response.headers["Location"])

    def _clause(self, field, op, value, negated=False):
        return {"model": MODEL, "operator": "and",
                "clauses": [{"field": field, "op": op, "value": value, "negated": negated}]}

    def test_the_unqueried_page_lists_everything(self):
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self._names(response)), 3)

    def test_a_query_filters_the_rows(self):
        self.assertEqual(self._names(self._apply(
            self._clause("binding_count", "eq", 0))), ["orphan"])

    def test_a_negated_clause_inverts_it(self):
        self.assertEqual(sorted(self._names(self._apply(
            self._clause("binding_count", "eq", 0, negated=True)))), ["bound", "orphan"])

    def test_a_group_combines_clauses(self):
        node = {"model": MODEL, "operator": "or", "clauses": [
            {"field": "hostname", "op": "eq", "value": "fw-b", "negated": False},
            {"field": "binding_count", "op": "gt", "value": 1, "negated": False}]}
        self.assertEqual(sorted(self._names(self._apply(node))), ["bound", "orphan"])

    def test_a_nested_group_carries_the_model_only_at_the_root(self):
        """The validator rejects a group with any key but `operator` and `clauses`, so a builder
        that stamped the model on every group could not submit a nested query at all - which is
        what the first one did. Caught by running the builder headlessly, not by a page test."""
        node = {"model": MODEL, "operator": "and", "clauses": [
            {"field": "binding_count", "op": "gte", "value": 0, "negated": False},
            {"operator": "or", "clauses": [
                {"field": "hostname", "op": "eq", "value": "fw-b", "negated": False},
                {"field": "binding_count", "op": "gt", "value": 1, "negated": False}]}]}
        self.assertEqual(sorted(self._names(self._apply(node))), ["bound", "orphan"])

        node["clauses"][1]["model"] = MODEL
        response = self.client.post(self.url, {"search": json.dumps(node)})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "must only contain")

    def test_the_query_survives_in_the_url_not_the_session(self):
        """The token is the point: a built query has to be reloadable, bookmarkable and
        pasteable to someone else. A POST that rendered its own results would be none of those."""
        response = self.client.post(self.url, {"search": json.dumps(
            self._clause("binding_count", "eq", 0))})
        token = ConfigurationSearchState.objects.get().token
        self.assertEqual(response.headers["Location"], f"{self.url}?search_state={token}")
        self.assertEqual(self._names(self.client.get(response.headers["Location"])), ["orphan"])

    def test_a_token_for_another_model_is_refused_by_name(self):
        """Not "0 results". A query built somewhere else compiles against fields this model does
        not have, and a page that answered a question it never asked would look like an answer."""
        state = ConfigurationSearchState.objects.create(
            model_label="integrations.SecurityRule", canonical_query={})
        response = self.client.get(f"{self.url}?search_state={state.token}")
        self.assertContains(response, "cannot be applied to")

    def test_an_unknown_token_says_so_and_still_renders(self):
        response = self.client.get(f"{self.url}?search_state=6f1c2e00-0000-4000-8000-000000000000")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "no longer available")

    def test_a_bad_value_returns_to_the_builder_with_the_reason(self):
        response = self.client.post(self.url, {"search": json.dumps(
            self._clause("binding_count", "eq", "zero"))})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "must be an integer")
        self.assertContains(response, "query-builder-root")

    def test_the_builder_offers_the_compilers_own_fields(self):
        """Rendered from FIELD_OPERATOR_REGISTRY, not typed into the template. The security
        rules builder keeps a second copy of both lists and they can drift apart."""
        response = self.client.get(f"{self.url}?edit_search=1")
        offered = json.loads(re.search(r'id="query-fields"[^>]*>(.*?)</script>',
                                       response.content.decode(), re.S).group(1))
        self.assertEqual(set(offered), set(MODEL_REGISTRY[MODEL]["field_operators"]))
        for field, ops in offered.items():
            self.assertEqual(set(ops), set(MODEL_REGISTRY[MODEL]["field_operators"][field]))


class ResultsSpecTests(TestCase):
    def test_every_row_is_as_wide_as_its_columns(self):
        """The findings tabs have `test_device_tab_tables_are_square` for exactly this. A row
        one cell short shifts every column after it and nothing raises."""
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.r")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-r", group_type=ApplianceGroup.TYPE_STANDALONE)
        make_profile(station, group, "fw-r", "p", 0)
        for label, spec in config_results.RESULTS.items():
            for item in spec.base_queryset():
                self.assertEqual(len(spec.row(item)), len(spec.columns), label)

    def test_every_spec_is_keyed_on_the_model_it_queries(self):
        """The dict key picks the compiler and the spec supplies the rows. Keyed wrongly, a page
        would filter one model and list another - and every row would still be square."""
        by_slug = {o.slug: o for o in config_nav.CONFIG_OBJECTS}
        for slug, spec in config_results.RESULTS.items():
            label = by_slug[slug].search_model
            self.assertIs(spec.base_queryset().model, MODEL_REGISTRY[label]["model_class"], slug)
            self.assertTrue(spec.columns, slug)

    def test_every_wired_page_renders_and_names_its_object_when_empty(self):
        """With no rows there is no table to check, so this checks what IS on the page: that it
        renders at all, and that the empty state names the object rather than saying nothing."""
        for obj in config_nav.CONFIG_OBJECTS:
            if not obj.search_model:
                continue
            url = reverse("assessment_configuration_object",
                          args=[config_nav.category_slug(obj.category), obj.slug])
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, obj.slug)
            self.assertContains(response, obj.label)

    def test_a_query_the_builder_could_emit_applies_on_every_wired_object(self):
        """Every one of these models is searchable by `hostname`, so one query shape exercises
        all ten compilers through the view - which is what the builder actually posts."""
        for obj in config_nav.CONFIG_OBJECTS:
            if not obj.search_model:
                continue
            self.assertIn("hostname", MODEL_REGISTRY[obj.search_model]["field_operators"],
                          obj.slug)
            url = reverse("assessment_configuration_object",
                          args=[config_nav.category_slug(obj.category), obj.slug])
            response = self.client.post(url, {"search": json.dumps({
                "model": obj.search_model, "operator": "and", "clauses": [
                    {"field": "hostname", "op": "contains", "value": "fw",
                     "negated": False}]})})
            self.assertEqual(response.status_code, 302, f"{obj.slug}: {response.content[:300]}")

    def test_no_field_is_offered_by_two_pages(self):
        """`fields` slices a SHARED model between pages, so a field in two slices is offered
        twice and means different things on each.

        This used to also assert that every searchable field is offered SOMEWHERE. That stopped
        being true on 2026-09-10: five clusters left `DeviceConfigurationProfile` for models of
        their own, the Management page went with them, and what remains on the aggregate -
        permitted-IP count, NTP, HA, hostname, time zone - is read by no completed control and
        so appears on no page. Demanding coverage would demand a page for objects the rule says
        should not have one.
        """
        offered = {}
        for slug, spec in config_results.RESULTS.items():
            for field in spec.fields:
                if field in ("hostname", "serial_number"):
                    continue
                offered.setdefault(field, []).append(slug)
        duplicated = {f: pages for f, pages in offered.items() if len(pages) > 1}
        self.assertEqual(duplicated, {}, f"offered by more than one page: {duplicated}")

    def test_every_object_with_a_search_model_has_a_results_spec(self):
        """Navigation gates the query view on `search_model`. A label with no spec behind it
        renders a table with no columns, which reads as "nothing matched", not "not built"."""
        for obj in config_nav.CONFIG_OBJECTS:
            if obj.search_model:
                self.assertIn(obj.slug, config_results.RESULTS, obj.slug)
                self.assertIn(obj.search_model, MODEL_REGISTRY, obj.slug)


class AdvertisedOperatorTests(TestCase):
    def test_every_compiler_can_serve_the_is_empty_it_advertises(self):
        """`is_empty` is the one text operator whose valid value is the EMPTY string, so a
        compiler that only checks for a non-empty one advertises it and can never serve it.

        Two did - `management_interface` and `interface_management_profile`, both of which took
        the operator set from `scalar_text` without taking its behaviour. Invisible until the
        query builder started rendering the registry, because nothing had ever offered those
        operators to a person.
        """
        refused = []
        for label, entry in MODEL_REGISTRY.items():
            for field, ops in entry["field_operators"].items():
                if "is_empty" not in ops:
                    continue
                try:
                    entry["compiler"]({"field": field, "op": "is_empty", "value": "",
                                       "negated": False, "case_sensitive": False})
                except SearchSyntaxError as exc:
                    refused.append(f"{label}.{field}: {exc}")
        self.assertEqual(refused, [])


class ManagementTlsJoinTests(TestCase):
    """The binding reads its floor THROUGH the profile row, and one operator has to know it.

    `min_version is_empty` must match a binding with NO row, or PAN-MGT-010's fourth clause - a
    profile is bound and its floor is empty - stops reporting dangling bindings, the case it was
    written for. A plain lookup does not match a null join, and nothing would fail loudly.
    """

    def setUp(self):
        from optivedge_integrations.integrations.models import (
            ManagementTlsBinding, SslTlsServiceProfile)
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.join")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-join", group_type=ApplianceGroup.TYPE_STANDALONE)

        def binding(hostname, name, profile_min=None):
            appliance = Appliance.objects.create(
                management_station=station, appliance_group=group,
                serial_number=f"S-{hostname}", hostname=hostname)
            snapshot = Snapshot.objects.create(
                management_station=station, appliance=appliance,
                source_type="show_merged_config", collected_at=timezone.now(), payload={})
            common = {"management_station": station, "appliance": appliance,
                      "source_snapshot": snapshot}
            row = None
            if profile_min is not None:
                row = SslTlsServiceProfile.objects.create(
                    name=name, scope="shared", min_version=profile_min, **common)
            return ManagementTlsBinding.objects.create(
                profile_name=name,
                profile_scope="shared" if row else ("unresolved" if name else ""),
                ssl_tls_service_profile=row, **common)

        self.Binding = ManagementTlsBinding
        binding("fw-good", "hard", "tls1-2")
        binding("fw-silent", "bare", "")
        binding("fw-dangling", "missing")
        binding("fw-unbound", "")

    def _match(self, node):
        from assessments.search.compiler import apply_search_node
        rows = apply_search_node(self.Binding.objects.all(),
                                 {"model": "integrations.ManagementTlsBinding", **node})
        return sorted(rows.values_list("appliance__hostname", flat=True))

    def test_is_empty_on_a_joined_field_includes_the_missing_row(self):
        self.assertEqual(
            self._match({"operator": "and", "clauses": [
                {"field": "min_version", "op": "is_empty", "value": ""}]}),
            ["fw-dangling", "fw-silent", "fw-unbound"])

    def test_pan_mgt_010s_fourth_clause_catches_the_dangling_binding(self):
        """Bound, and no floor to read - silent profile and dangling name alike."""
        self.assertEqual(
            self._match({"operator": "and", "clauses": [
                {"field": "profile_name", "op": "is_empty", "value": "", "negated": True},
                {"field": "min_version", "op": "is_empty", "value": ""}]}),
            ["fw-dangling", "fw-silent"])

    def test_eq_on_a_joined_field_never_matches_a_missing_row(self):
        self.assertEqual(
            self._match({"operator": "and", "clauses": [
                {"field": "min_version", "op": "eq", "value": "tls1-2"}]}),
            ["fw-good"])
