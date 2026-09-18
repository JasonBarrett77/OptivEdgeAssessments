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
from assessments.models import ConfigurationSearchState, Control, ControlQuery
from assessments.search.exceptions import SearchSyntaxError
from assessments.search.registry import MODEL_REGISTRY
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementPoint, InterfaceManagementProfile, ManagementStation,
    SecurityRule, SecurityRuleApplication, SecurityRuleFromZone, SecurityRuleService,
    SecurityRuleSourceAddressRef, SecurityRuleToZone, Snapshot)

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
        """Every compiler, through the view, the way the builder actually posts.

        It used to send `hostname contains fw` to all of them, on the observation that every
        wired model had that field. Security rules do not: a rule is scoped by vsys, and its
        appliance is a column on the enforcement point rather than on the rule. So the clause is
        built from what each model OFFERS - the first `contains` field its own registry lists -
        which is also closer to what the builder does, since the builder renders that registry.
        """
        for obj in config_nav.CONFIG_OBJECTS:
            if not obj.search_model:
                continue
            operators = MODEL_REGISTRY[obj.search_model]["field_operators"]
            field = next((name for name in sorted(operators) if "contains" in operators[name]),
                         None)
            self.assertIsNotNone(field, f"{obj.slug} offers no `contains` field to query")
            url = reverse("assessment_configuration_object",
                          args=[config_nav.category_slug(obj.category), obj.slug])
            response = self.client.post(url, {"search": json.dumps({
                "model": obj.search_model, "operator": "and", "clauses": [
                    {"field": field, "op": "contains", "value": "fw",
                     "negated": False}]})})
            self.assertEqual(response.status_code, 302,
                             f"{obj.slug} / {field}: {response.content[:300]}")

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


class ControlPreviewTests(TestCase):
    """Applying a whole CONTROL to an object page: what it would report, and at what severity.

    The page answered "which objects look like this" and stopped there, which is half of what it
    is for. A finding is the union of a control's active queries at the severity the worst
    matching one sets, so a single-query preview cannot show it - a control graded by a
    calibration query previews at the wrong severity, or at none - and the only page that could
    apply a whole control was the security rules one.

    Evaluated through `evaluate_queryset_control_queries`, the same function finding generation
    uses. A second implementation of worst-wins here would be a second thing to be wrong.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.preview")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-preview",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        for hostname, name, bound in (("fw-a", "orphan", 0), ("fw-a", "lonely", 1),
                                      ("fw-a", "busy", 4)):
            make_profile(self.station, self.group, hostname, name, bound)
        self.url = reverse("assessment_configuration_object", args=["network", "interface-mgmt"])
        self.control = Control.objects.create(
            control_id="PAN-TEST-001", name="Profiles should be bound",
            control_type=Control.ControlType.INTERFACE_MANAGEMENT_PROFILE,
            description="Prototype.", default_severity=Control.Severity.MEDIUM)
        ControlQuery.objects.create(
            control=self.control, name="Baseline", is_baseline=True, is_active=True,
            canonical_query={"model": MODEL, "operator": "and", "clauses": [
                {"field": "binding_count", "op": "lt", "value": 2}]})

    def _preview(self, control=None):
        return self.client.get(f"{self.url}?control={(control or self.control).pk}")

    def _body_rows(self, response):
        body = re.search(r"<tbody>(.*?)</tbody>", response.content.decode(), re.S)
        return [re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
                for row in re.findall(r"<tr>(.*?)</tr>", body.group(1), re.S)] if body else []

    def test_it_shows_the_rows_the_control_would_report_and_no_others(self):
        rows = self._body_rows(self._preview())
        self.assertEqual({cells[1].strip() for cells in rows}, {"orphan", "lonely"})

    def test_the_table_stays_square_when_the_preview_adds_columns(self):
        """The body grows two cells; the header has to grow the same two. A table that gains a
        column in one of them shifts every value after it, silently."""
        response = self._preview()
        html = response.content.decode()
        headers = re.findall(r"<th[^>]*>(.*?)</th>", re.search(r"<thead>(.*?)</thead>", html, re.S).group(1), re.S)
        self.assertEqual(headers[-2:], ["Severity", "Matched query"])
        for cells in self._body_rows(response):
            self.assertEqual(len(cells), len(headers))

    def test_the_worst_matching_query_sets_the_severity(self):
        """The whole reason a control preview is not a query preview."""
        ControlQuery.objects.create(
            control=self.control, name="Unbound entirely", is_baseline=False, is_active=True,
            adjusted_severity=Control.Severity.CRITICAL,
            canonical_query={"model": MODEL, "operator": "and", "clauses": [
                {"field": "binding_count", "op": "eq", "value": 0}]})
        by_name = {cells[1].strip(): cells for cells in self._body_rows(self._preview())}
        self.assertEqual(by_name["orphan"][-2].strip(), "Critical")
        self.assertEqual(by_name["lonely"][-2].strip(), "Medium")
        self.assertIn("Unbound entirely", by_name["orphan"][-1])
        self.assertIn("Baseline", by_name["lonely"][-1])

    def test_it_names_the_control_rather_than_describing_a_query(self):
        html = self._preview().content.decode()
        self.assertIn("PAN-TEST-001", html)
        self.assertIn("what this control would report here", html)

    def test_a_control_for_another_object_is_refused_rather_than_answered_emptily(self):
        """Applied to the wrong page it would match nothing, and "nothing" reads as the control
        finding no problem - the most misleading answer available."""
        other = Control.objects.create(
            control_id="PAN-TEST-002", name="Elsewhere",
            control_type=Control.ControlType.NTP_SETTINGS,
            description="Prototype.", default_severity=Control.Severity.LOW)
        html = self._preview(other).content.decode()
        self.assertIn("cannot be applied to", html)
        self.assertIn("PAN-TEST-002", html)

    def test_a_control_with_no_declared_target_says_so(self):
        self.control.control_type = Control.ControlType.CONFIG
        self.control.save()
        self.assertIn("declares no assessment target", self._preview().content.decode())

    def test_queries_that_could_not_be_applied_are_counted_out_loud(self):
        """Silence here would under-report and look like a clean result.

        Written with `update()` because `ControlQuery.clean()` refuses a wrong-model query at
        creation - which is right, and is also why this state only ever arrives as STORED DRIFT:
        a control whose type was changed after its queries were written, or a seed that moved.
        `apply_controls_catalog` exists for the same class of staleness. The evaluator skips
        such a query silently, so the page has to not.
        """
        stale = ControlQuery.objects.create(
            control=self.control, name="Stale", is_baseline=False, is_active=True,
            adjusted_severity=Control.Severity.HIGH,
            canonical_query={"model": MODEL, "operator": "and", "clauses": [
                {"field": "binding_count", "op": "eq", "value": 0}]})
        ControlQuery.objects.filter(pk=stale.pk).update(
            canonical_query={"model": "integrations.NtpSettings", "operator": "and", "clauses": [
                {"field": "server_count", "op": "eq", "value": 0}]})
        html = self._preview().content.decode()
        self.assertIn("could not be applied", html)
        self.assertIn("1 of 2 active queries", html)

    def test_a_control_that_reports_nothing_says_which_control_and_over_how_many_rows(self):
        self.control.queries.update(canonical_query={
            "model": MODEL, "operator": "and",
            "clauses": [{"field": "name", "op": "eq", "value": "no-such-profile"}]})
        html = self._preview().content.decode()
        self.assertIn("PAN-TEST-001 reports nothing against 3", html)


class SecurityRulePageTests(TestCase):
    """Policies > Security - the last empty category filled, 2026-09-18.

    Rules are the first object here whose row count is a different order of magnitude: the lab
    holds 878 of them against a few dozen of anything else, which is why the page pages.
    """

    URL_ARGS = ["policies", "security"]

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.rules")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-rules",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.point = EnforcementPoint.objects.create(
            management_station=self.station, appliance_group=self.group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        self.snapshot = Snapshot.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_type="test", collected_at=timezone.now())
        self.url = reverse("assessment_configuration_object", args=self.URL_ARGS)

    def _rule(self, name, *, order, services=("application-default",), action="allow",
              disabled=False, config_source=SecurityRule.SOURCE_LOCAL):
        rule = SecurityRule.objects.create(
            management_station=self.station, enforcement_point=self.point,
            source_snapshot=self.snapshot, config_source=config_source,
            effective_order=order, rule_position=order, name=name, action=action,
            disabled=disabled, rule_type="universal")
        for position, value in enumerate(services, start=1):
            SecurityRuleService.objects.create(
                security_rule=rule, value=value, prov="test", position=position)
        return rule

    #: The security rules page's own column order, from its second header row. `vsys` and the
    #: two address pairs are grouped there under a first header row; this frame has one header
    #: row, so the grouping moves into the labels and the ORDER is what has to match.
    RULES_PAGE_COLUMNS = (
        "Station", "Appliance", "vsys id", "vsys name", "Order", "Config Source", "Device Group",
        "Rule", "Source Zone", "Source Address", "Destination Zone", "Destination Address",
        "Application", "Service", "Action", "Log Start", "Log End", "Log Profile", "Profiles")

    def test_the_columns_are_the_security_rules_pages_columns(self):
        """Jason, 2026-09-18: this page "needs to look like /assessments/security-rules/ in
        terms of columns and values". Two tables over one object that disagree about what a rule
        looks like make a reader check which page they are on before reading a row."""
        self.assertEqual(config_results.RESULTS["security"].columns, self.RULES_PAGE_COLUMNS)

    def test_every_value_the_rules_page_shows_for_a_rule_this_page_shows_too(self):
        """The column names matching is half of it; the cells have to agree as well."""
        rule = self._rule("allow-any-any", order=1, services=("tcp-8443", "tcp-9443"))
        SecurityRuleFromZone.objects.create(
            security_rule=rule, value="untrust", prov="test", position=1)
        SecurityRuleToZone.objects.create(
            security_rule=rule, value="dmz", prov="test", position=1)
        SecurityRuleApplication.objects.create(
            security_rule=rule, value="web-browsing", prov="test", position=1)
        rule.log_setting = "default-forwarding"
        rule.save()

        here = self.client.get(self.url).content.decode()
        for value in ("allow-any-any", "untrust", "dmz", "web-browsing", "tcp-8443", "tcp-9443",
                      "default-forwarding", "vsys1", "allow"):
            self.assertIn(value, here, value)

    def test_a_multi_value_cell_renders_one_value_per_line(self):
        """Joined with commas, four zones and five addresses wrap into a paragraph. The rules
        page gives each member its own line and so does this one."""
        rule = self._rule("multi", order=1, services=("tcp-80", "tcp-443"))
        html = self.client.get(self.url).content.decode()
        self.assertIn("tcp-80<br>tcp-443", html)

    def test_an_empty_cell_reads_as_a_dash_the_way_the_rules_page_writes_it(self):
        """The two predefined defaults carry no service, and a blank cell there is
        indistinguishable from a column that failed to render."""
        self._rule("intrazone-default", order=9, services=(),
                   config_source=SecurityRule.SOURCE_DEFAULT)
        body = re.search(r"<tbody>(.*?)</tbody>",
                         self.client.get(self.url).content.decode(), re.S).group(1)
        self.assertIn(">-</td>", body.replace("\n", "").replace(" ", ""))

    def test_a_negated_address_list_says_so_rather_than_listing_what_it_excludes(self):
        """`negate-source` inverts the whole list - the rule matches everything EXCEPT these -
        so a cell showing the addresses without the marker states the opposite of the rule."""
        rule = self._rule("negated", order=1, services=("any",))
        rule.negate_source = True
        rule.save()
        # REGION is the one ref shape the model's check constraint lets stand alone - every
        # other kind, `any` included, requires its resolved object row. What this test is about
        # is the marker, not what the rule excludes.
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule, raw_value="us-east", position=1,
            ref_type=SecurityRuleSourceAddressRef.RefType.REGION)
        self.assertIn("NOT", self.client.get(self.url).content.decode())

    def test_applying_pan_pol_004_shows_what_it_would_report_here(self):
        """The capability that made the move worth making: the standalone rules page could apply
        a whole control and the explorer could not, so moving rules in before that would have
        lost the one thing rules had."""
        from assessments.tests._seed import seed_control, seed_specs
        control = seed_control(seed_specs()["PAN-POL-004"])
        self._rule("allow-any-any", order=1, services=("any",))
        self._rule("tight", order=2, services=("application-default",))
        html = self.client.get(f"{self.url}?control={control.pk}").content.decode()
        body = re.search(r"<tbody>(.*?)</tbody>", html, re.S).group(1)
        self.assertIn("allow-any-any", body)
        self.assertNotIn("tight", body)
        self.assertIn("High", body)
        self.assertIn("PAN-POL-004", html)

    def test_the_page_pages_rather_than_rendering_every_rule(self):
        for index in range(105):
            self._rule(f"rule-{index:03d}", order=index + 1, services=("any",))
        first = self.client.get(self.url)
        self.assertEqual(first.context["page_obj"].paginator.count, 105)
        self.assertEqual(len(first.context["rows"]), 100)
        second = self.client.get(f"{self.url}?page=2")
        self.assertEqual(len(second.context["rows"]), 5)
        self.assertIn("rule-104", second.content.decode())

    def test_the_pager_carries_the_applied_control_with_it(self):
        """A page link that drops the query returns the reader to the unfiltered listing while
        still saying page 2."""
        from assessments.tests._seed import seed_control, seed_specs
        control = seed_control(seed_specs()["PAN-POL-004"])
        for index in range(105):
            self._rule(f"rule-{index:03d}", order=index + 1, services=("any",))
        html = self.client.get(f"{self.url}?control={control.pk}").content.decode()
        self.assertIn(f"control={control.pk}&amp;page=2", html)


class ConfigurationDashboardTests(TestCase):
    """`/assessments/configuration/` - what the explorer holds.

    Every number on it is a comparison an object page cannot make, and each is derived from the
    same places the pages themselves are: the rail, the results specs, and the destination
    resolver. A control counted against an object here is a control whose "view query results"
    link lands there - two implementations of that would disagree eventually, invisibly.
    """

    def setUp(self):
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.dash")
        self.group = ApplianceGroup.objects.create(
            management_station=self.station, name="g-dash",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        self.url = reverse("assessment_configuration_index")

    def _profile_control(self):
        control = Control.objects.create(
            control_id="PAN-DASH-001", name="Profiles should be bound",
            control_type=Control.ControlType.INTERFACE_MANAGEMENT_PROFILE,
            description="Prototype.", default_severity=Control.Severity.MEDIUM)
        ControlQuery.objects.create(
            control=control, name="Baseline", is_baseline=True, is_active=True,
            canonical_query={"model": "integrations.InterfaceManagementProfile",
                             "operator": "and", "clauses": [
                                 {"field": "binding_count", "op": "eq", "value": 0}]})
        return control

    def test_it_renders_every_object_in_the_rail(self):
        html = self.client.get(self.url).content.decode()
        for obj in config_nav.CONFIG_OBJECTS:
            self.assertIn(obj.label, html, obj.slug)

    def test_a_control_is_counted_against_the_object_its_link_would_open(self):
        control = self._profile_control()
        response = self.client.get(self.url)
        summaries = {s.config_object.slug: s
                     for entry in response.context["categories_detail"]
                     for s in entry["objects"]}
        self.assertEqual([c.control_id for c in summaries["interface-mgmt"].controls],
                         ["PAN-DASH-001"])
        self.assertEqual(summaries["interface-mgmt"].query_count, 1)
        self.assertEqual(summaries["certificates"].controls, [])
        # and the link goes to that control's PREVIEW, which is the question being asked here
        self.assertIn(f"?control={control.pk}", response.content.decode())

    def test_rows_are_counted_after_the_pages_own_scope(self):
        """Anti-spyware and vulnerability protection share a model and split it with a scope
        query. Counting the model would report the same total on both rows."""
        make_profile(self.station, self.group, "fw-dash", "p1", 0)
        summaries = {s.config_object.slug: s
                     for entry in self.client.get(self.url).context["categories_detail"]
                     for s in entry["objects"]}
        self.assertEqual(summaries["interface-mgmt"].row_count, 1)
        self.assertEqual(summaries["anti-spyware"].row_count, 0)

    def test_an_object_no_control_reads_is_named(self):
        """The standing rule is that such an object comes out of the view until a control
        defines it, so the page showing the rail should show when that is not holding."""
        self._profile_control()
        response = self.client.get(self.url)
        listed = {s.config_object.slug for s in response.context["objects_without_controls"]}
        self.assertNotIn("interface-mgmt", listed)
        self.assertIn("certificates", listed)

    def test_a_control_with_nowhere_to_be_previewed_is_called_out(self):
        control = Control.objects.create(
            control_id="PAN-DASH-002", name="Zones",
            control_type=Control.ControlType.CONFIG,
            description="Prototype.", default_severity=Control.Severity.LOW)
        response = self.client.get(self.url)
        self.assertIn(control, list(response.context["unplaced_controls"]))
        self.assertIn("cannot be previewed anywhere", response.content.decode())

    def test_an_inactive_control_is_not_counted(self):
        control = self._profile_control()
        control.is_active = False
        control.save()
        summaries = {s.config_object.slug: s
                     for entry in self.client.get(self.url).context["categories_detail"]
                     for s in entry["objects"]}
        self.assertEqual(summaries["interface-mgmt"].controls, [])

    def test_a_built_query_can_be_found_again_from_here(self):
        """The token is the whole point of a parked query and also the whole problem: it existed
        in one address bar. These rows already exist; listing them costs nothing."""
        state = ConfigurationSearchState.objects.create(
            model_label="integrations.InterfaceManagementProfile",
            query_text="unbound profiles",
            canonical_query={"model": "integrations.InterfaceManagementProfile",
                             "operator": "and", "clauses": [
                                 {"field": "binding_count", "op": "eq", "value": 0}]})
        html = self.client.get(self.url).content.decode()
        self.assertIn("unbound profiles", html)
        self.assertIn(f"search_state={state.token}", html)

    def test_the_totals_add_up_to_what_the_table_shows(self):
        self._profile_control()
        make_profile(self.station, self.group, "fw-dash", "p1", 0)
        response = self.client.get(self.url)
        totals = dict(response.context["totals"])
        summaries = [s for entry in response.context["categories_detail"] for s in entry["objects"]]
        self.assertEqual(totals["Objects"], len(summaries))
        self.assertEqual(totals["Controls"], sum(s.control_count for s in summaries))
        self.assertEqual(totals["Active queries"], sum(s.query_count for s in summaries))
        self.assertEqual(totals["Rows normalized"], sum(s.row_count for s in summaries))


class DashboardChipTests(TestCase):
    """The Dashboard chip in the category bar.

    Rendered by the shared nav partial rather than added to `CATEGORIES`, because it is not a
    category: no objects, no rail, and every derivation over categories treats one as a set of
    objects. The tests are here rather than in `test_navigation` because what they guard is the
    bar's behaviour on these pages - that the chip is reachable from every object page, and that
    exactly one thing in the bar reads as active at a time.
    """

    ACTIVE = 'bg-slate-800 text-white'

    def _bar(self, url):
        html = self.client.get(url).content.decode()
        bar = re.search(r'<div class="flex shrink-0 items-center gap-1 border-b(.*?)</div>',
                        html, re.S)
        self.assertIsNotNone(bar, url)
        return bar.group(1)

    def test_the_chip_leads_the_bar_on_the_dashboard_itself(self):
        """PAN-OS runs Dashboard, ACC, Monitor, Policies, Objects, Network, Device - Dashboard
        is leftmost there too, so the order is the vendor's rather than ours."""
        bar = self._bar(reverse("assessment_configuration_index"))
        self.assertLess(bar.index("Dashboard"), bar.index("Policies"))

    def test_it_is_reachable_from_every_object_page(self):
        index = reverse("assessment_configuration_index")
        for obj in config_nav.CONFIG_OBJECTS:
            url = reverse("assessment_configuration_object",
                          args=[config_nav.category_slug(obj.category), obj.slug])
            with self.subTest(obj.slug):
                self.assertIn(f'href="{index}"', self._bar(url))

    def test_exactly_one_chip_reads_as_active_on_each_page(self):
        """Two solid chips would claim the reader is in two places; none would claim nowhere."""
        bar = self._bar(reverse("assessment_configuration_index"))
        self.assertEqual(bar.count(self.ACTIVE), 1)
        self.assertLess(bar.index(self.ACTIVE), bar.index("Policies"))

        obj = config_nav.CONFIG_OBJECTS[0]
        bar = self._bar(reverse("assessment_configuration_object",
                                args=[config_nav.category_slug(obj.category), obj.slug]))
        self.assertEqual(bar.count(self.ACTIVE), 1)
        self.assertGreater(bar.index(self.ACTIVE), bar.index("Dashboard"))

    def test_the_chip_carries_no_count(self):
        """Every category chip shows how many objects it holds. Dashboard holds none, and `0`
        there would read as an empty category rather than as a page."""
        bar = self._bar(reverse("assessment_configuration_index"))
        dashboard_chip = bar[bar.index("Dashboard"):bar.index("Policies")]
        self.assertNotIn("text-[10px] font-normal", dashboard_chip)
