"""Every device tab's table must be square: as many cells per row as columns declared.

Checklist item 44 exists because this failed once and was found by reading, not by testing -
removing two model fields left the headers declaring columns the body no longer rendered, and
every column after them shifted. A page can look plausible while doing that.

Parsing the rendered HTML rather than the column spec is the point: it covers the two pages
that keep hand-written grouped headers as well as the eight that generate theirs, so the
guarantee does not depend on a page having adopted the spec.
"""

from __future__ import annotations

from html.parser import HTMLParser

from django.test import TestCase
from django.urls import reverse

from django.utils import timezone

from assessments.navigation import DEVICE_TABS
from assessments.tables import Column
from optivedge_integrations.integrations.models import (
    AdminUser, Appliance, ApplianceGroup, AuthenticationProfile, AuthenticationSequence,
    Certificate, CertificateProfile,
    ServerProfile,
    InterfaceManagementProfile, ManagementInterface,
    AuthenticationSettings, LoginBanner, ManagementTlsBinding, ManagementSshSettings, MasterKey,
    PasswordComplexityPolicy,
    ManagementStation, PasswordProfile, SecurityProfile, Snapshot, SslTlsServiceProfile)


class _Table(HTMLParser):
    """Header rows and body rows of the analytical table, as cell counts."""

    def __init__(self):
        super().__init__()
        self.depth = 0
        self.header_rows: list[int] = []
        self.body_rows: list[int] = []
        self.row: list[int] | None = None
        self.kind = ""
        self.colspan = 0

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "table" and "analytical-table" in (attributes.get("class") or ""):
            self.depth += 1
        elif self.depth and tag == "tr":
            self.row, self.kind = [], ""
        elif self.depth and tag in ("th", "td") and self.row is not None:
            self.kind = self.kind or tag
            self.row.append(int(attributes.get("colspan", 1)))

    def handle_endtag(self, tag):
        if tag == "table" and self.depth:
            self.depth -= 1
        elif self.depth and tag == "tr" and self.row is not None:
            if self.row:
                (self.header_rows if self.kind == "th" else self.body_rows).append(sum(self.row))
            self.row = None


class DeviceTabTableTests(TestCase):
    """One row on every tab, so the squareness assertion is not vacuous.

    An empty database renders the empty state and no table at all - the first version of this
    test passed everywhere by checking nothing.
    """

    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.tables")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-tables",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-TABLES", hostname="fw-tables")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        common = {"management_station": station, "appliance": appliance,
                  "source_snapshot": snapshot}
        PasswordComplexityPolicy.objects.create(**common)
        AuthenticationSettings.objects.create(**common)
        LoginBanner.objects.create(**common)
        MasterKey.objects.create(**common)
        ManagementTlsBinding.objects.create(**common)
        ManagementSshSettings.objects.create(**common)
        ManagementInterface.objects.create(plane=ManagementInterface.PLANE_MGT, **common)
        InterfaceManagementProfile.objects.create(
            name="p", bound_interface_names=[], bound_interface_count=0, **common)
        SslTlsServiceProfile.objects.create(name="tls", scope="shared", **common)
        CertificateProfile.objects.create(name="cp", scope="shared", **common)
        Certificate.objects.create(name="cert", scope="shared", **common)
        AuthenticationProfile.objects.create(name="auth", scope="shared", **common)
        AuthenticationSequence.objects.create(name="seq", scope="shared", **common)
        PasswordProfile.objects.create(name="pwd", **common)
        # A policy object: owned by the group rather than the appliance, so not **common.
        SecurityProfile.objects.create(
            management_station=station, appliance_group=group, source_snapshot=snapshot,
            config_source="local", name="spy", namespace_type="local_shared",
            namespace_value="shared", precedence_rank=20, kind=SecurityProfile.KIND_SPYWARE)
        AdminUser.objects.create(name="admin", role_type=AdminUser.RoleType.SUPERUSER,
                                 is_superuser=True, superuser_cohort_size=1, **common)
        ServerProfile.objects.create(name="aaa", kind=ServerProfile.Kind.LDAP,
                                     scope="shared", **common)

    def test_every_body_row_has_as_many_cells_as_the_header_declares(self):
        for tab in DEVICE_TABS:
            for query in ("", "?provenance=1", "?findings=1"):
                with self.subTest(tab=tab.label, query=query):
                    response = self.client.get(reverse(tab.url_name) + query)
                    self.assertEqual(response.status_code, 200)
                    table = _Table()
                    table.feed(response.content.decode())
                    self.assertTrue(table.header_rows,
                                    f"{tab.label}{query} rendered no table - the row this "
                                    f"test creates should have produced one")
                    self.assertTrue(table.body_rows, f"{tab.label}{query} rendered no rows")
                    # Two pages carry a grouping row above the labels; every header row spans
                    # the same total width, and each body row must match it.
                    widths = set(table.header_rows) | set(table.body_rows)
                    self.assertEqual(
                        len(widths), 1,
                        f"{tab.label}{query}: header rows {table.header_rows}, "
                        f"body rows {sorted(set(table.body_rows))}")

    def test_the_generated_headers_render_exactly_the_declared_columns(self):
        """The pages that adopted the spec render its labels, in its order, and no others."""
        import re
        from django.urls import resolve
        adopted = 0
        for tab in DEVICE_TABS:
            view = resolve(reverse(tab.url_name)).func.view_class
            columns = getattr(view, "COLUMNS", None)
            if columns is None:
                continue
            adopted += 1
            with self.subTest(tab=tab.label):
                html = self.client.get(reverse(tab.url_name)).content.decode()
                head = re.search(r"<thead>(.*?)</thead>", html, re.S).group(1)
                rendered = re.findall(r"<th[^>]*>([^<]*)</th>", head)
                self.assertEqual([r.strip() for r in rendered],
                                 [c.label for c in columns])
        self.assertGreaterEqual(adopted, 8, "expected the simple tabs to declare COLUMNS")

    def test_a_column_spec_is_a_list_of_columns(self):
        from django.urls import resolve
        for tab in DEVICE_TABS:
            columns = getattr(resolve(reverse(tab.url_name)).func.view_class, "COLUMNS", None)
            if columns is None:
                continue
            for column in columns:
                self.assertIsInstance(column, Column)
                self.assertTrue(column.label.strip(), f"{tab.label} has a blank column label")


class DeviceTabViewConfigTests(TestCase):
    """`finding_controls = ()` means EVERY control of that finding model.

    That is right for a tab owning a whole object type, and silently wrong for tabs that SHARE a
    finding model: a tab that forgets to name its controls shows the others' findings as its own.
    Four tabs used to share DeviceConfigurationFinding - Login Banner, Management TLS, Master Key
    and Password Complexity - and removing `finding_controls` from MasterKeyListView broke no
    test until this one existed; the page just filled up.

    None share one now. The aggregate was split on 2026-09-10 and each of those tabs has a
    finding model of its own, which is what the split was for. The rule stays, conditional, for
    the next time two tabs are built over one model.
    """

    def _tab_views(self):
        from django.urls import resolve
        from assessments.views import DeviceTabListView
        for tab in DEVICE_TABS:
            view = resolve(reverse(tab.url_name)).func.view_class
            if isinstance(view, type) and issubclass(view, DeviceTabListView):
                yield tab, view

    def test_tabs_sharing_a_finding_model_must_name_their_controls(self):
        from collections import defaultdict
        by_model = defaultdict(list)
        for tab, view in self._tab_views():
            if view.finding_model is not None:
                by_model[view.finding_model].append((tab, view))
        shared = {model: pairs for model, pairs in by_model.items() if len(pairs) > 1}
        # No assertion that sharing EXISTS. It used to, and the aggregate split removed the
        # last of it on 2026-09-10 - five tabs that read DeviceConfigurationFinding now read a
        # finding model each. Requiring a sharer to be present made this test fail on the
        # success it was written to survive; the rule it guards is conditional, so it stays
        # conditional.
        for model, pairs in shared.items():
            for tab, view in pairs:
                self.assertTrue(
                    view.finding_controls,
                    f"{view.__name__} shares {model.__name__} with "
                    f"{len(pairs) - 1} other tab(s) and must name its controls, or it will "
                    f"show theirs")

    def test_tabs_sharing_a_finding_model_do_not_claim_the_same_control(self):
        from collections import defaultdict
        owner: dict[str, str] = {}
        for tab, view in self._tab_views():
            for control_id in view.finding_controls:
                key = f"{view.finding_model.__name__}:{control_id}"
                self.assertNotIn(
                    key, owner,
                    f"{control_id} is claimed by both {owner.get(key)} and {view.__name__}")
                owner[key] = view.__name__

    def test_every_tab_view_declares_what_the_base_needs(self):
        for tab, view in self._tab_views():
            with self.subTest(tab=tab.label):
                self.assertTrue(view.COLUMNS, f"{view.__name__} declares no COLUMNS")
                self.assertTrue(view.tab_title, f"{view.__name__} has no tab_title")
                self.assertIsNotNone(view.subject_model)
                self.assertIsNotNone(view.finding_model)
                self.assertTrue(view.finding_subject_field)
                view.finding_model._meta.get_field(view.finding_subject_field)
