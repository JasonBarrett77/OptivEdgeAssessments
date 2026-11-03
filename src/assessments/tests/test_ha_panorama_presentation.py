"""The two `ha-panorama` findings tabs, two rail items and two results pages, pinned.
Stage 9, `ha-panorama`, 2026-11-03.

WHAT THIS EXISTS FOR, since the shipped squareness checks already cover the tabs generically:
every assertion here is a JUDGEMENT this run made that nothing else in the repository states, and
a new tab nothing asserts on is one the next refactor can break silently.

  - THE PROVENANCE CELL BRANCHES, AND IT IS THE FIRST ONE THAT DOES. Every `provenance_cell`
    shipped before this returns the constant "Derived", because on those models every field a
    control clauses on is declared in `DERIVED_FIELDS`. On BOTH models here that is false:
    `ha_enabled` and `panorama_server_secondary` are real keys an administrator wrote, carrying
    real `FieldProvenance` rows, so a constant would print a falsehood about them - and
    `panorama_server_secondary` is the field PAN-HAP-005's own calibration asserts on. Both
    branches are pinned on built rows, and so is the third state the DEFAULT cell produces:
    "Not recorded", which states that nothing TRACKS the field and is the opposite of true.

  - AND THE OTHER HALF OF THE `choices` RULE, which ships a 500 rather than a wrong word (P462).
    NEITHER MODEL DECLARES `choices=` ON ANY FIELD, so `get_<field>_display()` does not exist on
    any of them and a labelling `ValueReader` would raise `AttributeError` at TEMPLATE RENDER -
    past `django check` and past all three cross-domain gates. The test asserts the attribute's
    absence on every clause field of both models, which is the guard against a later run copying
    the reader pattern across from a domain where it is mandatory.

  - THE HA PAIR DRAWS TWO ROWS AND THAT IS CORRECT. Both models are `unique(appliance)` and the
    subject is device-wide, so one real relationship yields two rows; a collapsed pair would be a
    pair half assessed. The `HA role` column is what makes them read as two members rather than
    as a duplicate, and the test pins that the two HA rows DISAGREE - `ha_mode` present on the
    active member and absent on the passive one, which is what stage 4 measured on this estate -
    while the two management-channel rows AGREE, which is the other half of the same claim.

  - THE COLUMN ORDER, per tab, read off the built table rather than derived. Nothing gates it:
    `tested_fields` takes the baseline's clauses in clause order and then every other active
    query's in ALPHABETICAL ORDER OF THE QUERY'S NAME, so renaming a shipped calibration query
    silently reorders a customer-facing column. PAN-HAP-002 is the one that depends on it, and
    the order puts the "did anybody look" column BETWEEN the assertion and the graded verdict.

  - THE TWO COLUMNS THIS RUN REFUSED TO DRAW, which is a judgement no gate can see:
    `link_monitoring_enabled` and `path_monitoring_enabled` read `Yes` when their keys are
    ABSENT, by the device's own answer, so on the PAN-HAP-004 row they would be two reassuring
    cells beside a verdict saying this firewall monitors nothing.

  - the explorer `row` lambdas over real rows, which the shipped check cannot read, and every
    `query_fields` entry against the search registry.

EVERY TEST THAT READS A ROW CALLS THE FINDING RUN ITSELF AND ASSERTS THE TABLE IS NOT EMPTY.
`build_findings_table` LOADS a domain's findings rather than computing them, and its only
row-count guard compares what it built against what the DATABASE holds - so with no findings
generated both sides are zero, nothing raises, the HEADINGS still come out right because they
derive from the controls, and every assertion written `for row in table.rows:` iterates nothing
and passes. That has already happened in committed work. The finding run is called in the tests
that need rows rather than in `setUp`, so the rest of the suite does not pay for it.
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.utils import timezone

from assessments import configuration_results as cr
from assessments import ha_panorama_presentation as presentation
from assessments.artifacts.domains import DOMAIN_BY_SLUG
from assessments.artifacts.sheets.findings import (
    ALL_TESTED_COLUMNS, build_findings_table, tested_fields)
from assessments.configuration_navigation import CATEGORIES, CONFIG_OBJECTS
from assessments.models import Control
from assessments.search.high_availability_config import compiler as ha_compiler
from assessments.search.panorama_registration import compiler as panorama_compiler
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, EnforcementNode, EnforcementPoint, HighAvailabilityConfig,
    ManagementStation, PanoramaRegistration, Snapshot)
from optivedge_integrations.integrations.models.provenance import FieldProvenance

#: All five active controls. PAN-HAP-006 and 007 are NOT here and have no catalog entry at all -
#: they assert over the management station's own configuration, which `rules.md` puts out of
#: assessment scope - so `seed_controls` would raise on either and nothing was built for them.
PAN_HAP = ("PAN-HAP-001", "PAN-HAP-002", "PAN-HAP-003", "PAN-HAP-004", "PAN-HAP-005")

#: (rail slug, findings-domain slug, control type, model). The category is Device for both and is
#: DERIVED from the rail, so the test asserts the agreement rather than the word.
TABS = (
    ("high-availability", "high-availability", "high_availability", HighAvailabilityConfig),
    ("panorama-settings", "panorama-settings", "panorama_registration", PanoramaRegistration),
)


class HaPanoramaRailTests(TestCase):
    """The two rail items, and the ways one can be wrong without a test name saying so."""

    def test_each_model_has_exactly_one_rail_item_and_it_claims_device(self):
        for rail_slug, _domain_slug, _control_type, model in TABS:
            with self.subTest(slug=rail_slug):
                label = f"integrations.{model.__name__}"
                items = [o for o in CONFIG_OBJECTS if o.search_model == label]
                self.assertEqual(1, len(items), f"{label} needs exactly one rail item")
                (item,) = items
                self.assertEqual(rail_slug, item.slug)
                self.assertEqual("Device", item.category)
                self.assertIn(item.category, CATEGORIES)

    def test_the_vendor_paths_are_the_help_s_own_words(self):
        """Five runs running have corrected a `where` written from memory. Both were read out of
        `PAN-OS Web Interface Help 11.2` through `probe.corpus` on 2026-11-03: p.800 heads the HA
        section `Device > High Availability`, and p.700 and p.709 both spell the panel
        `Panorama Settings: Device > Setup > Management`."""
        paths = {"high-availability": "Device > High Availability",
                 "panorama-settings": "Device > Setup > Management"}
        for slug, where in paths.items():
            with self.subTest(slug=slug):
                (item,) = [o for o in CONFIG_OBJECTS if o.slug == slug]
                self.assertEqual(where, item.where)

    def test_the_panorama_item_is_a_panel_of_the_setup_screen(self):
        """It is one panel of `Device > Setup > Management`, which is why it is in the `Setup`
        group beside `authentication-settings` and `policy-rule-settings` rather than a
        top-level item - Help 11.2 p.700 lists the panels of that screen and names it among
        them. High Availability is a Device SECTION in its own right (p.697), so it has no
        group."""
        (panorama,) = [o for o in CONFIG_OBJECTS if o.slug == "panorama-settings"]
        (high_availability,) = [o for o in CONFIG_OBJECTS if o.slug == "high-availability"]
        self.assertEqual("Setup", panorama.group)
        self.assertEqual("", high_availability.group)

    def test_every_icon_is_one_of_the_nineteen_vendored_files(self):
        """`ConfigObject.icon` IS NOT VALIDATED and a name that is not there raises
        `FileNotFoundError` at TEMPLATE RENDER - and because the rail renders on every explorer
        page it takes out every explorer test, with not one test name mentioning an icon. The
        nineteen are in the OptivEdge HOST repo at
        `src/optivedge/templates/components/icons/`, NOT in this repository, and were enumerated
        there on 2026-11-03 rather than taken from any list."""
        vendored = {
            "book-marked", "chevron-right", "circle-question-mark", "clipboard-check",
            "download", "eye", "flag", "layout-dashboard", "list-checks", "monitor", "plus",
            "refresh-cw", "server", "settings", "shield", "trash-2", "triangle-alert",
            "wand-sparkles", "x"}
        for slug in ("high-availability", "panorama-settings"):
            with self.subTest(slug=slug):
                (item,) = [o for o in CONFIG_OBJECTS if o.slug == slug]
                self.assertIn(item.icon, vendored)

    def test_the_prefix_no_longer_waits_for_presentation(self):
        """Clearing it is part of this stage's job rather than a side effect: an exemption that
        survives the work it was waiting for is a permanent hole. It is also what FORCES the two
        rail items - `test_every_query_in_the_shipped_catalog_has_somewhere_to_go` iterates the
        seed payload and never consults `is_active`, so with this gone there is no off-rail
        route left for any of the eleven shipped PAN-HAP queries."""
        self.assertNotIn("PAN-HAP", cr.AWAITING_PRESENTATION)


class HaPanoramaDomainTests(TestCase):
    """The two findings domains, their titles and where their category comes from."""

    def test_two_domains_and_not_one(self):
        """Two vendor screens, two sets of columns sharing nothing but the appliance, and two
        different remediations - adding an address versus enrolling a certificate. One tab would
        also print `layout.NONE` in every column belonging to the other model on every row,
        because `setting_columns` reads a field off the model its own control targets."""
        for _rail_slug, domain_slug, control_type, _model in TABS:
            with self.subTest(slug=domain_slug):
                domain = DOMAIN_BY_SLUG[domain_slug]
                self.assertEqual((control_type,), domain.spec.control_types)

    def test_each_tab_title_fits_a_worksheet_name(self):
        """Excel caps a sheet name at 31 characters and `write_sheet` truncates with `title[:31]`
        SILENTLY - while `probe.surface_for` prints the untruncated title, so the tool and the
        workbook would disagree and the tool would look right."""
        for _rail_slug, domain_slug, _control_type, _model in TABS:
            with self.subTest(slug=domain_slug):
                title = DOMAIN_BY_SLUG[domain_slug].spec.sheet_title
                self.assertLessEqual(len(title), 31, f"{title!r} truncates in the workbook")

    def test_both_titles_are_the_vendor_s_own_words(self):
        """PROPOSALS, per P399 - Jason takes the heading pass once across many domains - and each
        is the vendor's own name for the screen rather than the control type's internal label.
        `Panorama Settings` deliberately is NOT "Panorama Registration", which is what
        `Control.ControlType` calls it: Help 11.2 p.709 heads the panel `Panorama Settings`, and
        that is the phrase an assessor will be looking for on the screen."""
        self.assertEqual("High Availability",
                         DOMAIN_BY_SLUG["high-availability"].spec.sheet_title)
        self.assertEqual("Panorama Settings",
                         DOMAIN_BY_SLUG["panorama-settings"].spec.sheet_title)

    def test_neither_sheet_declares_a_category_so_both_derive_from_the_rail(self):
        """Right for a subject that IS a configuration object: deriving it means the workbook
        cannot disagree with the app about where the subject lives. The explicit `category`
        escape hatch is for a subject that is OUR OWN record, which neither of these is."""
        for _rail_slug, domain_slug, _control_type, _model in TABS:
            with self.subTest(slug=domain_slug):
                self.assertEqual("", DOMAIN_BY_SLUG[domain_slug].spec.category)

    def test_neither_sheet_hides_a_tested_field(self):
        """`check_every_tested_field_is_presented` counts a field as presented if
        `hidden_fields` carries it, so a non-empty one is a CLAIM accepted as proof - and it
        forfeits the value-at-fault mark, because the two `implicated` loops walk
        `subject_columns` and the settings columns and never consult it."""
        for _rail_slug, domain_slug, _control_type, _model in TABS:
            with self.subTest(slug=domain_slug):
                self.assertEqual((), DOMAIN_BY_SLUG[domain_slug].spec.hidden_fields)

    def test_both_sheets_carry_the_full_tested_block(self):
        """The default `("Provenance",)` drops `Fires when` from the WORKBOOK while the live page
        keeps it, so the two surfaces would disagree about which cell a reader meets (P427)."""
        for _rail_slug, domain_slug, _control_type, _model in TABS:
            with self.subTest(slug=domain_slug):
                self.assertEqual(ALL_TESTED_COLUMNS,
                                 DOMAIN_BY_SLUG[domain_slug].spec.tested_columns)


class NoChoicesReaderTests(TestCase):
    """P462's hard half: a reader is FATAL on a field without `choices`, not merely unhelpful."""

    def test_no_clause_field_on_either_model_declares_choices(self):
        """So the sheet-level `provenance_cell` is the only remedy available for the
        "Not recorded" cell, and it is mandatory here rather than an alternative."""
        for model in (HighAvailabilityConfig, PanoramaRegistration):
            for field in model._meta.get_fields():
                if not hasattr(field, "choices"):
                    continue
                with self.subTest(model=model.__name__, field=field.name):
                    self.assertFalse(field.choices,
                                     f"{model.__name__}.{field.name} now declares choices, so a "
                                     f"labelling ValueReader became available - see P457/P462")

    def test_get_display_does_not_exist_on_any_presented_field(self):
        """`get_<field>_display()` exists ONLY on a field that declares `choices`; on the
        booleans and the plain `CharField`s here the call raises `AttributeError` AT TEMPLATE
        RENDER, which is past `django check` and past every test that does not render the page.
        Measured on `GlobalProtectGateway.globalprotect_gateway_licensed` by the run that copied
        the pattern from a domain where the reader was mandatory."""
        for model in (HighAvailabilityConfig, PanoramaRegistration):
            for name in ("ha_enabled", "ha_mode", "ha1_control_link_exposure",
                         "ha_monitoring_state", "second_keepalive_path_state",
                         "panorama_server_secondary", "client_certificate_type"):
                if not hasattr(model, name) and not any(
                        f.name == name for f in model._meta.get_fields()):
                    continue
                with self.subTest(model=model.__name__, field=name):
                    self.assertFalse(hasattr(model(), f"get_{name}_display"))

    def test_neither_sheet_declares_a_value_reader(self):
        """The consequence of the two above, stated where a later run will look. It is also what
        makes the three classification columns print their stored band key rather than an English
        label, which this run recorded as a presentation defect it declined to fix rather than
        as a clean result."""
        for _rail_slug, domain_slug, _control_type, _model in TABS:
            with self.subTest(slug=domain_slug):
                self.assertEqual({}, DOMAIN_BY_SLUG[domain_slug].spec.value_readers)


class HaPanoramaEstateMixin:
    """An HA PAIR and a standalone, in the state the measured estate is in.

    THE PAIR IS BUILT BY HAND AND THAT IS THE POINT (P460). `tests/_estate.build_base_estate`
    always sets `EnforcementPoint.appliance` and gives every serial its own standalone group, so
    every row it builds reads `Standalone` and an HA measurement through it reports its own
    fixture. `flows.get_in_scope_appliances` (flows.py:503-527) takes
    `enforcement_point.appliance` when set and `continue`s without ever consulting the point's
    nodes, so ONE point with a NULL `appliance` and TWO `EnforcementNode`s is what makes both
    members normalise - measured 2026-11-03 as 1.0 rows per configuration against 2.0.
    """

    #: fw-core-tpa-a's measured state, 2026-10-26 to 2026-10-29, from stage 6 subject hap6-01.
    #: `ha_runtime_state_collected` is FALSE because no collector issues
    #: `show high-availability all` - which is why `no_live_redundant_peer` and
    #: `ha1_control_link_not_encrypted` stand at their firing value on every appliance in every
    #: estate today, and why the exposure band is `unencrypted-port-unknown` rather than naming
    #: a port.
    HA_MEASURED = dict(
        ha_config_collected=True, ha_runtime_state_collected=False,
        ha_enabled=True, cluster_participation_enabled=None,
        config_sync_enabled=True, state_sync_enabled=False,
        ha1_encryption_enabled=None, ha1_encryption_key_imported=None,
        ha1_backup_port="", peer_ip_backup="", heartbeat_backup_enabled=None,
        # The device's own implicit YES, measured in both directions across commit jobs 538 and
        # 539 on an appliance holding no `group/monitoring` node at all. NO COLUMN ON EITHER TAB
        # SHOWS THESE - see `HaPanoramaTabTests.test_the_reassuring_defaults_are_not_on_the_tab`.
        link_monitoring_enabled=True, path_monitoring_enabled=True,
        link_monitoring_failure_condition="", path_monitoring_failure_condition="",
        monitored_link_groups=[], monitored_link_group_count=0,
        no_live_redundant_peer=True, ha_monitors_nothing=True,
        ha_monitoring_state=HighAvailabilityConfig.MONITORING_ENABLED_NO_GROUP,
        no_independent_second_keepalive_path=True,
        second_keepalive_path_state=HighAvailabilityConfig.KEEPALIVE_BACKUP_WITHOUT_PEER,
        ha1_control_link_not_encrypted=True,
        ha1_control_link_exposure=HighAvailabilityConfig.EXPOSURE_PORT_UNKNOWN)

    #: The same appliance's management channel, from stage 6 subjects hap6-03 and hap6-06.
    #: `panorama-server-2` is this run's own write; the primary pre-existed on all four lab
    #: appliances. Neither `secure-conn-client` switch is in the configuration at all.
    PANORAMA_MEASURED = dict(
        management_config_collected=True,
        panorama_server_primary="20.185.152.225", panorama_server_secondary="192.0.2.1",
        secure_panorama_communication_enabled=None, check_server_identity_enabled=None,
        client_certificate_type="", client_certificate_name="",
        management_estate_is_a_pair=True, panorama_address_in_force_unverified=True,
        management_channel_not_hardened=True)

    @classmethod
    def build_estate(cls):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="p.hap")
        pair = ApplianceGroup.objects.create(
            management_station=station, name="ha-pair-tpa",
            group_type=ApplianceGroup.TYPE_HA_PAIR)
        active = Appliance.objects.create(
            management_station=station, appliance_group=pair,
            serial_number="013201001475", hostname="fw-core-tpa-a", model="PA-5220")
        passive = Appliance.objects.create(
            management_station=station, appliance_group=pair,
            serial_number="013201001476", hostname="fw-core-tpa-b", model="PA-5220")
        pair.active_appliance = active
        pair.save(update_fields=["active_appliance"])
        # ONE point for the PAIR - a vsys belongs to the group's namespace, which is what lets a
        # pair share one - with a NULL `appliance` and a node per member.
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=pair, appliance=None,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True)
        for appliance in (active, passive):
            EnforcementNode.objects.create(
                management_station=station, enforcement_point=point, appliance=appliance)

        standalone_group = ApplianceGroup.objects.create(
            management_station=station, name="standalone-201",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        standalone = Appliance.objects.create(
            management_station=station, appliance_group=standalone_group,
            serial_number="691665AC334B458", hostname="pan-fw-201", model="PA-VM")
        standalone_group.active_appliance = standalone
        standalone_group.save(update_fields=["active_appliance"])
        standalone_point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=standalone_group, appliance=standalone,
            vsys_name="vsys1", vsys_display_name="vsys1", in_scope=True)
        EnforcementNode.objects.create(
            management_station=station, enforcement_point=standalone_point,
            appliance=standalone)
        # `source_snapshot` is NOT NULL on both models, so no row can be built without one.
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=active,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        return station, active, passive, standalone, snapshot

    @classmethod
    def build_rows(cls, station, active, passive, standalone, snapshot):
        """Two HA rows that DISAGREE, two management-channel rows that AGREE, and a standalone.

        `ha_mode` is the divergence: `group/mode/active-passive` is present on fw-core-tpa-a and
        the peer holds no `mode` key at all, measured by stage 4 on this estate and recorded in
        `HighAvailabilityConfig`'s own docstring. So the two rows of one pair are not duplicates
        and must not be collapsed.
        """
        ha = {}
        for appliance, mode in ((active, HighAvailabilityConfig.MODE_ACTIVE_PASSIVE),
                                (passive, "")):
            ha[appliance.hostname] = HighAvailabilityConfig.objects.create(
                management_station=station, appliance=appliance, appliance_group=None,
                source_snapshot=snapshot, ha_mode=mode,
                **{k: v for k, v in cls.HA_MEASURED.items() if k != "ha_mode"})
        # The standalone: HA off entirely, which is pan-fw-201's measured state - hap6-02 read
        # back an EMPTY node. `ha_enabled` false is what EXCLUDES it from PAN-HAP-002, 003 and
        # 004 by their shared applicability clause, and does NOT exclude it from PAN-HAP-001.
        ha[standalone.hostname] = HighAvailabilityConfig.objects.create(
            management_station=station, appliance=standalone, appliance_group=None,
            source_snapshot=snapshot, ha_config_collected=True, ha_enabled=False)

        panorama = {}
        for appliance in (active, passive):
            panorama[appliance.hostname] = PanoramaRegistration.objects.create(
                management_station=station, appliance=appliance, appliance_group=None,
                source_snapshot=snapshot, **cls.PANORAMA_MEASURED)
        # pan-fw-201, stage 6 subject hap6-07: the `certificate-type/none` branch present with
        # no text, which MEANS THE SAME THING as an absent key and is a different stored state.
        panorama[standalone.hostname] = PanoramaRegistration.objects.create(
            management_station=station, appliance=standalone, appliance_group=None,
            source_snapshot=snapshot, management_config_collected=True,
            panorama_server_primary="20.185.152.225", panorama_server_secondary="",
            client_certificate_type=PanoramaRegistration.CERTIFICATE_TYPE_NONE,
            management_channel_not_hardened=True)
        return ha, panorama

    @classmethod
    def write_provenance(cls, ha, panorama):
        """The rows the committed normalisers write for the two STORED clause fields.

        `normalization/high_availability.py` writes fourteen `FieldProvenance` rows and
        `ha_enabled` is among them; the Panorama normaliser writes one for
        `panorama_server_secondary`. NEITHER WRITES AN `__entry__` ROW, which is the whole reason
        the default provenance cell reads "Not recorded" - `remediation_accessor` discards a
        DERIVED row on purpose and walks to an entry row that is not there.
        """
        for row in ha.values():
            if not row.ha_enabled:
                continue
            FieldProvenance.objects.create(
                content_type=ContentType.objects.get_for_model(HighAvailabilityConfig),
                object_id=row.pk, field_name="ha_enabled",
                provenance_type=FieldProvenance.ProvenanceType.LOCAL,
                raw_key="enabled", raw_value="yes")
        for row in panorama.values():
            if not row.panorama_server_secondary:
                continue
            FieldProvenance.objects.create(
                content_type=ContentType.objects.get_for_model(PanoramaRegistration),
                object_id=row.pk, field_name="panorama_server_secondary",
                provenance_type=FieldProvenance.ProvenanceType.LOCAL,
                raw_key="panorama-server-2", raw_value="192.0.2.1")


class ProvenanceCellTests(HaPanoramaEstateMixin, TestCase):
    """P451 on a domain whose clause fields are MIXED, which no previous tab's were."""

    def setUp(self):
        self.station, self.active, self.passive, self.standalone, self.snapshot = \
            self.build_estate()
        self.ha, self.panorama = self.build_rows(
            self.station, self.active, self.passive, self.standalone, self.snapshot)
        self.write_provenance(self.ha, self.panorama)

    def cell_for(self, subject, fields):
        def provenance_of(field):
            return subject.provenance_for(field)
        return presentation.provenance_cell(subject, provenance_of, fields)

    def test_a_declared_derived_field_reads_derived(self):
        """The branch every shipped `provenance_cell` gets right by being a constant."""
        subject = self.ha["fw-core-tpa-a"]
        self.assertIn("ha1_control_link_not_encrypted",
                      HighAvailabilityConfig.DERIVED_FIELDS)
        self.assertEqual(
            "Derived", self.cell_for(subject, [("ha1_control_link_not_encrypted", True)]))

    def test_a_stored_clause_field_reads_what_was_recorded(self):
        """THE BRANCH A CONSTANT WOULD GET WRONG. `ha_enabled` is
        `deviceconfig/high-availability/enabled`, a real key an administrator wrote, and it is
        NOT in `DERIVED_FIELDS` - so a cell reading "Derived" over it would tell a customer we
        computed a value the firewall holds."""
        subject = self.ha["fw-core-tpa-a"]
        self.assertNotIn("ha_enabled", HighAvailabilityConfig.DERIVED_FIELDS)
        self.assertEqual("Local", self.cell_for(subject, [("ha_enabled", True)]))

    def test_the_management_channel_s_stored_clause_field_is_the_asserted_one(self):
        """`panorama_server_secondary` is not merely stored, it is the field PAN-HAP-005's own
        calibration ASSERTS on - so a constant "Derived" would be a falsehood about the very
        value this control reports."""
        subject = self.panorama["fw-core-tpa-a"]
        self.assertNotIn("panorama_server_secondary", PanoramaRegistration.DERIVED_FIELDS)
        self.assertEqual("Local", self.cell_for(subject, [("panorama_server_secondary", True)]))

    def test_a_third_answer_appeared_that_no_two_way_branch_would_have_printed(self):
        """FOUND ON A BUILT ROW RATHER THAN ANTICIPATED, and it is why this cell reads what was
        RECORDED instead of deciding anything. On an appliance whose second management slot is
        ABSENT, the normaliser records the implicit as `PAN-OS default` - the key is not there
        and PAN-OS supplies the behaviour, which is neither something an administrator wrote nor
        something this assessment derived. A constant "Derived" would have been wrong, and so
        would a two-way derived-or-Local branch."""
        subject = self.panorama["pan-fw-201"]
        FieldProvenance.objects.create(
            content_type=ContentType.objects.get_for_model(PanoramaRegistration),
            object_id=subject.pk, field_name="panorama_server_secondary",
            provenance_type=FieldProvenance.ProvenanceType.PAN_OS_DEFAULT,
            raw_key="panorama-server-2", raw_value="")
        self.assertEqual(
            "PAN-OS default",
            self.cell_for(subject, [("panorama_server_secondary", True)]))

    def test_an_assumed_default_is_never_called_a_vendor_fact(self):
        """The one rewording `provenance_cells` does, and this cell inherits it rather than
        reimplementing it: `ASSUMED_DEFAULT` prints "Assumed - not measured" and NOT "PAN-OS
        default", because the value is our inference and printing it as vendor behaviour would
        state something about a customer's firewall that nobody established."""
        subject = self.panorama["fw-core-tpa-a"]
        FieldProvenance.objects.filter(
            content_type=ContentType.objects.get_for_model(PanoramaRegistration),
            object_id=subject.pk, field_name="panorama_server_secondary").update(
            provenance_type=FieldProvenance.ProvenanceType.ASSUMED_DEFAULT)
        self.assertEqual(
            "Assumed - not measured",
            self.cell_for(subject, [("panorama_server_secondary", True)]))

    def test_a_mixed_row_prints_both_answers_once_each(self):
        """Distinct answers, worst-known-first as encountered, matching `member_provenance`'s
        rule - a tab whose seven clause fields are six DERIVED and one Local prints two lines
        rather than seven."""
        subject = self.ha["fw-core-tpa-a"]
        fields = [("ha_enabled", True), ("ha1_control_link_not_encrypted", True),
                  ("ha_config_collected", True), ("ha1_control_link_exposure", True)]
        self.assertEqual("Local\nDerived", self.cell_for(subject, fields))

    def test_the_default_cell_would_have_said_nothing_tracks_these(self):
        """WHY THE HOOK IS NEEDED AT ALL, measured rather than argued. The default cell does not
        read `provenance_of`; it reads `remediation_accessor`, which discards a DERIVED row on
        purpose - "DERIVED counts as no answer" - and walks to the object's `__entry__` row.
        Neither normaliser writes one, so `provenance_cells` falls through to its `row is None`
        arm and the cell reads "Not recorded", which states that nothing TRACKS the field."""
        from assessments.artifacts.sheets.findings import (
            provenance_cells, remediation_accessor)
        subject = self.ha["fw-core-tpa-a"]
        fields = [("ha1_control_link_not_encrypted", True)]
        self.assertIsNone(
            FieldProvenance.objects.filter(
                content_type=ContentType.objects.get_for_model(HighAvailabilityConfig),
                object_id=subject.pk, field_name="__entry__").first())
        remediation_of = remediation_accessor(
            subject.provenance_for, dict(fields), None)
        self.assertEqual("Not recorded", provenance_cells(
            remediation_of("ha1_control_link_not_encrypted"), stored=True)[0])


class HaPairTests(HaPanoramaEstateMixin, TestCase):
    """Two rows for one pair, and why that is correct on THIS domain in particular."""

    def setUp(self):
        self.station, self.active, self.passive, self.standalone, self.snapshot = \
            self.build_estate()
        self.ha, self.panorama = self.build_rows(
            self.station, self.active, self.passive, self.standalone, self.snapshot)

    def test_both_models_are_unique_per_appliance(self):
        """Which is what makes two rows per pair the shape rather than a deduplication bug."""
        for model, name in ((HighAvailabilityConfig,
                             "unique_high_availability_config_per_appliance"),
                            (PanoramaRegistration,
                             "unique_panorama_registration_per_appliance")):
            with self.subTest(model=model.__name__):
                self.assertIn(name, [c.name for c in model._meta.constraints])

    def test_the_ha_role_column_tells_the_two_members_apart(self):
        """Without it two rows of one pair read as a duplicate a customer cannot reconcile
        against the device list. It is the SECOND column of the subject block, next to the
        appliance it qualifies."""
        read = dict(
            (column[0], column[3])
            for column in presentation.HIGH_AVAILABILITY_SUBJECT)["HA role"]
        self.assertEqual("Active", read(self.ha["fw-core-tpa-a"], None))
        self.assertEqual("Passive", read(self.ha["fw-core-tpa-b"], None))
        self.assertEqual("Standalone", read(self.ha["pan-fw-201"], None))

    def test_the_pair_s_two_ha_rows_are_not_expected_to_agree(self):
        """Stage 5 says so in terms and stage 4 measured it: `group/mode` is present on
        fw-core-tpa-a and absent on fw-core-tpa-b. So collapsing the pair would not remove a
        duplicate, it would DISCARD A READING - and this is the HA domain, where a pair half
        assessed is the failure the controls exist to catch."""
        self.assertEqual(HighAvailabilityConfig.MODE_ACTIVE_PASSIVE,
                         self.ha["fw-core-tpa-a"].ha_mode)
        self.assertEqual("", self.ha["fw-core-tpa-b"].ha_mode)

    def test_the_pair_s_two_management_channel_rows_do_agree(self):
        """The other half of the same claim, and the reason the HA tab's warning is not a general
        one: `panorama-server-2`, written on one member alone, was present on BOTH twenty minutes
        later - carried there by the pair's configuration synchronisation with nothing ever
        addressed to the peer. Synchronisation is per PATH, not one fact about one pair."""
        self.assertEqual(self.panorama["fw-core-tpa-a"].panorama_server_secondary,
                         self.panorama["fw-core-tpa-b"].panorama_server_secondary)


class HaPanoramaTabTests(HaPanoramaEstateMixin, TestCase):
    """The built tables. Every row loop here asserts the table is not empty first."""

    @classmethod
    def setUpTestData(cls):
        seed_controls(PAN_HAP)

    def setUp(self):
        self.station, self.active, self.passive, self.standalone, self.snapshot = \
            self.build_estate()
        self.ha, self.panorama = self.build_rows(
            self.station, self.active, self.passive, self.standalone, self.snapshot)
        self.write_provenance(self.ha, self.panorama)

    def table(self, slug):
        """THE FINDING RUN IS THE TEST. `build_findings_table` LOADS findings; its only row-count
        guard compares what it built against what the DATABASE holds, so with none generated both
        sides are zero, nothing raises, the headings still come out right and every
        `for row in table.rows:` assertion passes over nothing. Called here rather than in
        `setUp` so the rest of the suite does not pay a finding run on every gate run."""
        from assessments.finding_run import regenerate_findings
        regenerate_findings()
        table = build_findings_table(DOMAIN_BY_SLUG[slug].spec, tested=ALL_TESTED_COLUMNS)
        self.assertTrue(table.rows, f"{slug}: ZERO ROWS - nothing asserted below is a measurement")
        return table

    def test_the_high_availability_column_order(self):
        """READ OFF THE BUILT TABLE AND NOT DERIVED, because nothing gates it and
        `auto_setting_columns` is all-or-nothing so no sheet option corrects it. The settings run
        baseline-clauses-in-clause-order per control, controls by `control_id`, and within a
        control the non-baseline queries ALPHABETICALLY BY QUERY NAME."""
        table = self.table("high-availability")
        self.assertEqual(
            ["Finding #", "Control ID", "Control", "Severity", "Severity basis", "Status",
             "Appliance", "HA role", "Monitoring state", "Second keepalive path",
             "HA1 encryption switch", "Fires when (failing condition)", "Provenance", "Template",
             "No live redundant peer", "HA pair enabled", "HA1 control link not encrypted",
             "HA configuration collected", "Control link exposure", "No second keepalive path",
             "HA monitoring watches nothing", "Matched queries", "Config collected (UTC)"],
            table.headers)

    def test_the_did_anybody_look_column_sits_between_the_assertion_and_the_grade(self):
        """PAN-HAP-002's four columns, and the one property of them worth a test of its own.
        `High-availability configuration not collected` sorts before both `Unencrypted control
        link ...` queries on `H` < `U`, so the column saying whether anyone COLLECTED the subtree
        lands between the column the control asserts on and the column its severity is graded by.
        Renaming either shipped query silently moves it."""
        fields = [f for f, _stored in tested_fields(
            HighAvailabilityConfig, Control.objects.get(control_id="PAN-HAP-002"))]
        self.assertEqual(["ha_enabled", "ha1_control_link_not_encrypted",
                          "ha_config_collected", "ha1_control_link_exposure"], fields)

    def test_the_panorama_column_order(self):
        """The baseline here is stage 5's SECOND assertion record - the hardening half, at `low` -
        because that is the tier stage 8 made baseline, so the hardening verdict is the first
        setting a customer reads and the redundancy half that stage 5 wrote FIRST arrives from
        the calibration above it."""
        table = self.table("panorama-settings")
        self.assertEqual(
            ["Finding #", "Control ID", "Control", "Severity", "Severity basis", "Status",
             "Appliance", "HA role", "Fires when (failing condition)", "Provenance", "Template",
             "Management channel not hardened", "Management estate assumed a pair",
             "Secondary Panorama server", "Matched queries", "Config collected (UTC)"],
            table.headers)

    def test_no_heading_on_either_tab_is_a_raw_field_name(self):
        """A heading lives in `setting_labels`, which FALLS BACK TO THE RAW FIELD NAME - so
        declaring a column without a label IS choosing to show a customer a database field name.
        `is_management_surface` headed a customer-facing column from the day PAN-MGT-003 shipped.
        NOTE what this does NOT establish: `render_node` consults `setting_labels` nowhere, so the
        `Fires when` cells beside these headings still read in Django field names."""
        for slug in ("high-availability", "panorama-settings"):
            with self.subTest(slug=slug):
                table = self.table(slug)
                raw = [h for h in table.headers if "_" in h]
                self.assertEqual([], raw, f"{slug} shows raw field name(s): {raw}")

    def test_the_reassuring_defaults_are_not_on_the_tab(self):
        """THE ROW THAT WOULD HAVE ARGUED AGAINST ITSELF. `link_monitoring_enabled` and
        `path_monitoring_enabled` are `BooleanField(default=True)` and the default is the
        DEVICE's: `show high-availability state` answers `enabled: yes` with `groups: null` on an
        appliance holding no monitoring node at all. PAN-HAP-004 fires on `ha_monitors_nothing`,
        so on its row those two cells would read `Yes` and `Yes` by default rather than by
        measurement, beside a verdict saying this firewall monitors nothing - and they would be
        the most reassuring cells on the row. Stage 5 marks both `presented`, which is a record
        of what a column is FOR and not an instruction.

        THERE IS NO HONEST COLUMN TO ADD: both are non-nullable with no `*_known` companion, so
        the model cannot express "we never asked" for them. `Monitoring state`, which IS on the
        tab, carries the same question with an explicit `unknown` member."""
        table = self.table("high-availability")
        self.assertNotIn("Link monitoring", table.headers)
        self.assertNotIn("Path monitoring", table.headers)
        self.assertIn("Monitoring state", table.headers)
        # And the switches are still reachable on the EXPLORER page, which is a reference view of
        # the whole node rather than a verdict beside a contradicting cell.
        self.assertIn("Link monitoring", cr.RESULTS["high-availability"].columns)
        self.assertIn("Path monitoring", cr.RESULTS["high-availability"].columns)

    def test_the_firing_row_says_which_monitoring_gap_it_is(self):
        """What the two columns above are replaced by, and why it is not merely a substitute:
        `enabled-with-no-group` and `neither-enabled` need OPPOSITE remediations - add a link
        group, versus turn both switches on AND add a group - and stage 8 shipped no band query
        for this control, so the SEVERITY does not carry the distinction either."""
        table = self.table("high-availability")
        rows = [row for row in table.rows
                if row[table.headers.index("Control ID")] == "PAN-HAP-004"]
        self.assertTrue(rows, "PAN-HAP-004 drew no row, so nothing below is a measurement")
        for row in rows:
            cells = dict(zip(table.headers, row))
            if cells["Appliance"] != "fw-core-tpa-a":
                continue
            self.assertEqual("Yes", cells["HA monitoring watches nothing"])
            self.assertEqual("enabled-with-no-group", cells["Monitoring state"])

    def test_the_encryption_switch_is_three_states_and_null_is_not_off(self):
        """NULL is the key being ABSENT from the configuration, which `(none)` says and `No`
        would not - and neither value means the link is encrypted, because the switch cannot take
        effect without an imported HA key and `validate full` refuses the commit without one. The
        heading deliberately is not the vendor's "Encryption Enabled" for that reason."""
        read = dict(
            (column[0], column[3])
            for column in presentation.HIGH_AVAILABILITY_SUBJECT)["HA1 encryption switch"]
        self.assertEqual("(none)", read(HighAvailabilityConfig(ha1_encryption_enabled=None), None))
        self.assertEqual("Yes", read(HighAvailabilityConfig(ha1_encryption_enabled=True), None))
        self.assertEqual("No", read(HighAvailabilityConfig(ha1_encryption_enabled=False), None))

    def test_the_pair_draws_two_rows_on_each_tab_and_the_standalone_one(self):
        """PAN-HAP-001 applies to every appliance - it has no applicability clause - so all three
        appliances draw a row, and the pair's two are two members rather than one duplicate."""
        table = self.table("high-availability")
        appliances = [row[table.headers.index("Appliance")] for row in table.rows
                      if row[table.headers.index("Control ID")] == "PAN-HAP-001"]
        self.assertEqual(["fw-core-tpa-a", "fw-core-tpa-b", "pan-fw-201"], sorted(appliances))

    def test_the_standalone_is_excluded_from_the_three_pair_controls(self):
        """By the applicability clause `ha_enabled equals true`, and NOT because it complied -
        the clause is satisfiable, being true on both pair members. An exclusion and not an
        inert clause."""
        table = self.table("high-availability")
        for control_id in ("PAN-HAP-002", "PAN-HAP-003", "PAN-HAP-004"):
            with self.subTest(control=control_id):
                appliances = [row[table.headers.index("Appliance")] for row in table.rows
                              if row[table.headers.index("Control ID")] == control_id]
                self.assertNotIn("pan-fw-201", appliances)
                self.assertEqual(["fw-core-tpa-a", "fw-core-tpa-b"], sorted(appliances))

    def test_the_provenance_cell_reads_both_answers_on_a_built_row(self):
        """End to end, through `build_rows` rather than through the hook directly."""
        table = self.table("high-availability")
        rows = [row for row in table.rows
                if row[table.headers.index("Control ID")] == "PAN-HAP-002"]
        self.assertTrue(rows, "PAN-HAP-002 drew no row")
        for row in rows:
            cells = dict(zip(table.headers, row))
            self.assertEqual("Local\nDerived", cells["Provenance"])

    def test_the_only_derived_clause_field_row_reads_derived_alone(self):
        """PAN-HAP-001's single clause field is declared derived, so its cell is one line. The
        contrast with the test above is what makes the branch visible."""
        table = self.table("high-availability")
        rows = [row for row in table.rows
                if row[table.headers.index("Control ID")] == "PAN-HAP-001"]
        self.assertTrue(rows, "PAN-HAP-001 drew no row")
        for row in rows:
            cells = dict(zip(table.headers, row))
            self.assertEqual("Derived", cells["Provenance"])


class HaPanoramaResultsRowTests(HaPanoramaEstateMixin, TestCase):
    """The explorer `row` lambdas over real rows. The shipped check asserts a row is the same
    LENGTH as its columns and cannot see what a cell says."""

    def setUp(self):
        self.station, self.active, self.passive, self.standalone, self.snapshot = \
            self.build_estate()
        self.ha, self.panorama = self.build_rows(
            self.station, self.active, self.passive, self.standalone, self.snapshot)

    def row_for(self, slug, obj):
        spec = cr.RESULTS[slug]
        row = spec.row(obj)
        self.assertEqual(len(spec.columns), len(row))
        return dict(zip(spec.columns, row))

    def test_every_query_field_is_in_the_search_registry(self):
        """Stored, searchable and REGISTERED are three different things, and a heading mapped to
        an unregistered field points the "build a query from these rows" button at a lookup that
        refuses itself or silently matches nothing."""
        for slug, compiler in (("high-availability", ha_compiler),
                               ("panorama-settings", panorama_compiler)):
            spec = cr.RESULTS[slug]
            for heading, field in spec.query_fields.items():
                with self.subTest(slug=slug, heading=heading):
                    self.assertIn(heading, spec.columns)
                    self.assertIn(field, compiler.FIELD_OPERATOR_REGISTRY)

    def test_the_nullable_switches_are_offered_by_no_query_field(self):
        """Not an omission: there is no is-null operator in this language, so a clause over a
        nullable boolean PASSES every appliance nobody read - the reassuring direction. The
        verdict columns fold them in at normalization with the firing direction preserved."""
        offered = set(cr.RESULTS["high-availability"].query_fields.values())
        for field in ("ha1_encryption_enabled", "config_sync_enabled", "state_sync_enabled",
                      "cluster_participation_enabled", "ha1_encryption_key_imported"):
            with self.subTest(field=field):
                self.assertNotIn(field, offered)
        offered = set(cr.RESULTS["panorama-settings"].query_fields.values())
        for field in ("secure_panorama_communication_enabled", "check_server_identity_enabled"):
            with self.subTest(field=field):
                self.assertNotIn(field, offered)

    def test_the_high_availability_row_says_what_was_not_collected(self):
        cells = self.row_for("high-availability", self.ha["fw-core-tpa-a"])
        self.assertEqual("fw-core-tpa-a", cells["Appliance"])
        self.assertEqual("yes", cells["HA pair enabled"])
        self.assertEqual("active-passive", cells["Mode"])
        self.assertEqual("yes", cells["Config collected"])
        # THE COLUMN THAT TELLS FOUR VERDICTS APART FROM FOUR FINDINGS. No collector issues
        # `show high-availability all`, so this is `no` on every appliance in every estate.
        self.assertEqual("no", cells["Runtime read collected"])
        self.assertEqual("not in the configuration", cells["HA1 encryption switch"])
        self.assertEqual("unencrypted-port-unknown", cells["Control link exposure"])
        self.assertEqual("Nothing", cells["Link groups"])
        self.assertEqual("not in the configuration", cells["Heartbeat backup"])

    def test_the_link_groups_cell_breaks_on_newlines(self):
        """The repository's multi-value cell rule, which
        `test_no_presentation_module_comma_joins_a_list` enforces by grepping
        `configuration_results.py` for `", ".join`. The COUNT leads because a populated group
        carrying no interface is configuration `validate full` accepts, so the names alone do
        not say whether anything is monitored."""
        row = self.ha["fw-core-tpa-a"]
        row.monitored_link_groups = ["uplinks", "core"]
        row.monitored_link_group_count = 2
        row.save()
        self.assertEqual("2 groups\nuplinks\ncore",
                         self.row_for("high-availability", row)["Link groups"])

    def test_an_absent_mode_key_is_a_reading_and_not_a_gap(self):
        """fw-core-tpa-b holds no `mode` key beside a partner that holds `active-passive`, and
        `group/mode` is a CHOICE NODE read as which child is present - so blank is what the
        device answered."""
        cells = self.row_for("high-availability", self.ha["fw-core-tpa-b"])
        self.assertEqual("-", cells["Mode"])
        self.assertEqual("yes", cells["HA pair enabled"])

    def test_the_two_monitoring_switches_read_yes_with_nothing_monitored(self):
        """The device's own implicit, shown on the EXPLORER page where it is a reference reading
        of the node rather than a reassurance beside a contradicting verdict. A reader who took
        these two for the answer would raise a gap the device denies."""
        cells = self.row_for("high-availability", self.ha["fw-core-tpa-a"])
        self.assertEqual("yes", cells["Link monitoring"])
        self.assertEqual("yes", cells["Path monitoring"])
        self.assertEqual("Nothing", cells["Link groups"])
        self.assertEqual("yes", cells["Monitors nothing"])

    def test_the_panorama_row_names_both_slots_and_the_assumption(self):
        cells = self.row_for("panorama-settings", self.panorama["fw-core-tpa-a"])
        self.assertEqual("20.185.152.225", cells["Panorama server"])
        self.assertEqual("192.0.2.1", cells["Secondary Panorama server"])
        # TRUE BY DEFAULT AND FALSE BY NOTHING: the answer lives on the station's own HA node,
        # which is out of assessment scope, so the heading says "assumed".
        self.assertEqual("yes", cells["Estate assumed a pair"])
        self.assertEqual("not in the configuration", cells["Secure Client Communication"])
        self.assertEqual("not in the configuration", cells["Check Server Identity"])

    def test_an_absent_second_slot_is_a_measured_reading(self):
        """An absent `panorama-server-2` asserts the firewall names NO secondary appliance, paid
        in both directions on fw-core-tpa-a against `show panorama-status` (commit jobs 540 and
        541), which gained and lost a `Panorama Server 2` block with it."""
        cells = self.row_for("panorama-settings", self.panorama["pan-fw-201"])
        self.assertEqual("-", cells["Secondary Panorama server"])
        self.assertEqual("yes", cells["Channel not hardened"])

    def test_the_explicit_none_branch_is_shown_as_stored(self):
        """`certificate-type/none` present with no text and an ABSENT key MEAN THE SAME THING and
        are different stored states - measured on this estate, where three appliances hold no key
        and pan-fw-201 holds the `none` branch. Both are printed as they stand rather than folded
        together, because the distinction is what stage 6 built that subject to prove."""
        self.assertEqual(
            "none",
            self.row_for("panorama-settings", self.panorama["pan-fw-201"])[
                "Device certificate type"])
        self.assertEqual(
            "-",
            self.row_for("panorama-settings", self.panorama["fw-core-tpa-a"])[
                "Device certificate type"])
