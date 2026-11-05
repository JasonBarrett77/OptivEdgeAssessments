"""The engineer-detail workbook, once it stopped being a script.

The layout was proven by building it against the lab over and over; what was never proven is
the part that only matters inside a long-running process. Two globals and a `SystemExit` were
harmless while the prototype built one workbook and exited, and are not harmless here:

* the anchor map was a module dict, so a second workbook inherited the first one's row
  numbers and linked to the WRONG ROW - silently
* the format caches were keyed by `id(workbook)`, and CPython reuses an address once an
  object is freed
* `SystemExit` derives from `BaseException`, so a guard would take a worker down rather than
  return an error

So these tests are mostly about isolation and refusal, not about layout.
"""

from __future__ import annotations

import contextlib
import datetime
import io
import re
import zipfile
from pathlib import Path

from django.db import connection
from django.test import SimpleTestCase, TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from assessments.artifacts import ArtifactBuildError, build_workbook
from assessments.artifacts import layout, workbook as workbook_module
from assessments.artifacts.context import WorkbookBuild
from assessments.finding_run import regenerate_findings
from assessments.models import LoginBannerFinding
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance,
    ApplianceGroup,
    LoginBanner,
    ManagementStation,
    Snapshot,
)

ARTIFACTS = Path(layout.__file__).resolve().parent


def sheet_names(content: bytes) -> list[str]:
    """The tab names, read from the file itself rather than from what built it."""
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        book = archive.read("xl/workbook.xml").decode("utf-8")
    return re.findall(r'<sheet name="([^"]+)"', book)


def shared_strings(content: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        return archive.read("xl/sharedStrings.xml").decode("utf-8")


class WorkbookBuildTests(TestCase):
    def test_it_builds_on_an_estate_with_nothing_in_it(self):
        """A fresh deployment, or one whose collection has not run. Every tab still draws."""
        content, reports = build_workbook()

        self.assertTrue(content.startswith(b"PK"))
        # 33 since 2026-10-12: the four per-kind security-profile views.
        # 34 since 2026-10-28, when the normalization coverage tab was added beside Coverage.
        # 36 later the same day: IKE Crypto and IKE Gateways, under Network > Network Profiles.
        # 38 on 2026-11-01: Virtual System Rule Posture, first in Policies, and Policy Rule
        # Settings, last in Device - stage 9 of `security-policy`, for the two models stage 8
        # minted. The second draws no rows, by design: its one control ships inactive.
        # 40 on 2026-11-02: IPSec Crypto and IPSec Tunnels, the phase-2 pair, between the two
        # phase-1 tabs in Network - stage 9 of `ipsec-crypto`.
        # 43 later on 2026-11-02: Device-ID Policy Match (Policies, beside Virtual System Rule
        # Posture), Security Zones (Network, FIRST in that category because that is where the
        # vendor puts a zone) and IoT Security (Device) - stage 9 of `device-id-iot`. THREE TABS
        # IN THREE CATEGORIES from one pipeline domain, which is why they are not adjacent.
        # 45 later on 2026-11-02: User-ID Collector and User-ID Discovery, adjacent in Device -
        # stage 9 of `user-id`. TWO tabs for a SIX-control domain: PAN-UID-001 and PAN-UID-005
        # report on Security Zones and Management Interface, tabs that already existed.
        # 47 later on 2026-11-02: Zone Protection (Network, LAST in that category - the vendor
        # puts Network Profiles last and Zone Protection last within it) and DoS Protection
        # Rules (Policies, LAST - PAN-OS's Policies rail puts the DoS rulebase at the tail) -
        # stage 9 of `zone-dos-protection`. TWO tabs for an EIGHT-control domain, and they are
        # not adjacent: PAN-ZON-001 reports on Security Zones and PAN-ZON-008 on Security
        # Profile, both of which already existed, and the two new subjects categorise into two
        # different PAN-OS categories.
        # 48 on 2026-11-02 by stage 9 of `file-data-filtering`. ONE tab for a FOUR-control domain:
        # PAN-FIL-001, -002 and -004 report onto Security Profile, which already drew them, and
        # only PAN-FIL-003's per-enforcement-point verdict needed a subject of its own.
        # 49 on 2026-11-02 by stage 9 of `url-filtering`. ONE tab for a SIX-control domain, and it
        # is Custom URL Category, placed in Objects BEFORE Security Profile: PAN-URL-001 to -005
        # all report onto Security Profile, which already drew them, and only PAN-URL-006's
        # subject - `integrations.CustomUrlCategory`, minted by stage 7 for this domain - needed a
        # tab of its own. That domain ships 32 queries, the most in its batch, and 31 of them
        # needed a results DESTINATION rather than a tab; the two are different surfaces.
        # 50 on 2026-11-02 by stage 9 of `decryption-profiles`. ONE tab for a SEVEN-control
        # domain, and it is Forward Proxy Signing, placed in DEVICE beside Certificates:
        # PAN-DCP-001 to -005 and -007 all report onto Security Profile, which already drew them,
        # and only PAN-DCP-006's subject - `integrations.DecryptionSettings`, minted by stage 7
        # for this domain - needed a tab of its own. `probe.surface_for` is what answered that per
        # control; the domain's 25 queries needed a results DESTINATION, which is a different
        # surface from a tab.
        # 53 on 2026-11-02 by stage 9 of `decryption-policy`. THREE tabs for a TEN-control
        # domain, which is the largest build of this shape so far and the first to put one
        # domain's tabs in TWO PAN-OS categories: Decryption Coverage and Decryption Rules in
        # Policies, over the two models that carry the policy, and SSL Decryption Exclusions in
        # Device, because the vendor keeps that object at Device > Certificate Management > SSL
        # Decryption Exclusion. `probe.surface_for` answered per control that all ten reached NO
        # tab beforehand. A FOURTH model of the domain gets no tab deliberately -
        # `SslDecryptionVendorExclusionOptOut` is named by no shipped query, so no finding of its
        # kind can exist - and the domain's 21 queries needed a results DESTINATION, which is a
        # different surface from a tab.
        # 56 on 2026-11-02 by stage 9 of `globalprotect-portal`. THREE tabs for a SIX-control
        # domain, and the first build whose tabs all land in ONE NEW rail GROUP: GlobalProtect
        # Portals, Portal Client Authentication and GlobalProtect Coverage, all three in Network
        # under the vendor's own `Network > GlobalProtect` group (help 11.2 p.997 enumerates its
        # eight screens). `probe.surface_for` answered per control that all six reached NO tab
        # beforehand, so every one of them needed both surfaces rather than only a results
        # destination. The third tab is SHARED FORWARD: `globalprotect-gateway`'s PAN-GPG-005
        # reports on the same model, so that domain inherits GlobalProtect Coverage.
        # 59 on 2026-11-02 by stage 9 of `globalprotect-gateway`. THREE tabs for a SEVEN-control
        # domain, ADDED TO the rail group the entry above created rather than making a new one:
        # GlobalProtect Gateways, Gateway Client Authentication and Gateway Agent Configuration,
        # all three in Network under `Network > GlobalProtect`. `probe.surface_for` answered per
        # control that SIX of the seven reached no tab beforehand and that PAN-GPG-005 already
        # reached GlobalProtect Coverage - the tab the entry above shared forward - so this domain
        # adds three tabs for six controls and inherits the seventh's.
        #
        # AND THE SIX ARE STILL UNEXERCISED, which this count cannot show and is worth knowing
        # beside it: no GlobalProtect gateway exists anywhere in the measured estate, so the rows
        # these three tabs were designed against were RECONSTRUCTED. The tabs are real; the
        # measurement behind six of the seven controls is not.
        # 63 on 2026-11-02 by stage 9 of `saas-security`. FOUR tabs for a FIVE-control domain,
        # and the first build to put one domain's tabs in THREE PAN-OS categories: SaaS
        # Application Policy in Policies, Sanctioned Applications and SaaS URL Filtering Posture
        # in Objects, and App-ID Cloud Engine in Device. That is required rather than untidy -
        # an application's approval tag, a URL Filtering profile, a security rulebase and a
        # device-wide service switch live in four different places in the product, and an
        # assessor sent to the wrong one would not find the object. `probe.surface_for` answered
        # per control that all five reached NO tab beforehand.
        #
        # ONE OF THE FOUR DRAWS ROWS ONLY ON A RECONSTRUCTED ESTATE, which this count cannot
        # show and is worth knowing beside it: PAN-SAS-005's applicability clause excludes every
        # appliance in the measured lab, because all three report `license_check_failed` - no
        # SaaS Security Inline subscription - so App-ID Cloud Engine is an EMPTY tab on the real
        # estate. The rows it was designed against came from a seeded estate in which the
        # engine's operational read is absent rather than unlicensed.
        # 66 on 2026-11-02 by stage 9 of `platform-lifecycle`. THREE tabs for a SIX-control
        # domain, and the other three controls can never have one: PAN-PLT-001, -003 and -005
        # are discharged `engineer_answers` by stage 5, compile no query and have no catalog
        # entry at all, so there is no control type to draw a tab for. `probe.surface_for`
        # answered per control that all three of the remaining ones reached NO tab beforehand.
        #
        # ALL THREE DRAW ROWS ON THE MEASURED ESTATE, which is unusual in this list and is
        # because every subject of the domain is a device-wide singleton: four appliances give
        # four rows of each model, and eleven of the twelve carry a finding. TWO OF THE THREE
        # REQUIRED AN ESTATE THE COMMITTED SEEDER DOES NOT BUILD, which this count cannot show:
        # PAN-PLT-002 and PAN-PLT-004 read `show system info` and `request license info`, and
        # `print_findings_table` builds configuration snapshots only - see the stage 9 artifact.
        # 67 on 2026-11-03 by stage 9 of `updates`. ONE tab for FOUR controls, which is the most
        # concentrated shape in the pipeline so far and the reverse of the entry above: PAN-UPD-001,
        # -002, -004 and -005 all report on `integrations.ContentUpdateSchedule`, so they share one
        # tab, one rail item, one results page and one findings domain. The other two controls can
        # never have one - PAN-UPD-003 is discharged `engineer_answers` and PAN-UPD-006
        # `not_in_configuration` plus `engineer_answers`, and neither is in `seed.json` at all.
        # `probe.surface_for` answered per control that all four reached NO tab beforehand.
        #
        # THE TAB DRAWS ELEVEN ROWS ON THE MEASURED ESTATE, over four appliances, and the estate is
        # the committed seeder's own: all 20 of this domain's stage 6 subjects are CONFIGURATION
        # reads with no `op://` among them, so P470 does not apply and the normalised columns were
        # checked field by field against stage 6's `verified.read_back` before any row was read.
        # 67 -> 69 on 2026-11-03: stage 9 of `ha-panorama` added `High Availability` and
        # `Panorama Settings` - two tabs over two models, two specs in `sheets/objects.py` each
        # registered with `_object_domain` (P465). Both literals in this file were bumped in one
        # edit and both numbers were read off the failure rather than off a brief.
        # 69 -> 74 on 2026-11-03: stage 9 of `network-hardening` added FIVE tabs over five
        # control types - `Interfaces`, `Session Settings`, `DHCP Interfaces`,
        # `Tunnel Inspection` and `Routing Adjacencies` - which is the largest single addition
        # this literal has taken. They land in THREE PAN-OS categories rather than one, which no
        # earlier stage 9 domain has done. Both literals in this file were bumped in one edit and
        # both numbers were read off the failure rather than off a brief.
        # 74 -> 76 on 2026-11-03: stage 9 of `logging` added TWO tabs over two models stage 7
        # minted for that domain - `Syslog and Email Destinations` over
        # `integrations.LogServerTarget` (Device > Server Profiles > Syslog / Email) and
        # `Virtual System Log Forwarding` over `integrations.VsysLogForwarding` (Objects > Log
        # Forwarding). Its other eight controls joined an EXISTING tab, PAN-MGT-011's `Logging
        # and Reporting Settings`, which is why ten controls add two tabs and not three.
        # 77 -> 79 on 2026-11-03, BOTH literals bumped in one edit: `device-services`' two new
        # tabs, `DNS Settings` and `Service Routes`. They are NOT adjacent, although both belong
        # to one pipeline domain and both sit on one vendor screen (Device > Setup > Services):
        # `finding_run.GENERATORS` runs management resolvers at 12 and management service paths at
        # 17, with four other domains' control types between them, and within a category this list
        # takes that order. `domains.py` records both placements and the gap. The domain's other
        # THREE tabs - `NTP`, `SNMP` and `System Identity` - already existed, so nine controls add
        # two tabs and not five; what this stage owed those three was sixteen column headings.
        # 79 -> 81 on 2026-11-03, BOTH literals bumped in one edit: stage 9 of
        # `management-services` added TWO tabs over the two models that domain's own stage 7/8
        # minted and nothing had ever queried - `Management Plane Addressing` over
        # `integrations.ManagementPlaneAddressing` (Device > Setup > Interfaces) and
        # `Cryptographic Operational Mode` over `integrations.ApplianceOperationalMode`, whose
        # rail `where` names the web interface STATUS BAR because the vendor names no screen that
        # displays the value. Both sit between `DNS Settings` and `Service Routes`, which is
        # `finding_run.GENERATORS` order: management plane addressing is 15 and appliance
        # operational mode 16, between management resolvers at 12 and management service paths at
        # 17. THIRTEEN controls add two tabs because SIX of this domain's eight tabs already
        # existed - more than any other domain has inherited - and what this stage owed those six
        # was fourteen column headings, four `choices` readers and three provenance cells.
        # THIS WAS THE LAST DOMAIN OF THE 28, so `AWAITING_PRESENTATION` is now empty.
        self.assertIn("Summary: 81 tabs linked, 0 findings in total", reports[0])

    def test_the_summary_is_the_first_tab(self):
        names = sheet_names(build_workbook()[0])

        self.assertEqual(names[0], "Summary")
        # 29 findings tabs plus the Summary. Coverage joined them on 2026-10-02 and
        # WildFire settings on 2026-10-09.
        # 34 since 2026-10-12: Summary plus the four per-kind profile views.
        # 35 since 2026-10-28, when the normalization coverage tab was added beside Coverage.
        # 37 later the same day: IKE Crypto and IKE Gateways.
        # 39 on 2026-11-01: Virtual System Rule Posture and Policy Rule Settings.
        # 41 on 2026-11-02: IPSec Crypto and IPSec Tunnels.
        # 44 later on 2026-11-02: Device-ID Policy Match, Security Zones and IoT Security.
        # 46 later on 2026-11-02: User-ID Collector and User-ID Discovery.
        # 48 later on 2026-11-02: Zone Protection and DoS Protection Rules.
        # 49 later on 2026-11-02: Data Filtering Posture. `file-data-filtering` adds ONE tab for
        # four controls - its other three report onto the Security Profile tab, which already drew
        # them before that stage ran.
        # 50 later on 2026-11-02: Custom URL Category. `url-filtering` adds ONE tab for six
        # controls - its other five report onto the Security Profile tab, which already drew them.
        # 51 later on 2026-11-02: Forward Proxy Signing. `decryption-profiles` adds ONE tab for
        # seven controls - its other six report onto the Security Profile tab, which already drew
        # them. NOTE FOR THE NEXT RUN: this literal and the one above are TWO separate assertions
        # in this file and the second fails only once the first is fixed, so a run that bumps one
        # and re-runs sees a single failure and can believe it is done.
        # 54 later on 2026-11-02: Decryption Coverage, Decryption Rules and SSL Decryption
        # Exclusions. `decryption-policy` adds THREE tabs for ten controls - no PAN-DEC control
        # reached any existing tab, measured per control with `probe.surface_for` - and they are
        # not adjacent in this list: two categorise as Policies and one as Device, so the
        # Summary's category order splits them. The note above still holds and now cost this run
        # nothing: both literals were bumped together.
        # 57 later on 2026-11-02: GlobalProtect Portals, Portal Client Authentication and
        # GlobalProtect Coverage. `globalprotect-portal` adds THREE tabs for six controls - no
        # PAN-GPP control reached any existing tab, measured per control with
        # `probe.surface_for` - and unlike the three above they ARE adjacent, because all three
        # categorise as Network. The note above still holds and again cost nothing: both
        # literals were bumped together.
        #
        # "Portal Client Authentication" AND NOT "GlobalProtect Portal Client Authentication",
        # which is what that tab wanted to be called: this list is Excel's worksheet names,
        # capped at 31 characters, and the longer title truncated to "GlobalProtect Portal
        # Authentica" in the book while the live page kept all of it. `probe.surface_for` prints
        # that truncation, which is how it was caught before it shipped.
        #
        # 60 on 2026-11-02 by stage 9 of `globalprotect-gateway`, and all three of its titles were
        # counted against the same cap before they were chosen: "GlobalProtect Gateways" (22),
        # "Gateway Client Authentication" (29) and "Gateway Agent Configuration" (27). The middle
        # one made the same trade the portal tab above made - "GlobalProtect Gateway Client
        # Authentication" is 42 - and "Client Authentication" is the vendor's own sub-heading for
        # exactly that table (help 11.2 p.1046), so what was dropped is the product name and not
        # the thing's own word.
        #
        # 64 on 2026-11-02 by stage 9 of `saas-security`: "Sanctioned Applications" (23), "SaaS
        # URL Filtering Posture" (26), "SaaS Application Policy" (23) and "App-ID Cloud Engine"
        # (19), all four counted against the 31-character cap before they were chosen and none
        # truncated. They are NOT adjacent in this list and cannot be: the four subjects
        # categorise as Policies, Objects, Objects and Device, so the Summary's category order
        # puts them in three separate blocks. That is required rather than untidy - the four
        # live at four different addresses in the product.
        #
        # THE NOTE ABOVE ABOUT THE TWO LITERALS IS STILL TRUE AND THIS RUN PAID IT. Both were
        # bumped, but not together: the first was bumped from the workbook build's own reported
        # count and this one was missed, so the suite came back with exactly one new failure and
        # it read like an unrelated regression. The cheap check is to grep this file for the old
        # number before re-running, not after.
        # 67 on 2026-11-02 by stage 9 of `platform-lifecycle`: "Installed Content" (17),
        # "Licenses" (8) and "Alarm Settings" (14), all three counted against the
        # 31-character cap before they were chosen and none truncated. All three subjects are
        # Device settings, so unlike the four above they DO land in one block - between
        # "IoT Security" and "User-ID Collector", which is `finding_run.GENERATORS` order.
        #
        # AND THE NOTE ABOVE WAS READ BEFORE RE-RUNNING RATHER THAN AFTER: both literals were
        # grepped out of this file and bumped in one edit, which is what that paragraph asks
        # the next run to do.
        # 68 on 2026-11-03 by stage 9 of `updates`: "Dynamic Update Schedule" (23 characters,
        # counted against the 31-character Excel cap before it was chosen and not truncated), ONE
        # tab carrying FOUR controls. It sits between "Licenses" and "Installed Content", which is
        # `finding_run.GENERATORS` order - licence inventory, content update schedule, firewall
        # content streams - and that file's own comment carries the reader's argument for the second
        # adjacency: this subject is the configured CAUSE of stale content and PAN-PLT-002's streams
        # are the runtime SYMPTOM.
        #
        # BOTH LITERALS WERE GREPPED OUT OF THIS FILE AND BUMPED IN ONE EDIT, which is what the
        # paragraph above asks for, and the numbers were read off the file rather than off a brief
        # that quoted them one run stale.
        # 68 -> 70 on 2026-11-03, the second of the two literals, same edit: `ha-panorama`'s two
        # tabs. They sit between "System Identity" and "Management Interfaces", which is
        # `finding_run.GENERATORS` order - that tuple runs management service paths, high
        # availability, panorama registration, management interface - read off the finding run's
        # own `by_kind` ordering rather than assumed.
        # 70 -> 75 on 2026-11-03, the second of the two literals, same edit: `network-hardening`'s
        # five tabs. They do NOT sit in one block, because the domain spans three categories -
        # `Tunnel Inspection` last in Policies, `Interfaces` FIRST in Network with
        # `Routing Adjacencies` and `DHCP Interfaces` after the zones tab, and `Session Settings`
        # first in Device. Two of those placements follow the vendor's rail and two follow
        # `finding_run.GENERATORS`, which disagree here; `domains.py` records which and why at
        # each site.
        # 75 -> 77 on 2026-11-03, the second of the two literals, same edit: `logging`'s two new
        # tabs. They are NOT beside each other, because the domain's three subjects categorise as
        # Objects and Device - `Virtual System Log Forwarding` sits in the Objects block after the
        # security-profile family and before Coverage, following the vendor's own Objects rail
        # (Help 11.2 p.213), and `Syslog and Email Destinations` sits in the Device block
        # immediately before `aaa-server-profiles`, following the vendor's own Server Profiles
        # order (Help 11.2 p.915). `domains.py` records both placements and the generator order
        # each one disagrees with.
        # 77 -> 79 on 2026-11-03, BOTH literals bumped in one edit: `device-services`' two new
        # tabs, `DNS Settings` and `Service Routes`. They are NOT adjacent, although both belong
        # to one pipeline domain and both sit on one vendor screen (Device > Setup > Services):
        # `finding_run.GENERATORS` runs management resolvers at 12 and management service paths at
        # 17, with four other domains' control types between them, and within a category this list
        # takes that order. `domains.py` records both placements and the gap. The domain's other
        # THREE tabs - `NTP`, `SNMP` and `System Identity` - already existed, so nine controls add
        # two tabs and not five; what this stage owed those three was sixteen column headings.
        # 79 -> 81 on 2026-11-03, BOTH literals bumped in one edit: stage 9 of
        # `management-services` added TWO tabs over the two models that domain's own stage 7/8
        # minted and nothing had ever queried - `Management Plane Addressing` over
        # `integrations.ManagementPlaneAddressing` (Device > Setup > Interfaces) and
        # `Cryptographic Operational Mode` over `integrations.ApplianceOperationalMode`, whose
        # rail `where` names the web interface STATUS BAR because the vendor names no screen that
        # displays the value. Both sit between `DNS Settings` and `Service Routes`, which is
        # `finding_run.GENERATORS` order: management plane addressing is 15 and appliance
        # operational mode 16, between management resolvers at 12 and management service paths at
        # 17. THIRTEEN controls add two tabs because SIX of this domain's eight tabs already
        # existed - more than any other domain has inherited - and what this stage owed those six
        # was fourteen column headings, four `choices` readers and three provenance cells.
        # THIS WAS THE LAST DOMAIN OF THE 28, so `AWAITING_PRESENTATION` is now empty.
        self.assertEqual(len(names), 82)

    def test_a_control_type_with_no_active_control_still_draws_its_tab(self):
        """It used to raise IndexError: the category came from the controls that LOADED, and
        deactivating the one control of a type left none to read it from."""
        seed_controls(["PAN-MGT-007"])
        from assessments.models import Control

        Control.objects.update(is_active=False)

        self.assertIn("Login Banner", sheet_names(build_workbook()[0]))


class WorkbookContentTests(TestCase):
    def setUp(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.artifact")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-artifact",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-artifact", hostname="fw-artifact")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        self.run = regenerate_findings().assessment_run

    def test_a_finding_reaches_its_tab_by_its_reference(self):
        finding = LoginBannerFinding.objects.get()
        content, _reports = build_workbook()

        self.assertIn(finding.reference, shared_strings(content))

    def test_the_appliance_it_is_about_is_named(self):
        content, _reports = build_workbook()

        self.assertIn("fw-artifact", shared_strings(content))


class WorkbookIsolationTests(TestCase):
    """Two workbooks in one process must not share anything. This is the whole reason the
    move was not a copy."""

    def test_anchors_do_not_survive_between_builds(self):
        first = WorkbookBuild(workbook=object())
        layout.register_row_anchor(first, "control", 7, "Controls", 5, 9)
        second = WorkbookBuild(workbook=object())

        self.assertIn(("control", 7), first.anchors)
        self.assertEqual(second.anchors, {})

    def test_a_format_belongs_to_one_workbook(self):
        class FakeWorkbook:
            def add_format(self, properties):
                return ("format", id(self), tuple(sorted(properties.items())))

        first = WorkbookBuild(workbook=FakeWorkbook())
        second = WorkbookBuild(workbook=FakeWorkbook())

        self.assertNotEqual(first.format("link", {"bold": True}),
                            second.format("link", {"bold": True}))
        self.assertEqual(first.format("link", {"bold": True}),
                         first.format("link", {"bold": True}))

    def test_the_module_holds_no_build_state(self):
        """The bug was invisible for as long as the process exited after one workbook."""
        source = (ARTIFACTS / "layout.py").read_text(encoding="utf-8")

        self.assertNotIn("ANCHORS", source)
        self.assertNotIn("id(workbook)", source)

    def test_building_twice_gives_two_good_workbooks(self):
        first, _ = build_workbook()
        second, _ = build_workbook()

        self.assertEqual(sheet_names(first), sheet_names(second))
        self.assertTrue(second.startswith(b"PK"))


class WorkbookGuardTests(TestCase):
    def test_a_finding_on_no_tab_refuses_the_build(self):
        """The guard that matters most: a workbook silently missing a finding is worse than
        no workbook, because it is the reference document."""
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.guard")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-guard",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-guard", hostname="fw-guard")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

        with self.assertRaises(ArtifactBuildError) as raised:
            workbook_module.check_every_finding_reached_a_tab([])

        self.assertIn("is on no tab", str(raised.exception))

    def test_tabs_out_of_the_summary_order_refuse_the_build(self):
        from assessments.artifacts.layout import SheetInfo

        out_of_order = [
            SheetInfo(title="a", description="", count="", category="Device",
                      by_severity={"high": 1}, report=""),
            SheetInfo(title="b", description="", count="", category="Policies",
                      by_severity={"high": 1}, report=""),
        ]

        with self.assertRaises(ArtifactBuildError):
            workbook_module.check_tabs_follow_the_summary(out_of_order)

    def test_no_guard_reaches_for_SystemExit(self):
        """It derives from BaseException: under a web server it takes the worker down, and a
        caller's `except Exception` never sees it."""
        offenders = [
            path.relative_to(ARTIFACTS)
            for path in sorted(ARTIFACTS.rglob("*.py"))
            # `raise SystemExit`, not the word - errors.py explains why it is gone.
            if "raise SystemExit" in path.read_text(encoding="utf-8")
        ]

        self.assertEqual(offenders, [])


class TimestampTests(TestCase):
    """Every timestamp column in the workbook is headed "(UTC)"."""

    def test_an_aware_timestamp_is_converted_rather_than_printed_as_it_stands(self):
        somewhere_else = datetime.timezone(datetime.timedelta(hours=-4))
        moment = datetime.datetime(2026, 9, 24, 8, 30, 0, tzinfo=somewhere_else)

        self.assertEqual(layout.utc(moment), "2026-09-24 12:30:00")

    def test_a_naive_timestamp_is_read_as_utc(self):
        """Which is where they come from - a `collected_at` Django stored in UTC - and not
        machine-local, which is what `astimezone` would have assumed."""
        moment = datetime.datetime(2026, 9, 24, 8, 30, 0)

        self.assertEqual(layout.utc(moment), "2026-09-24 08:30:00")

    def test_nothing_is_an_em_dash(self):
        self.assertEqual(layout.utc(None), layout.NONE)


class FindingsTableTests(TestCase):
    """The table both surfaces render.

    The workbook and the live findings pages are meant to match. The only way they stay
    matched is by being one table: everything that decides WHAT a row says lives in
    `build_findings_table`, and each surface only decides how to draw it.
    """

    def _table(self, spec=None, **kwargs):
        from assessments.artifacts import build_findings_table
        from assessments.artifacts.sheets import objects
        from assessments.models import Control

        return build_findings_table(
            spec or objects.SPEC_BY_TYPE[Control.ControlType.LOGIN_BANNER], **kwargs)

    def test_every_row_is_as_wide_as_the_columns(self):
        table = self._table()

        for row in table.rows:
            self.assertEqual(len(row), len(table.columns))

    def test_it_opens_with_the_finding_and_the_control(self):
        """One layout for every domain: which finding, which control, how bad, and why."""
        table = self._table()

        self.assertEqual(table.headers[:6], [
            "Finding #", "Control ID", "Control", "Severity", "Severity basis", "Status"])

    def test_a_surface_can_ask_for_provenance_the_workbook_tab_omits(self):
        """Jason, 2026-09-25: "can we add the provenance data, even if both presentation
        surfaces don't use it?"

        The policy tab passes `tested_columns=()` because its own columns already show every
        field its controls test. That is a decision about one TAB, not about the data, so a
        surface can ask for the provenance and the firing condition anyway.
        """
        from assessments.artifacts import ALL_TESTED_COLUMNS
        from assessments.artifacts.sheets import security_rules

        default = self._table(security_rules.SPEC)
        asked = self._table(security_rules.SPEC, tested=ALL_TESTED_COLUMNS)

        self.assertNotIn("Provenance", default.headers)
        self.assertIn("Provenance", asked.headers)
        self.assertIn("Fires when (failing condition)", asked.headers)

    def test_it_reports_the_domain_its_category_and_its_severities(self):
        table = self._table()

        self.assertEqual(table.title, "Login Banner")
        self.assertEqual(table.category, "Device")
        self.assertTrue(table.description)
        self.assertEqual(table.by_severity, {})

    def test_a_finding_becomes_exactly_one_row(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.table")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-table",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-table", hostname="fw-table")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        LoginBanner.objects.create(
            management_station=station, appliance=appliance, source_snapshot=snapshot,
            text="", acknowledgement_required=False)
        seed_controls(["PAN-MGT-007"])
        regenerate_findings()

        table = self._table()
        finding = LoginBannerFinding.objects.get()

        self.assertEqual(len(table.rows), 1)
        self.assertEqual(table.rows[0][0], finding.reference)
        self.assertEqual(table.by_severity, {finding.severity: 1})


class FiringConditionTests(TestCase):
    """"Fires when" is prose over a control's baseline query, and it is read by a client.

    It used to RAISE on an operator it had no phrasing for, which nothing noticed because the
    only tabs carrying that column used five of the twelve operators. Asking for it on every
    findings page surfaced two - `exactly` and `contains` - as 500s.
    """

    def test_every_operator_a_control_can_use_has_a_phrasing(self):
        """A test rather than a runtime check: this fires when an operator is ADDED, not when
        someone opens the page that happens to use it."""
        from assessments.artifacts.sheets.findings import (
            NEGATED_OPERATORS, OPERATORS, UNARY_OPERATORS)
        from assessments.search.registry import MODEL_REGISTRY

        available = {op
                     for entry in MODEL_REGISTRY.values()
                     for operators in entry["field_operators"].values()
                     for op in operators}
        phrased = set(OPERATORS) | set(UNARY_OPERATORS)

        self.assertEqual(sorted(available - phrased), [])
        # Negation is offered on every comparison, so a phrasing missing there reads as the
        # opposite of what the control asserts.
        self.assertEqual(sorted(set(OPERATORS) - set(NEGATED_OPERATORS)), [])

    def test_the_address_set_operators_say_what_the_spec_locked(self):
        """`equals` is whole-set equality and `exactly` is exact membership - different
        questions, and the names do not say which is which. The phrasings come from the locked
        meanings in docs/security-rule-search-spec.md."""
        from assessments.artifacts.sheets.findings import OPERATORS

        self.assertEqual(OPERATORS["equals"], "is exactly")
        self.assertEqual(OPERATORS["exactly"], "includes exactly")
        self.assertEqual(OPERATORS["intersects"], "overlaps")

    def test_an_unphrased_operator_prints_rather_than_raising(self):
        """A findings page must not vanish because one condition reads awkwardly."""
        from assessments.artifacts.sheets.findings import render_node
        from assessments.models import Control

        control = Control(control_id="PAN-TEST-009")
        rendered = render_node(
            control, {"field": "name", "op": "sounds_like", "value": "x"})

        self.assertEqual(rendered, "name sounds_like x")


class EveryDomainDrawsWithTheWholeCatalogTests(TestCase):
    """Every findings domain, with every control the catalog ships, on an empty estate.

    Two bugs got through the suite and onto the running app on 2026-10-05, both because no test
    combined those three things:

    * PAN-POL-002 tests `source_breadth_known`, a SEARCH field with no column behind it, and
      `build_findings_table` refuses a tested field the subject model can neither store nor
      compute - "A value held on related rows needs a value_reader on the sheet". 588 tests
      passed because each control test seeds only its own control, so nothing ever built the
      security-rules table with PAN-POL-002 present.
    * The Coverage tab inherited the appliance-scoped `subject_select_related` default, and its
      subject is an address object, which has no `appliance`. `test_coverage_controls` proved
      the findings GENERATE; nothing drew them.

    Neither needs a finding, an appliance or a snapshot - the field check iterates controls, and
    `select_related` is validated when the SQL is compiled, so an empty database raises both.
    That is what makes this test cheap enough to cover all of it.
    """

    def setUp(self):
        from assessments.tests._seed import seed_control, seed_specs
        self.seeded = [seed_control(spec) for spec in seed_specs().values()]
        self._build_subjects()

    def _build_subjects(self):
        """One subject for each of the two domains whose presentation was broken, because an
        EMPTY estate does not exercise the same code.

        Django skips `prefetch_related` entirely when a queryset returns no rows, so the
        Coverage tab's prefetch named two relations that do not exist on AddressObject - a
        rule has `source_address_refs`, an address object has
        `securityrulesourceaddressref_set` - and an empty-database test passed anyway. It was
        caught by rendering against the lab. These subjects put the rows back.
        """
        from optivedge_integrations.integrations.models import (
            AddressObject,
            EnforcementNode,
            EnforcementPoint,
            SecurityRule,
            SecurityRuleSourceAddressRef,
        )
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.domains")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-domains",
            group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-domains", hostname="fw-domains")
        point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        # Every enforcement point is shown on the Enforcement Points tab THROUGH a node, and
        # that tab refuses to build if one would vanish. A fixture without this is incomplete
        # rather than minimal.
        EnforcementNode.objects.create(
            management_station=station, appliance=appliance, enforcement_point=point)

        # PAN-POL-002: an allow rule broad enough to land in the critical band.
        rule = SecurityRule.objects.create(
            management_station=station, enforcement_point=point, source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL, effective_order=1, rule_position=1,
            name="rule-domains", action="allow", rule_type="universal",
            source_num_hosts=4_294_967_296, destination_num_hosts=None)
        # PAN-COV-001: an EDL a rule references and nothing ever collected.
        edl = AddressObject.objects.create(
            management_station=station, enforcement_point=point, source_snapshot=snapshot,
            config_source=SecurityRule.SOURCE_LOCAL, name="edl-domains",
            namespace_type="local_vsys", namespace_value="vsys1", precedence_rank=10,
            address_type=AddressObject.TYPE_EDL, is_edl=True, edl_list_type="ip",
            value="ip", normalized_value="ip")
        SecurityRuleSourceAddressRef.objects.create(
            security_rule=rule, raw_value=edl.name, position=0,
            ref_type=SecurityRuleSourceAddressRef.RefType.ADDRESS_OBJECT, address_object=edl)
        regenerate_findings()

    def test_the_two_domains_this_exists_for_actually_have_rows(self):
        """Guards the sweep below: without rows it degrades to the empty-estate check that
        already let a prefetch bug through."""
        from assessments.artifacts import ALL_TESTED_COLUMNS, build_findings_table
        from assessments.artifacts.domains import DOMAINS

        by_slug = {domain.slug: domain for domain in DOMAINS}
        for slug in ("security-rules", "coverage"):
            with self.subTest(domain=slug):
                table = build_findings_table(by_slug[slug].spec, tested=ALL_TESTED_COLUMNS)
                self.assertTrue(table.rows, f"{slug} rendered no rows")

    def test_the_controls_that_broke_it_are_actually_seeded(self):
        """Guards the tests below rather than the product. A seeder that produced nothing, or
        skipped a control type, would make them pass over an empty loop - so this names the
        three controls whose presence is the whole point rather than asserting a row count.
        """
        seeded = {control.control_id for control in self.seeded}
        for control_id in ("PAN-POL-002", "PAN-COV-001", "PAN-COV-002"):
            self.assertIn(control_id, seeded)
        self.assertGreater(len(seeded), 60, "the shipped catalog should hold dozens of controls")

    def test_every_domain_builds_its_findings_table(self):
        from assessments.artifacts import ALL_TESTED_COLUMNS, build_findings_table
        from assessments.artifacts.domains import DOMAINS

        self.assertTrue(DOMAINS)
        for domain in DOMAINS:
            with self.subTest(domain=domain.slug):
                build_findings_table(domain.spec, tested=ALL_TESTED_COLUMNS)

    def test_every_domain_builds_the_way_the_workbook_asks_for_it(self):
        """The pages pass `tested=ALL_TESTED_COLUMNS` and the workbook takes the spec's own
        columns, so the two surfaces do not exercise the same code."""
        from assessments.artifacts import build_findings_table
        from assessments.artifacts.domains import DOMAINS

        for domain in DOMAINS:
            with self.subTest(domain=domain.slug):
                build_findings_table(domain.spec)

    def test_the_whole_workbook_builds_with_every_control_active(self):
        content, _reports = build_workbook()
        self.assertTrue(content)


class DeferredPayloadTests(TestCase):
    """What the findings tabs decline to fetch.

    A joined row arrives whole, so a wide column on a joined model is paid for per ROW whether
    or not anything reads it. `Snapshot.payload` cost 1.75 GB on one tab that way before the
    snapshot left the join entirely; the `raw_*` payloads on the subjects are the same habit,
    smaller.

    The care here is in what is NOT deferred. Most JSONFields on these models are read - the
    SSH algorithm lists, bound interface names, exposed SNMP surfaces - and deferring one of
    those turns it into a query per row: slower than the problem it set out to fix, and silent.
    """

    def test_only_verbatim_vendor_payloads_are_deferred(self):
        """`raw_*`, which the query service boundary already forbids reading. A JSONField the
        tabs DO read must never appear here."""
        from assessments.artifacts import domains as artifact_domains
        from assessments.artifacts.sheets.findings import verbatim_payload_paths

        for domain in artifact_domains.DOMAINS:
            spec = domain.spec
            for control_type in spec.control_types:
                kind = spec.kind_for(control_type)
                with self.subTest(f"{domain.slug}/{kind.model.__name__}"):
                    for path in verbatim_payload_paths(kind, spec):
                        self.assertRegex(path.rsplit("__", 1)[-1], r"^raw_",
                                         f"{path} is deferred but is not a raw_* payload")

    def test_a_json_field_is_identified_by_the_model_and_not_by_its_name(self):
        """Both conditions are required. `raw_*` alone would defer a CharField called
        `raw_text`; JSONField alone would defer `ciphers` and cost a query per row."""
        import inspect

        from assessments.artifacts.sheets import findings as findings_module

        source = inspect.getsource(findings_module.verbatim_payload_paths)
        self.assertIn("JSONField", source)
        self.assertIn('startswith("raw_")', source)

    def test_deferring_adds_no_queries(self):
        """The failure this guards against. If a deferred field turns out to be read, Django
        fetches it lazily - correct output, one extra query per row, nothing raised. So each
        domain is built both ways and the counts must match.

        BOTH PATHS ARE WARMED FIRST. `ContentType.objects.get_for_model` caches per process, so
        whichever build runs first pays for it and looks one query worse. Measured without the
        warm-up this reported a +1 on all 23 domains - a constant offset, which is the shape of
        a cache miss and not of an N+1, since a lazy field would cost one query per ROW.

        Only the domains with findings in this fixture exercise it; the full check is run
        against lab data, where all 23 have rows and the counts are identical.
        """
        from unittest import mock

        from assessments.artifacts import ALL_TESTED_COLUMNS, build_findings_table
        from assessments.artifacts import domains as artifact_domains

        def count(spec, *, defer):
            whole = mock.patch(
                "assessments.artifacts.sheets.findings.verbatim_payload_paths",
                return_value=())
            with contextlib.nullcontext() if defer else whole:
                with CaptureQueriesContext(connection) as queries:
                    build_findings_table(spec, tested=ALL_TESTED_COLUMNS)
            return len(queries)

        for domain in artifact_domains.DOMAINS:
            with self.subTest(domain.slug):
                count(domain.spec, defer=True)
                count(domain.spec, defer=False)
                self.assertEqual(
                    count(domain.spec, defer=True), count(domain.spec, defer=False),
                    f"{domain.slug}: deferring changed the query count, so something reads a "
                    f"field it declines to fetch")


class RuleTabsDoNotQueryPerRowTests(TestCase):
    """The rule tabs cost the same number of queries for one rule as for three.

    Every threat-profile property on `SecurityRule` - `antivirus_blocks_malware` and its
    twenty-one siblings - walks `profile_verdicts`, and the rules spec did not prefetch it. So
    each one a cell read was a query: 134k across the five rule tabs on the lab, 2026-10-14,
    and 58 of the workbook's 61 seconds. Nothing failed, because `test_deferring_adds_no_queries`
    compares two builds of the SAME rows, and an N+1 both of them pay looks like agreement.

    A rule with NO profiles is the subject because every verdict is then NULL, which fires all
    eleven threat-profile controls and prints a line for each - every property is read.
    """

    def setUp(self):
        from optivedge_integrations.integrations.models import (
            EnforcementNode, EnforcementPoint, SecurityRule, SecurityRuleProfileVerdict)
        from assessments.models import Control
        from assessments.tests._seed import seed_specs

        seed_controls([cid for cid, spec in seed_specs().items()
                       if spec["control_type"] == Control.ControlType.SECURITY_RULE])
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.n1")
        group = ApplianceGroup.objects.create(
            management_station=station, name="g-n1", group_type=ApplianceGroup.TYPE_STANDALONE)
        appliance = Appliance.objects.create(
            management_station=station, appliance_group=group,
            serial_number="S-n1", hostname="fw-n1")
        self.point = EnforcementPoint.objects.create(
            management_station=station, appliance_group=group,
            vsys_name="vsys1", vsys_display_name="vsys1")
        EnforcementNode.objects.create(
            management_station=station, appliance=appliance, enforcement_point=self.point)
        self.snapshot = Snapshot.objects.create(
            management_station=station, appliance=appliance,
            source_type="show_merged_config", collected_at=timezone.now(), payload={})
        self.station = station
        self.SecurityRule, self.Verdict = SecurityRule, SecurityRuleProfileVerdict

    def add_rules(self, count):
        start = self.SecurityRule.objects.count()
        for order in range(start + 1, start + count + 1):
            rule = self.SecurityRule.objects.create(
                management_station=self.station, enforcement_point=self.point,
                source_snapshot=self.snapshot, config_source=self.SecurityRule.SOURCE_LOCAL,
                effective_order=order, rule_position=order, name=f"bare-{order}",
                action="allow", rule_type="universal")
            for assertion, _label in self.Verdict.ASSERTION_CHOICES:
                self.Verdict.objects.create(
                    security_rule=rule, assertion=assertion, profile_name="",
                    satisfied=None, detail="no profile is in force on this rule")
        regenerate_findings()

    def queries(self, spec):
        from assessments.artifacts import ALL_TESTED_COLUMNS, build_findings_table

        build_findings_table(spec, tested=ALL_TESTED_COLUMNS)  # warm the per-process caches
        with CaptureQueriesContext(connection) as captured:
            table = build_findings_table(spec, tested=ALL_TESTED_COLUMNS)
        return len(captured), len(table.rows)

    def test_query_count_does_not_grow_with_rules(self):
        from assessments.artifacts.domains import DOMAINS

        rule_domains = [domain for domain in DOMAINS
                        if domain.slug == "security-rules" or domain.slug.endswith("-by-rule")]
        self.assertEqual(len(rule_domains), 5)

        self.add_rules(1)
        one = {domain.slug: self.queries(domain.spec) for domain in rule_domains}
        self.add_rules(2)
        for domain in rule_domains:
            with self.subTest(domain.slug):
                (one_queries, one_rows) = one[domain.slug]
                three_queries, three_rows = self.queries(domain.spec)
                # Guards the comparison: tabs with no rows would agree on any code.
                self.assertGreater(three_rows, one_rows)
                self.assertEqual(three_queries, one_queries,
                                 f"{domain.slug} costs a query per row")

    def rule_domains(self):
        from assessments.artifacts.domains import DOMAINS

        return [domain for domain in DOMAINS
                if domain.slug == "security-rules" or domain.slug.endswith("-by-rule")]

    def test_the_rule_tabs_of_one_build_load_the_rules_once(self):
        """Six tabs report on security rules and each loaded every rule and its ten member sets
        again. Production, 2026-10-15: 12,188 rules, and most of the build's 3.3 million model
        instances were those copies - the queries were constant, so only time showed it."""
        from assessments.artifacts import build_findings_table

        self.add_rules(3)
        rule_table = re.compile(r'FROM "integrations_securityrule"(?:\s|$)')
        shared = WorkbookBuild(workbook=None).subjects
        loads = []
        for domain in self.rule_domains():
            with CaptureQueriesContext(connection) as captured:
                table = build_findings_table(domain.spec, subjects=shared)
            self.assertTrue(table.rows, domain.slug)
            loads.append(sum(bool(rule_table.search(q["sql"])) for q in captured))

        self.assertEqual(loads, [1] + [0] * (len(loads) - 1))

    def test_a_rule_is_drawn_once_per_tab_however_many_findings_it_has(self):
        """The subject cells read the rule and nothing about the finding, and were drawn per
        ROW: ten controls firing on one rule drew its Profiles cell ten times, each walking the
        rule's verdicts twenty-two times. That was the largest single cost in production."""
        from unittest import mock

        from assessments.artifacts import build_findings_table
        from assessments.artifacts.sheets import security_rules

        self.add_rules(2)
        domain = max(self.rule_domains(),
                     key=lambda d: len(build_findings_table(d.spec).rows))
        with mock.patch.object(security_rules, "profiles_in_force",
                               wraps=security_rules.profiles_in_force) as drawn:
            table = build_findings_table(domain.spec)

        self.assertGreater(len(table.rows), 2, "a rule must carry several findings here")
        self.assertEqual(drawn.call_count, 2)


class BulkProvenanceTests(TestCase):
    """Provenance is read from an index built up front, never per object in a row loop.

    `member_provenance` called `member.provenance_for("__entry__")` once per member, so the
    Management Interfaces tab issued 88 of its 96 queries one service and one permitted source
    at a time. It scaled with MEMBERS rather than with rows, which is why 15 rows could cost 96
    queries and why it stayed invisible: on the lab it was 0.026s.
    """

    def test_no_sheet_reads_provenance_one_object_at_a_time(self):
        """`provenance_for` is Integrations' per-object accessor and is right in a view that
        wants one answer. In a sheet it is a query per row, or per member of per row."""
        import ast

        # Parsed rather than grepped: the docstrings here NAME the call they replaced, and a
        # text match cannot tell an explanation from a reintroduction.
        offenders = []
        for path in sorted(Path(__file__).resolve().parent.parent.glob("artifacts/**/*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "provenance_for"):
                    offenders.append(f"{path.name}:{node.lineno}")

        self.assertEqual(
            offenders, [],
            "build provenance once with provenance_index/member_provenance_index instead: "
            f"{offenders}")

    def test_member_provenance_requires_the_index(self):
        """Taking it as an argument is what stops the per-member query coming back: there is no
        longer a version of this function that can look one up on its own."""
        import inspect

        from assessments.artifacts.sheets.findings import member_provenance

        self.assertIn("index", inspect.signature(member_provenance).parameters)


class RemediationProvenanceTests(SimpleTestCase):
    """Provenance answers WHERE TO GO AND CHANGE IT, not where a value came from.

    `read-template-provenance.md` states it: "Provenance answers **where do I go to change
    this**, not what a value's history is." A tested field often cannot answer that -
    `binding_count` on an unused interface management profile is derived, and a derived number
    has no location - but the object can, because the profile is defined somewhere.

    A WALK rather than a per-control declaration. Jason, 2026-10-05, on whether the control
    should name its source: "do we need that value defined, or a method? It seems that, for the
    most important question, we can get the answer from the provenance value closest to what
    we're measuring." Measured on lab data: the field answers 81% of findings and the object a
    further 10%, so 71 declarations would have bought nothing a rule does not.
    """

    def accessor(self, rows, stored, entry):
        from assessments.artifacts.sheets.findings import remediation_accessor

        return remediation_accessor(lambda field: rows.get(field), stored, entry)

    @staticmethod
    def row(kind, value=""):
        from optivedge_integrations.integrations.models import FieldProvenance

        return FieldProvenance(provenance_type=kind, raw_value=value)

    def test_the_fields_own_provenance_wins(self):
        field = self.row("template", "tpl-a")
        entry = self.row("local")
        resolved = self.accessor({"minimum_length": field}, {"minimum_length": True}, entry)

        self.assertIs(resolved("minimum_length"), field)

    def test_a_field_with_no_row_falls_through_to_the_object(self):
        entry = self.row("local")
        resolved = self.accessor({}, {"kind": True}, entry)

        self.assertIs(resolved("kind"), entry)

    def test_a_field_that_is_not_a_column_falls_through_to_the_object(self):
        """`binding_count` is a query name whose model attribute is `bound_interface_count`, so
        `tested_fields` reports it unstored. F-0078 is this case, and its answer is where the
        profile is defined."""
        entry = self.row("template", "ptpl_fw-core-tpa")
        resolved = self.accessor({}, {"binding_count": False}, entry)

        self.assertIs(resolved("binding_count"), entry)

    def test_derived_counts_as_no_answer(self):
        """`provenance_of` synthesises a DERIVED row for a declared computed column. That is
        true and useless here - a computed value has no location - so it must not block the
        walk. Without this the object is never reached for any derived field."""
        entry = self.row("local")
        resolved = self.accessor({"server_count": self.row("derived")},
                                 {"server_count": True}, entry)

        self.assertIs(resolved("server_count"), entry)

    def test_nothing_anywhere_stays_nothing(self):
        """No invention. A settings node carries no `__entry__`, and a derived field on one has
        no location to offer - which is honest rather than a gap to paper over."""
        resolved = self.accessor({}, {"timezone_is_utc": True}, None)

        self.assertIsNone(resolved("timezone_is_utc"))

    def test_pan_os_default_is_an_answer_and_is_not_walked_past(self):
        """"Nothing configured this" is a real statement about the field. Walking past it would
        replace a measured fact with the object's location and lose the reason the finding
        fired."""
        default = self.row("pan_os_default", "0")
        resolved = self.accessor({"failed_attempts": default},
                                 {"failed_attempts": True}, self.row("local"))

        self.assertIs(resolved("failed_attempts"), default)


class RemediationWiringTests(TestCase):
    """The walk has to reach both cells that answer "where", not just one."""

    def test_the_template_column_does_not_short_circuit_on_stored(self):
        """It read `provenance_of(field) if stored else None`, so a derived field named no
        template even when the object was pushed by one. Measured on the lab: F-0080's Template
        cell was blank and is now `ptpl_fw-core-tpa`."""
        import inspect

        from assessments.artifacts.sheets import findings as findings_module

        source = inspect.getsource(findings_module._default_template_cell)
        self.assertNotIn("if stored else None", source)

    def test_source_columns_receive_the_walking_accessor(self):
        """`source_columns` are documented as "saying WHERE a pushed value came from", so they
        get the accessor that can answer it."""
        import inspect

        from assessments.artifacts.sheets import findings as findings_module

        source = inspect.getsource(findings_module.build_rows)
        self.assertIn("read(policy, remediation_of, shown)", source)
        self.assertIn("remediation_accessor(provenance_of", source)
