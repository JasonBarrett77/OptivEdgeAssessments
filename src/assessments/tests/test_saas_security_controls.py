"""The five SaaS controls, against the configuration stage 6 of the `saas-security` domain built.

EVERY PAYLOAD HERE IS A READBACK AND NOT AN INVENTION. The application-tag entries, URL Filtering
profiles, application filters, SaaS tenant lists and security rules below are transcribed from
`stage6-saas-security.json`'s `verified.read_back` blocks - what `type=config&action=show`
returned through Panorama after the commit that created each one, on 2026-10-27. Stage 6 wrote
its expected verdict for each one BEFORE any query existed, which is what makes this a test of
the queries rather than a restatement of them.

THREE OF THE FOUR SUBJECTS ARE VERDICTS OVER AN ENFORCEMENT POINT and not entries of an object,
so a finding's subject is a PARTITION and several stage 6 subjects land on one finding row. That
is the shape to keep in mind reading these assertions: `vsys1` of pan-fw-201 carries ten of stage
6's subjects and produces at most one finding per control.

WHAT A PER-RECORD EXPECTATION CANNOT ASSERT. Stage 6 grades one stage 3 ASSERTION RECORD at a
time; a finding exists per CONTROL. PAN-SAS-001 carries two records that disagree about
`vsys1` of fw-core-tpa-b - the first passes, the second fires - and the union is one finding.
PAN-SAS-004 is worse: its two records name DIFFERENT MODELS, so the control can carry queries for
one of them and `test_the_attribute_surface_of_pan_sas_004_has_no_query` holds that silence in
place rather than letting it read as coverage.

EVERY RULE STAGE 6 WROTE IS `disabled: yes` and this domain's derivation counts a disabled rule.
The normalizer that writes these verdicts records that decision and records that it is probably
wrong; these tests pin the behavior the estate was graded against, not a judgment about it.
"""

from __future__ import annotations

from django.test import TestCase
from django.utils import timezone

from assessments.cloud_app_engine_findings import generate_cloud_app_engine_findings
from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import (
    CloudAppEngineFinding,
    Control,
    SaasApplicationPolicyPostureFinding,
    SaasUrlFilteringPostureFinding,
    SanctionedApplicationMarkingFinding,
)
from assessments.saas_application_policy_posture_findings import (
    generate_saas_application_policy_posture_findings,
)
from assessments.saas_url_filtering_posture_findings import (
    generate_saas_url_filtering_posture_findings,
)
from assessments.sanctioned_application_marking_findings import (
    generate_sanctioned_application_marking_findings,
)
from assessments.models import AssessmentRun
from assessments.tests._seed import seed_controls
from optivedge_integrations.integrations.models import (
    Appliance, ApplianceGroup, CloudAppEngineSetting, EnforcementPoint, ManagementStation,
    Snapshot)
from optivedge_integrations.integrations.platforms.pan_os.normalization.saas_security import (
    normalize_cloud_app_engine, normalize_saas_security)

SAAS_CONTROLS = ["PAN-SAS-001", "PAN-SAS-002", "PAN-SAS-003", "PAN-SAS-004", "PAN-SAS-005"]
TYPE_BY_CONTROL = {
    "PAN-SAS-001": Control.ControlType.SANCTIONED_APPLICATION_MARKING,
    "PAN-SAS-002": Control.ControlType.SAAS_URL_FILTERING_POSTURE,
    "PAN-SAS-003": Control.ControlType.SAAS_APPLICATION_POLICY_POSTURE,
    "PAN-SAS-004": Control.ControlType.SAAS_URL_FILTERING_POSTURE,
    "PAN-SAS-005": Control.ControlType.CLOUD_APP_ENGINE_SETTING,
}

#: The two web categories PAN-SAS-004 is about, as stage 6 wrote them into every category list.
CATS = ["online-storage-and-backup", "personal-sites-and-blogs"]

#: `show cloud-appid connection-to-cloud`, verbatim from the 11.2 appliance. The wording moves
#: with the build - 11.1.13-h3 names one licence where this names two - and every condition in it
#: is a failing one, which is the state of every appliance in this lab.
ACE_REPLY = (
    "Summary of ACE grpc client:\n"
    "ACE Error: License check failed. Check if SaaS license or Ai Access license is installed "
    "and active\n"
    "Cloud connection: failed\n"
    "Device cert status: Not installed, Invalid or Not pushed to daemons\n"
)

#: The same reply with the LICENCE SATISFIED and the certificate still missing. Not a readback -
#: no appliance in this lab can reach it - and it exists for one purpose: to prove PAN-SAS-005's
#: applicability clause is an EXCLUSION rather than an inert control. Without it, "no finding on
#: any appliance" and "a control that can never fire" are the same observation.
ACE_REPLY_LICENSED = (
    "Summary of ACE grpc client:\n"
    "Cloud connection: failed\n"
    "Device cert status: Not installed, Invalid or Not pushed to daemons\n"
)

#: The `dropbox` container at /config/predefined/application. THE FUNCTION TAG IS WHAT SEPARATES A
#: FUNCTION CHILD from an ordinary sub-application of a container, and the brackets are part of
#: the stored string: `[Uploading]`, not `Uploading`. `dropbox-base` carries `[Web App]` alone,
#: which is what keeps the base application out of the population.
PREDEFINED = {"application": {"entry": [
    {"@name": "dropbox-base", "application-container": "dropbox",
     "tag": {"member": ["[Web App]"]},
     "use-applications": {"member": ["ssl", "web-browsing", "google-base", "grpc"]}},
    {"@name": "dropbox-uploading", "application-container": "dropbox",
     "tag": {"member": ["[Uploading]", "[Web App]"]},
     "use-applications": {"member": "dropbox-base"}},
    {"@name": "dropbox-downloading", "application-container": "dropbox",
     "tag": {"member": ["[Downloading]", "[Web App]"]},
     "use-applications": {"member": "dropbox-base"}},
    {"@name": "dropbox-delete", "application-container": "dropbox",
     "tag": {"member": ["[Deleting]", "[Web App]"]},
     "use-applications": {"member": "dropbox-base"}, "parent-app": "dropbox-base"},
]}}


def members(*values):
    """A `<member>` list as xmltodict delivers it: a bare string for one, a list for several."""
    return {"member": list(values) if len(values) > 1 else values[0]}


def rule(name, application, action, **extra):
    """One security rule as stage 6 read it back. EVERY ONE OF THEM IS `disabled: yes`."""
    entry = {"@name": name, "disabled": "yes", "from": members("any"), "to": members("any"),
             "source": members("any"), "destination": members("any"),
             "service": members("application-default"),
             "application": members(*application), "action": action}
    entry.update(extra)
    return entry


def profile(name, **content):
    return {"@name": name, **content}


#: Seven partitions of fw-core-tpa-b, from stage 6 subjects sas6-01 to sas6-18. The appliance has
#: nine; the two omitted carry none of stage 6's subjects, and `appliance_is_multi_vsys` is true
#: either way.
TPA_B = {
    "vsys1": {
        "application-tag": {"entry": [{"@name": "dropbox-base", "tag": members("Sanctioned")}]},
        "profiles": {"url-filtering": {"entry": [profile("oep-sas6-url-blk",
                                                         block=members(*CATS))]}},
        "application-filter": {"entry": [{"@name": "oep-sas6-filt-min", "is-saas": "yes"}]},
        "rulebase": {"security": {"rules": {"entry": [
            rule("oep-sas6-r-deny", ["dropbox-uploading"], "deny")]}}},
    },
    "vsys2": {
        # A POPULATED CONTAINER WHOSE ENTRY CARRIES NO MARKING: the collection is non-empty and
        # the marked count is nil. A truthiness test on the container splits those the wrong way,
        # which is why the column is a count.
        "application-tag": {"entry": [{"@name": "dropbox-downloading"}]},
        "profiles": {"url-filtering": {"entry": [profile("oep-sas6-url-ovr",
                                                         override=members(*CATS))]}},
        "rulebase": {"security": {"rules": {"entry": [
            rule("oep-sas6-r-drop", ["dropbox-uploading"], "drop")]}}},
    },
    "vsys3": {
        "profiles": {"url-filtering": {"entry": [
            profile("oep-sas6-url-cont", **{"continue": members(*CATS)})]}},
        "rulebase": {"security": {"rules": {"entry": [
            rule("oep-sas6-r-rstc", ["dropbox-uploading"], "reset-client")]}}},
    },
    "vsys5": {
        "profiles": {"url-filtering": {"entry": [profile("oep-sas6-url-alrt",
                                                         alert=members(*CATS))]}},
        "rulebase": {"security": {"rules": {"entry": [
            rule("oep-sas6-r-rsts", ["dropbox-uploading"], "reset-server")]}}},
    },
    "vsys6": {
        "profiles": {"url-filtering": {"entry": [profile("oep-sas6-url-alw",
                                                         allow=members(*CATS))]}},
        "rulebase": {"security": {"rules": {"entry": [
            rule("oep-sas6-r-rstb", ["dropbox-uploading"], "reset-both")]}}},
    },
    "vsys7": {
        # A profile that EXISTS, is readable, says nothing about any web category and carries no
        # `http-header-insertion` child. Two stage 6 subjects in one entry.
        "profiles": {"url-filtering": {"entry": [
            profile("oep-sas6-url-nohhi", **{"log-http-hdr-referer": "yes"})]}},
        "rulebase": {"security": {"rules": {"entry": [
            rule("oep-sas6-r-allow", ["dropbox-uploading"], "allow")]}}},
    },
    # NO url-filtering container and NO rules container: two stage 6 subjects, both absences.
    "vsys10": {},
}

FW_201 = {
    "vsys1": {
        "application-tag": {"entry": [{"@name": "dropbox-base", "tag": members("Sanctioned")}]},
        "profiles": {
            "url-filtering": {"entry": [
                profile("oep-sas6-url-a", **{"http-header-insertion": {"entry": [
                    {"@name": "oep-sas6-hhi1", "type": {"entry": [{
                        "@name": "Microsoft Office365 Tenant Restrictions",
                        "domains": members("*.office.com"),
                        "headers": {"entry": [{
                            "@name": "oep-sas6-h1", "header": "Restrict-Access-To-Tenants",
                            "value": "contoso.onmicrosoft.com", "log": "yes"}]}}]}},
                    # NO `domains` list: nothing in the configuration says which requests the
                    # header is inserted into.
                    {"@name": "oep-sas6-hhi2", "type": {"entry": [{
                        "@name": "Dropbox Network Control",
                        "headers": {"entry": [{
                            "@name": "oep-sas6-h4", "header": "X-Dropbox-allowed-Team-Ids",
                            "value": "dbid:oep-sas6-team"}]}}]}},
                ]}}),
                profile("oep-sas6-url-b", **{"log-http-hdr-referer": "yes"}),
                # The eleven profiles the `url-filtering` domain left standing, which stage 6
                # recorded as FOUND rather than written. Named and otherwise empty: stage 6 read
                # their per-action category lists and recorded that none of the twelve names
                # either consumer-storage category and none carries header insertion.
                *[profile(f"oep-url-{n:02d}") for n in range(1, 12)],
            ]},
            # A tenant list that names NO tenant, and one that names two. A bare entry commits,
            # so a rule can reference a tenant list that restricts nothing.
            "saas-tenant-list": {"entry": [
                {"@name": "oep-sas6-tl-bare"},
                {"@name": "oep-sas6-tl-pop",
                 "list": members("contoso.onmicrosoft.com", "fabrikam.com")},
            ]},
        },
        "application-filter": {"entry": [
            {"@name": "oep-sas6-filt-a", "subcategory": members("file-sharing", "storage-backup"),
             "exclude": members("dropbox-base"), "tagging": {"no-tag": "yes"}}]},
        "rulebase": {"security": {"rules": {"entry": [
            rule("oep-sas6-rule-a", ["oep-sas6-filt-a"], "deny"),
            rule("oep-sas6-rule-b", ["dropbox-base"], "allow",
                 **{"profile-setting": {"profiles": {
                        "url-filtering": members("oep-sas6-url-a")}},
                    "saas-tenant-list": members("oep-sas6-tl-pop")}),
        ]}}},
    },
}

#: The firewall's OWN shared namespace on pan-fw-201 - the scope stage 4 derived from the grammar
#: and never wrote, and stage 6 measured by writing it. Reachable from every partition.
FW_201_SHARED = {
    "profiles": {"url-filtering": {"entry": [
        profile("oep-sas6-url-sh", **{"http-header-insertion": {"entry": [{
            "@name": "oep-sas6-hhi-sh", "type": {"entry": [{
                "@name": "Microsoft Office365 Tenant Restrictions",
                "headers": {"entry": [{
                    "@name": "oep-sas6-hsh", "header": "Restrict-Access-To-Tenants",
                    "value": "contoso.onmicrosoft.com"}]}}]}}]}}),
        profile("oep-url-sh-01"),
    ]}},
    "application-filter": {"entry": [{"@name": "oep-sas6-filt-sh", "is-saas": "yes"}]},
}

#: pan-fw-111: FOUR ABSENCES AND THE THREE PROFILES NOBODY HERE PUT THERE. The profiles matter
#: for one reason: they make `url_filtering_profiles_read` TRUE, which is the column separating
#: "this partition has no profile" from "nobody looked". None of them names either category.
FW_111 = {"vsys1": {
    "profiles": {"url-filtering": {"entry": [profile("active_block"),
                                             profile("all_site_access_actions")]}},
}}
FW_111_SHARED = {"profiles": {"url-filtering": {"entry": [profile("zz_urlfilt_test")]}}}

APPLIANCES = [
    # (serial, hostname, vsys map, shared subtree, deviceconfig/setting subtree)
    # `deviceconfig/setting` PRESENT AND CARRYING NO `cloudapp` on two of the three, which is the
    # state of three of the four lab appliances - stage 4 read that parent on all four.
    ("013201001085", "fw-core-tpa-b", TPA_B, {}, {}),
    ("691665AC334B458", "pan-fw-201", FW_201, FW_201_SHARED, {"cloudapp": {"disable": "yes"}}),
    ("6A9C0A9904E7D6E", "pan-fw-111", FW_111, FW_111_SHARED,
     {"management": {"rule-require-audit-comment": "yes"}}),
]


def merged_payload(vsys_map, shared, setting):
    device = {"@name": "localhost.localdomain",
              "vsys": {"entry": [{"@name": name, **content}
                                 for name, content in vsys_map.items()]}}
    if setting is not None:
        device["deviceconfig"] = {"setting": setting}
    config = {"devices": {"entry": [device]}}
    if shared:
        config["shared"] = shared
    return {"config": config}


class SaasControlTestCase(TestCase):
    """Three appliances carrying the configuration stage 6 built, and the five controls over it."""

    ace_reply = ACE_REPLY

    def setUp(self):
        self.now = timezone.now()
        self.station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA, hostname="pano.saas")
        self.run = AssessmentRun.objects.create(
            name="SaaS", status=AssessmentRun.Status.RUNNING, started_at=self.now)
        for control in seed_controls(SAAS_CONTROLS):
            control.control_type = TYPE_BY_CONTROL[control.control_id]
            # save() DERIVES target_model from control_type, so this is what keeps the queries
            # compilable: `ControlQuery.clean` refuses a query on another model.
            control.save()
        self.points = {}
        self.appliances = {}
        for serial, hostname, vsys_map, shared, setting in APPLIANCES:
            group = ApplianceGroup.objects.create(
                management_station=self.station, name=f"g-{hostname}",
                group_type=ApplianceGroup.TYPE_STANDALONE)
            appliance = Appliance.objects.create(
                management_station=self.station, appliance_group=group,
                serial_number=serial, hostname=hostname)
            self.appliances[hostname] = appliance
            Snapshot.objects.create(
                management_station=self.station, appliance=appliance,
                source_type="show_merged_config", collected_at=self.now,
                payload=merged_payload(vsys_map, shared, setting))
            Snapshot.objects.create(
                management_station=self.station, appliance=appliance,
                source_type="config_predefined_application", collected_at=self.now,
                payload=PREDEFINED)
            Snapshot.objects.create(
                management_station=self.station, appliance=appliance,
                source_type="show_cloud_appid_connection", collected_at=self.now,
                payload=self.ace_reply)
            for vsys_name in vsys_map:
                point = EnforcementPoint.objects.create(
                    management_station=self.station, appliance=appliance,
                    vsys_name=vsys_name, in_scope=True)
                # AN EMPTY PUSHED ROOT. Every object stage 6 built is local and stage 6 verified
                # each one in the firewall's own view; a Panorama-managed point with no pushed
                # snapshot at all raises in the normalizer.
                Snapshot.objects.create(
                    management_station=self.station, appliance=appliance,
                    enforcement_point=point,
                    source_type="show_pushed_shared_policy_vsys", collected_at=self.now,
                    payload={"policy": {"panorama": {}}})
                self.points[(hostname, vsys_name)] = point

    def whole_lab(self):
        for appliance in self.appliances.values():
            normalize_cloud_app_engine(appliance)
        for point in self.points.values():
            normalize_saas_security(point)
        generate_cloud_app_engine_findings(self.run)
        generate_sanctioned_application_marking_findings(self.run)
        generate_saas_url_filtering_posture_findings(self.run)
        generate_saas_application_policy_posture_findings(self.run)

    #: Which finding model answers for which control.
    MODELS = {
        "PAN-SAS-001": SanctionedApplicationMarkingFinding,
        "PAN-SAS-002": SaasUrlFilteringPostureFinding,
        "PAN-SAS-003": SaasApplicationPolicyPostureFinding,
        "PAN-SAS-004": SaasUrlFilteringPostureFinding,
        "PAN-SAS-005": CloudAppEngineFinding,
    }

    def verdicts(self, control_id):
        """{(appliance, partition): (severity, [query names])} for one control over the lab.

        The three verdict subjects carry the appliance in `subject_scope` and the partition in
        `subject_name`, because `vsys1` is not unique in an estate. The App-ID Cloud Engine is a
        device-wide singleton with no scope at all, so its key is the hostname twice - which is
        ugly and is the honest shape rather than two helpers.
        """
        model = self.MODELS[control_id]
        return {(getattr(f, "subject_scope", "") or f.subject_name, f.subject_name):
                (f.severity, sorted(f.matched_query_names))
                for f in model.objects.filter(control__control_id=control_id)}

    def summary(self, control_id, scope, name):
        model = self.MODELS[control_id]
        lookup = {"control__control_id": control_id, "subject_name": name}
        if any(f.name == "subject_scope" for f in model._meta.get_fields()):
            lookup["subject_scope"] = scope
        return model.objects.get(**lookup).summary


class ApprovalMarkingTests(SaasControlTestCase):
    """PAN-SAS-001, whose two assertion records disagree about one partition."""

    def test_the_marking_control_over_the_whole_lab(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-SAS-001"), {
            # THE RECORD-GRAIN CASE. The first record PASSES here - one application carries the
            # marking - and the second FIRES, because no sibling partition marks it. One finding,
            # through the second record's query alone.
            ("fw-core-tpa-b", "vsys1"): ("medium", ["Approval marking differs between "
                                                    "virtual systems"]),
            # Both records fire: nothing is marked here AND the partitions disagree.
            ("fw-core-tpa-b", "vsys2"): ("medium", ["Approval marking differs between "
                                                    "virtual systems", "Baseline"]),
            ("fw-core-tpa-b", "vsys3"): ("medium", ["Approval marking differs between "
                                                    "virtual systems", "Baseline"]),
            ("fw-core-tpa-b", "vsys5"): ("medium", ["Approval marking differs between "
                                                    "virtual systems", "Baseline"]),
            ("fw-core-tpa-b", "vsys6"): ("medium", ["Approval marking differs between "
                                                    "virtual systems", "Baseline"]),
            ("fw-core-tpa-b", "vsys7"): ("medium", ["Approval marking differs between "
                                                    "virtual systems", "Baseline"]),
            ("fw-core-tpa-b", "vsys10"): ("medium", ["Approval marking differs between "
                                                     "virtual systems", "Baseline"]),
            # A single-vsys appliance with nothing marked: the baseline alone, because the
            # companion query's applicability clause excludes it.
            ("pan-fw-111", "vsys1"): ("medium", ["Baseline"]),
        })

    def test_a_single_vsys_appliance_that_marks_something_produces_nothing(self):
        """pan-fw-201 holds the same marking as fw-core-tpa-b vsys1 and no finding at all.

        The difference is the APPLICABILITY clause, not the configuration: there is no second
        partition for the marking to disagree with, so the question does not arise. That is a
        suppression and not a pass on the second record.
        """
        self.whole_lab()
        self.assertNotIn(("pan-fw-201", "vsys1"), self.verdicts("PAN-SAS-001"))

    def test_a_populated_container_with_no_marking_fires(self):
        """The state a truthiness test on the container reads backwards: vsys2's application-tag
        container holds an entry and the marked count is nil."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-001", "fw-core-tpa-b", "vsys2")
        self.assertIn("no application in this virtual system carries the predefined approval tag",
                      summary)

    def test_the_finding_warns_that_the_screen_shows_the_vendors_own_tags(self):
        """The measured trap: the Objects > Applications grid renders the vendor's predefined
        characteristic tags in the same chips as the operator's approval markings, so that column
        is full on a partition which marks nothing."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-001", "pan-fw-111", "vsys1")
        self.assertIn("Objects > Applications GRID IS NOT THE PLACE TO CHECK THIS", summary)

    def test_the_finding_does_not_claim_a_marking_was_authored_here(self):
        """A marking pushed from a Panorama device group counts toward the count and the row has
        no column saying so, so the sentence must not place the inventory on this firewall."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-001", "fw-core-tpa-b", "vsys1")
        self.assertIn("where the marking was AUTHORED is not recorded on this row", summary)

    def test_the_inconsistency_finding_does_not_say_which_partition_wins(self):
        """Precedence for this node across a vsys, the firewall's shared namespace and a Panorama
        push is UNMEASURED. The finding reports the divergence and stops."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-001", "fw-core-tpa-b", "vsys1")
        self.assertIn("WHICH PARTITION IS IN FORCE IS NOT STATED HERE", summary)


class TenantRestrictionTests(SaasControlTestCase):
    """PAN-SAS-002. One partition in this lab has the restriction in force; eight do not."""

    def test_the_tenant_restriction_control_over_the_whole_lab(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-SAS-002"), {
            ("fw-core-tpa-b", "vsys1"): ("high", ["Baseline"]),
            ("fw-core-tpa-b", "vsys2"): ("high", ["Baseline"]),
            ("fw-core-tpa-b", "vsys3"): ("high", ["Baseline"]),
            ("fw-core-tpa-b", "vsys5"): ("high", ["Baseline"]),
            ("fw-core-tpa-b", "vsys6"): ("high", ["Baseline"]),
            ("fw-core-tpa-b", "vsys7"): ("high", ["Baseline"]),
            ("fw-core-tpa-b", "vsys10"): ("high", ["Baseline"]),
            ("pan-fw-111", "vsys1"): ("high", ["Baseline"]),
        })

    def test_the_one_partition_with_the_restriction_in_force_produces_nothing(self):
        """THE THREE-HOP TRAVERSAL, and the only place in this lab where it resolves: a rule of
        vsys1 on pan-fw-201 names `oep-sas6-url-a` directly in its profile-setting, and that
        profile carries a tenant-restriction type entry. A profile with header insertion that no
        rule carries - which is `oep-sas6-url-sh` in the same appliance's shared namespace - does
        NOT satisfy this control, and that is the whole of its first clause.
        """
        self.whole_lab()
        self.assertNotIn(("pan-fw-201", "vsys1"), self.verdicts("PAN-SAS-002"))

    def test_a_partition_with_no_profile_says_nobody_looked(self):
        """vsys10 has no url-filtering container at all, so `url_filtering_profiles_read` is
        false - and in the collected payload "no header insertion" and "url-filtering was never
        collected" are the SAME absence. The sentence must not report a configuration."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-002", "fw-core-tpa-b", "vsys10")
        self.assertIn("NOBODY LOOKED", summary)
        self.assertNotIn("no profile this partition can reach inserts", summary)

    def test_a_partition_with_profiles_and_no_insertion_reports_the_configuration(self):
        """The other side of the same column. pan-fw-111 holds three standing profiles that carry
        no header insertion, so this IS a reading and not a silence."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-002", "pan-fw-111", "vsys1")
        self.assertNotIn("NOBODY LOOKED", summary)
        self.assertIn("nothing confines these applications to the corporate account", summary)

    def test_the_finding_does_not_claim_the_tenant_identifier_is_wrong(self):
        """The device stores whatever string it is given and cannot tell a correct identifier
        from a plausible wrong one, so that half stays with the engineer's question."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-002", "fw-core-tpa-b", "vsys1")
        self.assertIn("is the engineer's answer", summary)


class FunctionApplicationTests(SaasControlTestCase):
    """PAN-SAS-003. Five refusing actions pass, `allow` fires, and the sentinel fires too."""

    def test_the_function_control_over_the_whole_lab(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-SAS-003"), {
            # A rule names the upload function and PERMITS it.
            ("fw-core-tpa-b", "vsys7"): ("high", ["Baseline"]),
            # THE SENTINEL: no rule names any function child application, so there is no action
            # to read. It sorts as benign on any equality against `allow` and is the state every
            # appliance in this lab was in before stage 6 wrote six rules.
            ("fw-core-tpa-b", "vsys10"): ("high", ["Baseline"]),
            ("pan-fw-111", "vsys1"): ("high", ["Baseline"]),
            # A rulebase whose two rules name an application FILTER and a BASE application, and
            # no function child - so the sentinel, at the same severity as a permitted upload.
            ("pan-fw-201", "vsys1"): ("high", ["Baseline"]),
        })

    def test_every_refusing_action_passes_and_not_only_deny(self):
        """`deny` IS NOT THE ONLY REFUSAL. Four of the six actions are denials in this control's
        sense and none of them is the string `deny`; a query matching the literal would report
        four compliant partitions as failing."""
        self.whole_lab()
        for partition in ("vsys1", "vsys2", "vsys3", "vsys5", "vsys6"):
            with self.subTest(partition):
                self.assertNotIn(("fw-core-tpa-b", partition), self.verdicts("PAN-SAS-003"))

    def test_the_sentinel_finding_says_no_rule_names_them(self):
        """The two failing states are the same `false` and a reader has to be told which."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-003", "fw-core-tpa-b", "vsys10")
        self.assertIn("NO RULE OF THIS PARTITION NAMES ANY UPLOAD, SHARING OR DELETE FUNCTION",
                      summary)

    def test_a_permitted_function_reads_differently_from_the_sentinel(self):
        """Naming the functions and then permitting them is worse than not naming them, because
        it reads as control - so the two sentences are not interchangeable."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-003", "fw-core-tpa-b", "vsys7")
        self.assertIn("permits them", summary)
        self.assertIn("enforces the opposite of it", summary)
        self.assertNotIn("NO RULE OF THIS PARTITION NAMES", summary)

    def test_the_count_is_reported_as_a_lower_bound(self):
        """Which applications have function children is a property of the vendor's catalog,
        delivered by content updates, and this pipeline has not enumerated it."""
        self.whole_lab()
        self.assertIn("LOWER BOUND", self.summary("PAN-SAS-003", "fw-core-tpa-b", "vsys7"))


class ConsumerStorageCategoryTests(SaasControlTestCase):
    """PAN-SAS-004's web-category half: six ranks over one string column."""

    def test_the_category_control_over_the_whole_lab(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-SAS-004"), {
            # `alert` - the one CALIBRATED band. The visit happens and is recorded, so stage 3
            # grades it below the permitting values, and the calibration query takes the finding
            # from the control's own medium down to low.
            ("fw-core-tpa-b", "vsys5"): ("low", ["Baseline",
                                                 "Permitted and recorded rather than restricted"]),
            # `allow`: permitted, at the control's own severity.
            ("fw-core-tpa-b", "vsys6"): ("medium", ["Baseline"]),
            # A profile that says nothing about either category, and a partition with no profile
            # at all: both reduce to `in-no-restricting-list`, which is a RANK and not a gap.
            ("fw-core-tpa-b", "vsys7"): ("medium", ["Baseline"]),
            ("fw-core-tpa-b", "vsys10"): ("medium", ["Baseline"]),
            # Twelve standing profiles, none of which names either category.
            ("pan-fw-201", "vsys1"): ("medium", ["Baseline"]),
            ("pan-fw-111", "vsys1"): ("medium", ["Baseline"]),
        })

    def test_the_three_restricting_treatments_pass(self):
        """Block, override and continue. The vendor's own floor for a category it calls
        necessary-but-risky is the interruption, which is why `continue` passes."""
        self.whole_lab()
        for partition in ("vsys1", "vsys2", "vsys3"):
            with self.subTest(partition):
                self.assertNotIn(("fw-core-tpa-b", partition), self.verdicts("PAN-SAS-004"))

    def test_the_calibration_query_cannot_downgrade_a_permitting_partition(self):
        """THE PROPERTY THE SEVERITY RESTS ON. `derive_control_query_severity_value` discards the
        baseline tier the moment any non-baseline query matches, and the worst match wins - so a
        LOW query that could also match an `allow` or `in-no-restricting-list` row would report
        those at low. It cannot: all three placements are equalities on one string column whose
        derivation yields exactly one token per row. A later stage writing the `alert` placement
        as a threshold or a `contains` breaks this silently.
        """
        self.whole_lab()
        verdicts = self.verdicts("PAN-SAS-004")
        self.assertEqual(verdicts[("fw-core-tpa-b", "vsys6")][0], "medium")
        self.assertEqual(verdicts[("fw-core-tpa-b", "vsys10")][0], "medium")
        self.assertEqual(verdicts[("fw-core-tpa-b", "vsys5")][0], "low")

    def test_the_unrestricted_finding_says_an_absence_cannot_be_told_from_a_decision(self):
        """A predefined category explicitly set to permit is NEVER WRITTEN, so a category in no
        list and a category somebody chose to permit read identically."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-004", "pan-fw-201", "vsys1")
        self.assertIn("appears in no restricting list", summary)
        self.assertIn("cannot tell that from a deliberate decision to permit", summary)

    def test_the_alert_finding_says_the_exposure_is_unchanged(self):
        """A reader seeing a LOW finding has to know the visit still happens."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-004", "fw-core-tpa-b", "vsys5")
        self.assertIn("the visit happens", summary)

    def test_the_attribute_surface_of_pan_sas_004_has_no_query(self):
        """THE HALF OF THIS CONTROL THAT REACHES NO CUSTOMER, held here so the silence cannot be
        read as coverage.

        Stage 3 gives PAN-SAS-004 two assertion records and they name DIFFERENT SUBJECTS: the web
        categories, which are a URL-filtering verdict, and the attribute-driven application
        selection, which is a policy verdict. `Control.save()` derives ONE `target_model` from
        `control_type` through a one-to-one map and `ControlQuery.clean()` refuses a query on any
        other model, so the second record cannot have a query on this control at all - and the
        finding model for its subject exists and is never written by it.

        Splitting the control into two catalog ids is a product decision and not this stage's.
        If it is ever made, this test fails and that is the signal to update it.
        """
        self.whole_lab()
        control = Control.objects.get(control_id="PAN-SAS-004")
        self.assertEqual(control.target_model, "integrations.SaasUrlFilteringPosture")
        models = {q.canonical_query.get("model") for q in control.queries.all()}
        self.assertEqual(models, {"integrations.SaasUrlFilteringPosture"})
        # And the proof it matters: the partition the second record expects a finding on produces
        # none. vsys1 of fw-core-tpa-b holds an application filter selecting cloud services that
        # no rule names, which is the second record's whole assertion.
        self.assertNotIn(("fw-core-tpa-b", "vsys1"), self.verdicts("PAN-SAS-004"))
        self.assertFalse(SaasApplicationPolicyPostureFinding.objects.filter(
            control__control_id="PAN-SAS-004").exists())


class CloudAppEngineTests(SaasControlTestCase):
    """PAN-SAS-005, which produces NOTHING on this lab and is not inert."""

    def test_the_engine_control_produces_nothing_on_this_lab(self):
        """And the reason is the APPLICABILITY clause, not the configuration. The engine is not
        working on all three appliances - the assertion is satisfied everywhere - and the reason
        is the one the gate excludes, so every row falls to the half of this control that asks
        whether the adoption decision is on the record, which has no query.
        """
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-SAS-005"), {})
        self.assertEqual(CloudAppEngineSetting.objects.filter(
            ace_not_operational=True).count(), 3)
        self.assertEqual(CloudAppEngineSetting.objects.exclude(
            ace_failure_reason="license_check_failed").count(), 0)

    def test_the_configuration_half_passes_on_every_appliance_and_the_engine_does_not(self):
        """THE MEASURED POLARITY, and the reason this control reads the operational verdict. The
        configured key is absent on two appliances and SET on the third - pan-fw-201 carries
        `disable: yes`, which switches the engine off - and the engine reports itself broken on
        all three regardless."""
        self.whole_lab()
        by_host = {s.appliance.hostname: s for s in
                   CloudAppEngineSetting.objects.select_related("appliance")}
        self.assertIs(by_host["pan-fw-201"].ace_disabled, True)
        self.assertIs(by_host["pan-fw-111"].ace_disabled, False)
        self.assertIs(by_host["fw-core-tpa-b"].ace_disabled, False)
        for setting in by_host.values():
            self.assertTrue(setting.cloudapp_node_read)
            self.assertTrue(setting.ace_not_operational)


class LicensedCloudAppEngineTests(SaasControlTestCase):
    """The same lab with the license check PASSING, which is the proof the gate is an exclusion.

    Without this, "no finding on any appliance" and "a control that can never fire" are the same
    observation - and the second is the thing a reader must be able to rule out. The reply here
    is NOT a readback: no appliance in this lab can reach it, because every condition the command
    reports is unsatisfied until the reply says otherwise.
    """

    ace_reply = ACE_REPLY_LICENSED

    def test_a_subscribed_appliance_whose_engine_is_broken_fires(self):
        self.whole_lab()
        self.assertEqual(self.verdicts("PAN-SAS-005"), {
            ("fw-core-tpa-b", "fw-core-tpa-b"): ("medium", ["Baseline"]),
            ("pan-fw-201", "pan-fw-201"): ("medium", ["Baseline"]),
            ("pan-fw-111", "pan-fw-111"): ("medium", ["Baseline"]),
        })

    def test_the_finding_names_the_condition_and_not_the_symptom(self):
        """The device certificate is a SECOND precondition and it is not in the license listing at
        all, so a remediation reading only the license would buy a subscription and still have no
        engine."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-005", "", "pan-fw-111")
        self.assertIn("device certificate", summary)
        self.assertIn("still has no engine", summary)

    def test_the_finding_does_not_report_the_configured_key_as_the_cause(self):
        """The implicit this consumer stores for an absent `disable` is an INFERENCE and not a
        measured vendor default, so the sentence declines to report the configuration unless the
        reason names it."""
        self.whole_lab()
        summary = self.summary("PAN-SAS-005", "", "fw-core-tpa-b")
        self.assertIn("nothing here reports that somebody switched the engine off", summary)


class SaasCatalogShapeTests(TestCase):
    """What the shipped catalog entries must carry, read off the seed rather than off a run."""

    def specs(self):
        return {c["control_id"]: c
                for cat in load_seed_payload()["catalogs"] for c in cat["controls"]
                if c["control_id"].startswith("PAN-SAS-")}

    def test_every_saas_control_ships_with_exactly_one_baseline(self):
        """`derive_control_query_severity_value` falls back to the control's default only where no
        non-baseline query matched, so two baselines or none makes every severity undefined."""
        for control_id, spec in sorted(self.specs().items()):
            with self.subTest(control_id):
                baselines = [q for q in spec["queries"] if q["is_baseline"]]
                self.assertEqual(len(baselines), 1)

    def test_every_saas_query_names_the_fields_it_asserts_on(self):
        """EMPTY `asserted_fields` IS SILENT. `tested_fields()` falls back to every clause, so the
        finding colors the cells that SCOPED the object as well as the one that failed - and a
        reader is pointed at the setting that made the row qualify."""
        for control_id, spec in sorted(self.specs().items()):
            for query in spec["queries"]:
                with self.subTest(control=control_id, query=query["name"]):
                    self.assertTrue(query["asserted_fields"])

    def test_no_saas_query_asserts_on_a_scope_clause(self):
        """The two applicability clauses in this domain, held out of `asserted_fields` by name.

        `appliance_is_multi_vsys` is the reason PAN-SAS-001's companion query QUALIFIES a row and
        `ace_failure_reason` is the reason PAN-SAS-005's baseline does. Colouring either would
        point a reader at the setting the partition has right.
        """
        scope_only = {"appliance_is_multi_vsys", "ace_failure_reason"}
        for control_id, spec in sorted(self.specs().items()):
            for query in spec["queries"]:
                with self.subTest(control=control_id, query=query["name"]):
                    self.assertEqual(set(query["asserted_fields"]) & scope_only, set())

    def test_every_calibration_query_carries_the_baseline_assertion_clause(self):
        """`evaluate_queryset_control_queries` ORs every active query, so a calibration query
        without the assertion clause WIDENS the control onto rows the assertion passes. One
        calibration query in this domain, and this is what keeps it narrow."""
        for control_id, spec in sorted(self.specs().items()):
            baseline = next(q for q in spec["queries"] if q["is_baseline"])
            assertion = {(c["field"], c["op"], c["value"], c.get("negated", False))
                         for c in baseline["canonical_query"]["clauses"]}
            for query in spec["queries"]:
                with self.subTest(control=control_id, query=query["name"]):
                    if query["is_baseline"]:
                        continue
                    clauses = {(c["field"], c["op"], c["value"], c.get("negated", False))
                               for c in query["canonical_query"]["clauses"]}
                    # PAN-SAS-001's companion query is a SECOND ASSERTION RECORD rather than a
                    # calibration of the first, so it carries its own clauses and not the
                    # baseline's - which is why this asserts the intersection is non-empty only
                    # where the query came from a grading placement.
                    if query["adjusted_severity"] != spec["default_severity"]:
                        self.assertTrue(assertion <= clauses)
