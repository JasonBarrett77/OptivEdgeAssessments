"""The registry must hold every finding model, or it is just another list to forget."""

from __future__ import annotations

from django.test import TestCase

from assessments.finding_registry import FINDING_KINDS, FINDING_MODELS, KIND_BY_MODEL
from assessments.models import FindingBase


def _concrete_finding_models():
    def walk(cls):
        for sub in cls.__subclasses__():
            if not sub._meta.abstract:
                yield sub
            yield from walk(sub)
    return set(walk(FindingBase))


class FindingRegistryTests(TestCase):
    def test_the_registry_holds_every_concrete_finding_model(self):
        """The whole point. A new finding model that is not registered fails HERE, rather than
        quietly narrowing the report the way five models already did."""
        missing = _concrete_finding_models() - set(FINDING_MODELS)
        self.assertEqual(missing, set(),
                         f"finding models missing from FINDING_KINDS: "
                         f"{sorted(m.__name__ for m in missing)}")

    def test_the_registry_names_no_model_that_is_not_a_finding(self):
        self.assertEqual(set(FINDING_MODELS) - _concrete_finding_models(), set())

    def test_every_kind_names_a_real_subject_field(self):
        for kind in FINDING_KINDS:
            with self.subTest(kind.name):
                kind.model._meta.get_field(kind.subject_field)

    def test_every_kind_names_a_real_control_type(self):
        from assessments.models import Control
        valid = {choice for choice, _ in Control.ControlType.choices}
        for kind in FINDING_KINDS:
            self.assertIn(kind.control_type, valid, kind.name)

    #: Labels the singular rule does not apply to, each with the reason. The rule is a
    #: heuristic for catching "certificates" where "certificate" was meant; a label whose
    #: SUBJECT is plural in the vendor's own UI is not that mistake.
    PLURAL_BY_NAME = {
        # Device > Setup > Management > Authentication Settings. "authentication setting"
        # names nothing - the screen is one object made of several values.
        "authentication settings",
        # Device > Setup > Services. "update server setting" names nothing either.
        "update server settings",
        # Device > Setup > Management > Logging and Reporting Settings.
        "logging settings",
        # Device > Setup > WildFire. "wildfire setting" names nothing either - the screen is
        # a cluster of settings and the finding is about the cluster.
        "wildfire settings",
        # Device > Setup > Session. Two sibling config nodes - `setting/config/rematch` and
        # `setting/session/ipv6-firewalling` - on the one panel an engineer opens, so "session
        # setting" would name neither of them and the finding is about the panel.
        "session settings",
        # Device > Dynamic Updates. ONE ROW CARRIES EVERY CONTENT STREAM AS ITS OWN COLUMN -
        # stage 5's `identity.one_row_per` for `platform-lifecycle` says so in terms - and the
        # vendor's screen lists several. "firewall content stream" would name one stream, which
        # is the grain this subject exists not to be: a stream-keyed row has nothing to report on
        # exactly the streams that are absent, and that is the commonest state measured.
        "firewall content streams",
        # `deviceconfig/setting/management`'s policy-rule switches. ONE ROW PER APPLIANCE
        # CARRYING SEVERAL SWITCHES - the hit counter and the shadow-rule check - and the node
        # has no vsys axis, so "policy rule setting" would name one of them. The same grain
        # argument as "session settings" above: the subject is the group of switches at one
        # node, and a switch-keyed row has nothing to report on a switch whose key is absent,
        # which is the state PAN-POL-011 exists to report.
        "policy rule settings",
    }

    def test_labels_are_unique_and_prose_shaped(self):
        labels = [k.label for k in FINDING_KINDS]
        self.assertEqual(len(labels), len(set(labels)))
        for label in labels:
            if label in self.PLURAL_BY_NAME:
                continue
            self.assertFalse(label.endswith("s"), f"{label!r} should be singular")

    def test_counts_cover_every_kind(self):
        from assessments.finding_registry import open_finding_counts
        self.assertEqual(set(open_finding_counts()), {k.label for k in FINDING_KINDS})

    #: A first word this rule leaves capitalized. An acronym or a vendor's own spelling carries
    #: a capital somewhere other than its first letter - `SSL/TLS`, `IPSec`, `GlobalProtect`,
    #: `WildFire`, `App-ID`, `Device-ID`, `DoS`, `SaaS`, `NTP` - so the rule reads the whole
    #: word and needs no line per brand. `Panorama` is the one product name spelled like an
    #: ordinary English word, which is why it is the one that has to be written down.
    CAPITALIZED_FIRST_WORD = {"Panorama"}

    #: Endings no plural in this registry has, and each one is a pluralizer that ran twice.
    #: `layout.plural` appends a bare `s`, which over an already-plural noun gives
    #: "certificatess" and "settingss"; `health_check.plural_noun`'s sibilant branch gives
    #: "settingses" and "inventorieses". "addresses" ends in `es` and is not caught by either.
    DOUBLE_PLURAL_ENDINGS = ("ss", "eses")

    def test_every_kind_names_its_objects_for_a_client(self):
        """`client_plural` is printed as it stands - the Occurrences line applies no pluralizer
        it - so the form has to be right here. The same call `common_name` gets in
        `test_health_check.SubjectTests`: the field being required stops a new kind reaching the
        document nameless, and this is what stops it reaching the document misspelled."""
        from assessments.artifacts.health_check import plural_noun

        for kind in FINDING_KINDS:
            with self.subTest(kind.name):
                plural = kind.client_plural
                self.assertTrue(plural.strip(), f"{kind.name} has no client plural")
                self.assertEqual(plural, plural.strip())
                first = plural.split()[0]
                if first not in self.CAPITALIZED_FIRST_WORD:
                    self.assertFalse(
                        first[0].isupper() and first[1:].islower(),
                        f"{plural!r} reads as a heading; it is printed mid-sentence")
                self.assertFalse(
                    plural.endswith(self.DOUBLE_PLURAL_ENDINGS),
                    f"{plural!r} looks like a pluralizer that ran twice")
                self.assertEqual(plural_noun(2, plural), plural,
                                 f"{plural!r} is not already plural")

    #: THE LABELS WHOSE CLIENT PLURAL WAS CHOSEN RATHER THAN DERIVED - 31 of the 75, measured
    #: 2026-11-07 - and this set is what stops a later tidy-up deriving them again. Every one
    #: of them pluralizes into something a client should not be handed: our own vocabulary
    #: ("coverages", "virtual system rule postures", "forward-proxy signing designations"), a
    #: word that is not English for what is counted ("NTPs", "high availabilities", "management
    #: plane addressings"), a vendor's brand the label spells all in lowercase ("wildfire
    #: settings", "panorama registrations"), or the British spelling of the one noun the
    #: vendor's own screen spells Licenses. The other 44 labels ARE the vendor's term and their
    #: plural is the answer, which is why the registry carries no list of those.
    CHOSEN_RATHER_THAN_DERIVED = {
        "coverage", "normalization issue", "password complexity", "wildfire settings", "NTP",
        "SNMP", "system identity", "management resolver set", "management service path set",
        "high availability", "panorama registration", "global LLDP setting",
        "tunnel inspection coverage", "sanctioned application marking", "App-ID Cloud Engine",
        "device identification", "rulebase device match",
        "GlobalProtect portal authentication row", "GlobalProtect enforcement point",
        "log database alarm mechanism", "User-ID collector", "User-ID discovery bound",
        "forward-proxy signing designation", "GlobalProtect gateway authentication row",
        "DoS policy rule", "decryption policy rule", "decryption rulebase coverage",
        "virtual system log forwarding", "management plane addressing",
        "virtual system rule posture",
    }

    def test_a_kind_that_chose_its_plural_also_chose_its_singular(self):
        """Required of exactly the kinds in `CHOSEN_RATHER_THAN_DERIVED`, and of no others.

        The Occurrences line counts, and a count can be one: 11 of the lab's 203 control
        were about a single object on 2026-11-07, six of them reading "1, across 1 AAA server
        profiles". A kind whose plural is just its label pluralized needs nothing here, because
        the label IS the singular a client should read. A kind that chose a different word owes
        both numbers, or the line has to pick between grammar and register.
        """
        from assessments.artifacts.health_check import plural_noun

        for kind in FINDING_KINDS:
            derived = kind.client_plural == plural_noun(2, kind.label)
            with self.subTest(kind.name):
                if derived:
                    self.assertEqual(
                        kind.client_singular, "",
                        f"{kind.name} pluralizes its label, so `label` is already the singular "
                        f"a client reads and this field is weight")
                else:
                    self.assertTrue(
                        kind.client_singular,
                        f"{kind.name} chose {kind.client_plural!r} over its label, so it has "
                        f"to choose the word for one of them too")
                    self.assertEqual(kind.client_singular.strip(), kind.client_singular)

    def test_no_kind_was_left_on_the_plural_of_its_label(self):
        """A kind named here must still differ from its own label pluralized. The field was
        added because 31 kinds could not be served by any pluralizer, and the cheapest way to
        undo that work is a later pass that "notices" the two fields mostly agree."""
        from assessments.artifacts.health_check import plural_noun

        labels = {kind.label for kind in FINDING_KINDS}
        self.assertEqual(self.CHOSEN_RATHER_THAN_DERIVED - labels, set(),
                         "this set names a label the registry no longer carries")
        for kind in FINDING_KINDS:
            if kind.label not in self.CHOSEN_RATHER_THAN_DERIVED:
                continue
            with self.subTest(kind.name):
                self.assertNotEqual(kind.client_plural, plural_noun(2, kind.label))


class FindingPathConvergenceTests(TestCase):
    """One path for every finding kind, policy included.

    `RuleFinding` sat on `FindingBase` while the other 22 kinds moved to `ObjectFindingBase`,
    and the divergence was invisible: nothing failed, the policy findings just could not say
    which rule they were about. Asserted over the REGISTRY so a new model cannot reintroduce it.
    """

    #: Kinds that legitimately have no named subject, each with the reason. Empty today: every
    #: finding in the corpus is about something with a name. A device-wide setting finding would
    #: belong here - and adding to this set should be a deliberate argument, not a shortcut.
    NO_NAMED_SUBJECT: set[str] = set()

    def test_every_finding_model_is_an_object_finding(self):
        from assessments.models import ObjectFindingBase
        divergent = sorted(
            kind.name for kind in FINDING_KINDS
            if kind.name not in self.NO_NAMED_SUBJECT
            and not issubclass(kind.model, ObjectFindingBase))
        self.assertEqual(divergent, [],
                         f"finding models not on the shared object path: {divergent}. "
                         "Extend ObjectFindingBase and generate with an ObjectFindingSpec, or "
                         "add the model to NO_NAMED_SUBJECT with a reason.")

    def test_every_finding_model_freezes_a_subject_name(self):
        for kind in FINDING_KINDS:
            if kind.name in self.NO_NAMED_SUBJECT:
                continue
            with self.subTest(kind.name):
                kind.model._meta.get_field("subject_name")
