import json
import re
from unittest.mock import patch

from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse

from assessments.controls_catalog.drift import catalog_has_drifted
from assessments.controls_catalog.io.importers import (
    apply_catalog,
    create_catalog_from_current_controls,
    refresh_seeded_catalogs,
    seed_catalogs_if_empty,
)
from assessments.controls_catalog.schemas import (
    CLIENT_DETAIL_LIMITS, SHORT_REMEDIATION_LIMIT, _IMPERATIVE, _NOT_AN_IMPERATIVE,
    _EVIDENCE_LIMIT, _EVIDENCE_MAY_NOT_SAY, _EVIDENCE_SENTENCES, _ONE_SENTENCE,
    _ONE_SENTENCE_END, _PROCEDURE_IN_A_STANDARD, validate_catalog_payload)
from assessments.controls_catalog.registry import load_seed_payload
from assessments.models import (
    ApplicationEnvironmentCatalogState,
    AssessmentRun,
    Catalog,
    Control,
    ControlQuery,
)
from optivedge.models import ApplicationEnvironment


def _seed_with_evidence(sentence: str) -> dict:
    """A one-control payload whose only query carries `sentence` as its Evidence row.

    Everything else passes the register, so a refusal can only come from the sentence.
    """
    return {
        "type": "optivedge.assessments.catalog",
        "schema_version": "1.0",
        "catalog": {"key": "evidence", "label": "Evidence", "version": "1.0.0",
                    "description": ""},
        "controls": [{
            "control_id": "FW-RULE-EV-001",
            "name": "Evidence Fixture",
            "control_type": "security_rule",
            "description": "A fixture for the Evidence row's own rules.",
            "rationale": "",
            "audit": "",
            "remediation": "Tighten rule scope.",
            "short_remediation": "Tighten the rule's scope.",
            "what_it_checks": "A rule that permits traffic limits what it allows to the flow "
                              "it was written for.",
            "why_it_matters": "A rule broader than the flow it carries is access nobody is "
                              "watching.",
            "where_to_confirm": "Policies > Security, the source and destination columns.",
            "what_to_change": "Narrow the rule to the hosts and services the flow needs.",
            "default_severity": "high",
            "implementation_version": "v1",
            "target_model": "integrations.SecurityRule",
            "is_active": True,
            "queries": [{
                "name": "Baseline",
                "short_description": sentence,
                "canonical_query": build_security_rule_query("dmz"),
                "is_baseline": True,
                "adjusted_severity": None,
                "is_active": True,
            }],
        }],
    }


def build_security_rule_query(value: str) -> dict:
    return {
        "model": "integrations.SecurityRule",
        "operator": "and",
        "clauses": [
            {
                "field": "from_zone",
                "op": "eq",
                "value": value,
                "negated": False,
                "case_sensitive": False,
                "include_any": False,
            }
        ],
    }


class SeededCatalogTextTests(TestCase):
    """The text a CUSTOMER reads, checked on the shipped payload rather than on a model."""

    def test_every_shipped_evidence_sentence_says_what_was_found(self):
        """The Evidence row belongs to the QUERY, and it had no rule at all until 2026-11-17:
        it shipped 42 backticks, 25 copies of "Default baseline query." and 50 sentences
        explaining our own grading to a client. All 579 of them are rewritten; this is what
        stops the next one."""
        offenders = []
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                for query in control["queries"]:
                    if not query.get("is_active"):
                        continue
                    sentence = query.get("short_description") or ""
                    for pattern, _what in _EVIDENCE_MAY_NOT_SAY:
                        if pattern.search(sentence):
                            offenders.append((control["control_id"], query["name"],
                                              pattern.search(sentence).group(0)))
                    if len(sentence) > _EVIDENCE_LIMIT:
                        offenders.append((control["control_id"], query["name"], len(sentence)))
                    if len(_ONE_SENTENCE_END.findall(sentence)) > _EVIDENCE_SENTENCES:
                        offenders.append((control["control_id"], query["name"], "sentences"))
        self.assertEqual(offenders, [])

    def test_every_active_query_has_an_evidence_sentence(self):
        """48 of the 579 had none, and the document printed a MANUAL placeholder in the row a
        client reads to learn what was found on their firewall."""
        missing = [(control["control_id"], query["name"])
                   for catalog in load_seed_payload()["catalogs"]
                   for control in catalog["controls"]
                   for query in control["queries"]
                   if query.get("is_active") and not (query.get("short_description") or "")]
        self.assertEqual(missing, [])

    def test_an_evidence_sentence_explaining_our_own_grading_is_refused(self):
        """What PAN-AUTH-018's low band used to say, verbatim."""
        payload = _seed_with_evidence("failed attempts before lockout 4 to 5 - reported low.")

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("explains our own grading", str(caught.exception))

    def test_an_evidence_sentence_naming_our_machinery_is_refused(self):
        """What 25 queries used to say, verbatim."""
        payload = _seed_with_evidence("Default baseline query.")

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("names this application's own machinery", str(caught.exception))

    def test_a_malware_verdict_is_the_firewalls_own_word(self):
        """The lesson the Requirement register learned four times. A WildFire verdict and the
        HA1 control link are PAN-OS's vocabulary, so the rules name phrases rather than words:
        a pattern over "verdict" refused six true sentences."""
        payload = _seed_with_evidence(
            "No recurrence is set, so a verdict the cloud has already reached never reaches "
            "this firewall.")

        self.assertTrue(validate_catalog_payload(payload))

    def test_no_control_ships_a_literal_backslash_n(self):
        """A paragraph break written `\\n` in the JSON reaches the page as two CHARACTERS.

        FOUND BY A SIDEWAYS GLANCE, NOT BY A READER. The stage 8 anti-spyware run of 2026-10-31
        fixed eight of these in PAN-SPY-001's description and reported it as that control's
        defect; the same grep over the whole payload found 28 controls carrying 132 of them,
        across PAN-AUTH, PAN-CRT, PAN-MGT and PAN-VLN, every one in `description` and every one a
        paragraph break beside REAL newlines in the same string. So the shape is a known one: an
        author escaping a newline twice in a field that already holds them literally.

        Checked here and not in a template filter because the payload is where it is wrong - a
        filter would hide it from the next author, and `description` is the one field with no
        length limit and the most prose in it.
        """
        offenders = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                for field, value in control.items():
                    if isinstance(value, str) and "\\n" in value:
                        offenders.setdefault(control["control_id"], []).append(field)
        self.assertEqual(offenders, {})


    def test_every_active_control_ships_a_short_recommendation(self):
        """The one sentence of a control a CLIENT reads, in the health check's Summary of
        Findings and Recommendations.

        It used to be `remediation`, the engineer's instruction - so the table carried UI paths
        and CLI into a document for whoever decides whether to fund the work. Jason, 2026-11-06:
        *"The 'Recommendation' is too long, and the values themselves aren't appropriate for
        this customer facing artifact."*
        """
        missing = [control["control_id"]
                   for catalog in load_seed_payload()["catalogs"]
                   for control in catalog["controls"]
                   if control["is_active"] and not control.get("short_remediation", "").strip()]

        self.assertEqual(missing, [])

    def test_no_short_recommendation_reads_like_an_instruction_to_an_engineer(self):
        """The rule, over the shipped payload: one sentence, 100 characters or fewer, no
        command, no UI path, no control id. `schemas` refuses a catalog that breaks it; this
        says so about the one that ships, so a bad line cannot reach a client even if the
        refusal is ever loosened.
        """
        offenders = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                value = (control.get("short_remediation") or "").strip()
                if not value:
                    continue
                why = []
                if len(value) > SHORT_REMEDIATION_LIMIT:
                    why.append(f"{len(value)} characters")
                if "`" in value or ">" in value:
                    why.append("a command or a UI path")
                if re.search(r"[A-Z]{2,4}-[A-Z]{2,5}-\d{3}", value):
                    why.append("a control id")
                if len(re.findall(r"\.(?:\s|$)", value)) != 1 or not value.endswith("."):
                    why.append("more or less than one sentence")
                if why:
                    offenders[control["control_id"]] = why

        self.assertEqual(offenders, {})

    def test_a_control_with_no_short_recommendation_is_refused(self):
        """A guard and not a convention: a control added tomorrow without one would put the full
        remediation back in front of a client, and nothing else in the build would notice."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], short_remediation="")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("short_remediation", str(caught.exception))

    def test_a_short_recommendation_that_carries_a_command_is_refused(self):
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    short_remediation="Run `set deviceconfig system`.")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("remediation", str(caught.exception))

    def test_a_short_recommendation_over_the_limit_is_refused(self):
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    short_remediation="Narrow it. " * 20)]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn(str(SHORT_REMEDIATION_LIMIT), str(caught.exception))

    def test_a_snapshot_of_controls_that_predate_the_field_is_not_refused(self):
        """`apply_catalog` snapshots the live controls before replacing them. On a deployment
        upgraded from a release before this field those rows carry nothing, and refusing the
        snapshot would refuse the upgrade that introduces it."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], short_remediation="")]

        validated = validate_catalog_payload(payload, require_client_text=False)

        self.assertEqual(validated["controls"][0]["short_remediation"], "")

    def test_a_snapshot_still_refuses_a_line_that_is_unfit_to_print(self):
        """Only the PRESENCE rule is relaxed for a snapshot. A line that exists has to be one a
        client can read, however the payload was built."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    short_remediation="Run `set deviceconfig system`.")]

        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload, require_client_text=False)

    def test_an_inactive_control_needs_no_short_recommendation(self):
        """It is graded by nothing, so it reaches no document."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], short_remediation="",
                                    is_active=False)]

        validated = validate_catalog_payload(payload)

        self.assertEqual(validated["controls"][0]["short_remediation"], "")

    def test_it_survives_a_round_trip_through_the_exporter(self):
        """A catalog exported from the live controls and validated again must not lose it -
        which is how a reissue is made, and losing it there would put the full remediation back
        in the document with nothing failing."""
        seed_catalogs_if_empty()
        refresh_seeded_catalogs()
        payload = load_seed_payload()["catalogs"][0]
        for row in payload["controls"]:
            Control.objects.create(
                control_id=row["control_id"], name=row["name"],
                control_type=row["control_type"], description=row["description"],
                remediation=row["remediation"],
                short_remediation=row["short_remediation"],
                what_it_checks=row["what_it_checks"],
                why_it_matters=row["why_it_matters"],
                where_to_confirm=row["where_to_confirm"],
                what_to_change=row["what_to_change"],
                default_severity=row["default_severity"], is_active=row["is_active"],
                target_model=row.get("target_model", ""))

        exported = create_catalog_from_current_controls(
            label="Round trip", version="1", description="A snapshot of the live controls.")

        validated = validate_catalog_payload(exported.payload)
        shipped = next(row for row in validated["controls"]
                       if row["control_id"] == "PAN-MGT-007")
        self.assertEqual(shipped["short_remediation"],
                         Control.objects.get(control_id="PAN-MGT-007").short_remediation)
        self.assertTrue(shipped["short_remediation"])
        for field in CLIENT_DETAIL_LIMITS:
            self.assertEqual(shipped[field],
                             getattr(Control.objects.get(control_id="PAN-MGT-007"), field))
            self.assertTrue(shipped[field])

    def test_every_active_control_ships_the_four_lines_of_its_control_detail(self):
        """The Control Detail section of the health check gives a client one block per control
        that raised a finding, and reads these four fields for it.

        They are WRITTEN for that audience rather than condensed from `description`,
        `rationale`, `audit` and `remediation`. Jason, 2026-11-06: *"These probably all need to
        be produced because the existing seed data isn't consistently using the right level
        language."* Measured the same day over all 218 controls, counting backticked
        identifiers, ALL-CAPS asides, dated notes and control ids: `rationale` was clean on 209,
        `audit` on 140, `remediation` on 116, and `description` ran to a median of 1,924
        characters written to us.
        """
        missing = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                if not control["is_active"]:
                    continue
                absent = [field for field in CLIENT_DETAIL_LIMITS
                          if not (control.get(field) or "").strip()]
                if absent:
                    missing[control["control_id"]] = absent

        self.assertEqual(missing, {})

    def test_no_line_of_a_control_detail_reads_like_a_note_to_an_engineer(self):
        """The rule over the shipped payload: inside its cap, ending in a full stop, no
        command, no mention of the control's own id, nothing in the first person.
        `where_to_confirm` is the one field allowed a UI path, because a screen path is what it
        is for. `schemas` refuses a catalog that breaks this; the test says so about the one
        that ships.
        """
        offenders = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                for field, limit in CLIENT_DETAIL_LIMITS.items():
                    value = (control.get(field) or "").strip()
                    if not value:
                        continue
                    why = []
                    if len(value) > limit:
                        why.append(f"{len(value)} characters")
                    if "`" in value:
                        why.append("a command")
                    if ">" in value and field != "where_to_confirm":
                        why.append("a UI path")
                    if control["control_id"] in value:
                        why.append("its own control id")
                    if re.search(r"\b(?:we|our|ours|us|I|my)\b", value):
                        why.append("the first person")
                    if not value.endswith((".", "?")):
                        why.append("no full stop")
                    if why:
                        offenders[f"{control['control_id']}.{field}"] = why

        self.assertEqual(offenders, {})

    def test_a_control_with_no_control_detail_is_refused(self):
        """A guard rather than a convention: a control added tomorrow without these four would
        appear in the Control Detail section with nothing under its heading."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], what_it_checks="")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("what_it_checks", str(caught.exception))

    def test_every_shipped_requirement_line_states_the_standard(self):
        """The REGISTER of the Requirement line, as opposed to its format, over all 218.

        Jason, 2026-11-16: *"The text values for requirement, risk, and remediation in the
        'Detailed Findings and Recommendations' is not written for the intended audience."* The
        document's labels became Requirement, Risk and Remediation on 2026-11-12 and the text
        under them did not change, so every block described THIS APPLICATION'S PROCEDURE under a
        heading promising THE STANDARD.

        MEASURED BOTH WAYS, which is why this test is worth its line count. Against the text
        this replaced, these patterns refuse 217 of the 218 lines - 195 said "checked for", 167
        "is checked", 138 "for whether", 124 opened with "Each". Against the swept text they
        refuse none. The one line they would have passed before, PAN-AUTH-020, opened with
        "Whether" instead. The median line also fell from 217 characters to 132, and the number
        written as a single sentence rose from 62 to 212.
        """
        offenders = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                value = (control.get("what_it_checks") or "").strip()
                caught = [pattern.search(value).group(0)
                          for pattern, _why in _PROCEDURE_IN_A_STANDARD
                          if pattern.search(value)]
                if caught:
                    offenders[control["control_id"]] = caught

        self.assertEqual(offenders, {})

    def test_every_shipped_risk_line_is_one_sentence(self):
        """Jason agreed the voice on a five-control sample, 2026-11-16: Risk is ONE SENTENCE
        naming what goes wrong.

        MEASURED BEFORE THE SWEEP over all 218: `why_it_matters` ran to a median of 209
        characters and only 100 lines were a single sentence, so the usual shape was a general
        claim followed by the case that made it concrete. After it: 218 of 218, median 174. Two
        lines also spoke about our own machinery - "the finding is not that a number is wrong"
        and "unlike most findings" - and the Requirement patterns now cover this field too.
        """
        offenders = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                value = (control.get("why_it_matters") or "").strip()
                sentences = len(_ONE_SENTENCE_END.findall(value))
                if sentences != 1:
                    offenders[control["control_id"]] = sentences
                caught = [pattern.search(value).group(0)
                          for pattern, _why in _PROCEDURE_IN_A_STANDARD
                          if pattern.search(value)]
                if caught:
                    offenders[f"{control['control_id']} voice"] = caught

        self.assertEqual(offenders, {})

    def test_every_shipped_remediation_line_is_one_imperative_sentence(self):
        """Jason's third rule, agreed on the five-control sample 2026-11-16: Remediation is one
        imperative sentence naming the change, with the engineer's steps left in `remediation`.

        MEASURED BEFORE THE SWEEP over all 218: `what_to_change` ran to a median of 237
        characters, only 35 lines were a single sentence, and 21 spoke about this application
        rather than the firewall - "Clear the algorithm settings the finding names". After it:
        218 of 218 one sentence, median 116, none of them opening with a word that describes
        rather than instructs.

        NOTHING WAS LOST BY CUTTING THEM. 165 lines kept their first sentence and dropped the
        rest, which was the engineer's caveat - break-glass access before enforcing a lockout,
        the master key being unrecoverable, an irreversible delete - and `remediation` was read
        first to confirm it carries every one of those in full.
        """
        offenders = {}
        for catalog in load_seed_payload()["catalogs"]:
            for control in catalog["controls"]:
                value = (control.get("what_to_change") or "").strip()
                why = []
                if len(_ONE_SENTENCE_END.findall(value)) != 1:
                    why.append(f"{len(_ONE_SENTENCE_END.findall(value))} sentences")
                opening = re.sub(r"[^A-Za-z-]", "", value.split(" ")[0]).lower()
                if opening in _NOT_AN_IMPERATIVE:
                    why.append(f"opens with {opening!r}")
                if any(pattern.search(value) for pattern, _w in _PROCEDURE_IN_A_STANDARD):
                    why.append("our own machinery")
                if why:
                    offenders[control["control_id"]] = why

        self.assertEqual(offenders, {})

    def test_a_remediation_line_that_describes_rather_than_instructs_is_refused(self):
        """The line below is what PAN-COV-002 said before the sweep. It is true, and it is not
        a remediation: the cell it lands in is headed Remediation.
        """
        self.assertIn("what_to_change", _IMPERATIVE)
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    what_to_change="Nothing changes on the firewall.")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("imperative", str(caught.exception))

    def test_the_firewalls_own_control_link_is_not_our_machinery(self):
        """`the control link` is PAN-OS's name for the HA1 link between a redundant pair, and
        it was the one false refusal the machinery pattern produced over the 218 - PAN-HAP-002's
        remediation. A pattern that refuses the subject's own vocabulary is a worse rule than no
        rule, because the writer's only way out is to say something less true.
        """
        line = ("Export the high availability key from one firewall and import it on the "
                "other, then enable encryption on the control link on both members.")
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], what_to_change=line)]

        validated = validate_catalog_payload(payload)
        self.assertEqual(validated["controls"][0]["what_to_change"], line)

    def test_a_two_sentence_risk_line_is_refused(self):
        """A guard: 118 of the 218 lines had two or more sentences before 2026-11-16."""
        self.assertIn("why_it_matters", _ONE_SENTENCE)
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(
            payload["controls"][0],
            why_it_matters="A weak key undermines every certificate that chains to it. "
                           "Reissuing one is slower than editing a setting.")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("exactly one", str(caught.exception))

    def test_a_version_number_does_not_end_a_risk_sentence(self):
        """`TLS 1.2` and `aes256-gcm` carry a full stop that is not a sentence end, and the
        sentence count has to agree: a rule that counted them would refuse a correct line."""
        payload = load_seed_payload()["catalogs"][0]
        line = "A floor below TLS 1.2 lets a session negotiate a protocol with known attacks."
        payload["controls"] = [dict(payload["controls"][0], why_it_matters=line)]

        validated = validate_catalog_payload(payload)
        self.assertEqual(validated["controls"][0]["why_it_matters"], line)

    def test_a_requirement_line_that_says_what_was_looked_at_is_refused(self):
        """A guard, not a convention. The sentence below is the SHAPE 216 of the 218 lines had
        before 2026-11-16, and a control added tomorrow must not be able to bring it back.
        """
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(
            payload["controls"][0],
            what_it_checks="Each LDAP server profile is checked for whether SSL/TLS is "
                           "required on the connection to the directory.")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("what_it_checks", str(caught.exception))
        self.assertIn("prints this line as the Requirement", str(caught.exception))

    def test_the_register_leaves_the_firewalls_own_vocabulary_alone(self):
        """The rules refuse OUR procedure, not the subject's. Three sentences that have to pass:
        a revocation check, a date the firewall reports, and a correlative "whether ... or".
        Each one was a false refusal while the patterns were being narrowed.
        """
        for line in ("Every certificate profile enables revocation checking and refuses an "
                     "inconclusive answer.",
                     "The installed device classification data is less than a week old, "
                     "counted from the release date the firewall reports for it.",
                     "No rule permits a high-risk application, whether named directly or "
                     "reached through a group."):
            payload = load_seed_payload()["catalogs"][0]
            payload["controls"] = [dict(payload["controls"][0], what_it_checks=line)]
            with self.subTest(line=line):
                validated = validate_catalog_payload(payload)
                self.assertEqual(validated["controls"][0]["what_it_checks"], line)

    def test_a_control_detail_line_that_carries_a_command_is_refused(self):
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    why_it_matters="It runs `set deviceconfig system`.")]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn("why_it_matters", str(caught.exception))

    def test_where_to_confirm_may_carry_a_ui_path_and_its_neighbors_may_not(self):
        """The one relaxation, and the reason for it: `where_to_confirm` IS a screen path."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    where_to_confirm="Device > Setup > Management.")]

        validated = validate_catalog_payload(payload)
        self.assertEqual(validated["controls"][0]["where_to_confirm"],
                         "Device > Setup > Management.")

        payload["controls"] = [dict(payload["controls"][0],
                                    what_to_change="Set Device > Setup > Management.")]
        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload)

    def test_a_control_detail_line_over_its_cap_is_refused(self):
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    what_to_change="Narrow it. " * 40)]

        with self.assertRaises(ValidationError) as caught:
            validate_catalog_payload(payload)

        self.assertIn(str(CLIENT_DETAIL_LIMITS["what_to_change"]), str(caught.exception))

    def test_a_snapshot_of_controls_that_predate_the_control_detail_is_not_refused(self):
        """Same reason as `short_remediation`: `apply_catalog` snapshots the live controls
        before replacing them, and on a deployment upgraded from a release before these fields
        those rows carry nothing."""
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0],
                                    **{field: "" for field in CLIENT_DETAIL_LIMITS})]

        validated = validate_catalog_payload(payload, require_client_text=False)

        for field in CLIENT_DETAIL_LIMITS:
            self.assertEqual(validated["controls"][0][field], "")

    def test_an_inactive_control_needs_no_control_detail(self):
        payload = load_seed_payload()["catalogs"][0]
        payload["controls"] = [dict(payload["controls"][0], is_active=False,
                                    **{field: "" for field in CLIENT_DETAIL_LIMITS})]

        validated = validate_catalog_payload(payload)

        self.assertEqual(validated["controls"][0]["what_it_checks"], "")


class ControlsCatalogTests(TestCase):
    def setUp(self):
        self.application_environment = ApplicationEnvironment.objects.create(
            client_name="Example Corp",
            client_short_name="EXAMPLE",
            opportunity_number="OP-1234567",
        )

    def create_live_control(self, *, control_id: str, name: str, from_zone: str) -> Control:
        control = Control.objects.create(
            control_id=control_id,
            name=name,
            control_type=Control.ControlType.SECURITY_RULE,
            description=f"{name} description",
            remediation=f"{name} remediation",
            default_severity=Control.Severity.MEDIUM,
        )
        ControlQuery.objects.create(
            control=control,
            name="Baseline",
            short_description="Query description",
            canonical_query=build_security_rule_query(from_zone),
            is_baseline=True,
            is_active=True,
        )
        return control

    def test_create_catalog_from_current_controls_persists_payload(self):
        self.create_live_control(
            control_id="FW-RULE-001",
            name="Trust Rules",
            from_zone="trust",
        )

        catalog = create_catalog_from_current_controls(
            label="Base Controls",
            version="1.0.0",
            description="Reusable baseline controls.",
        )

        self.assertEqual(catalog.key, "base-controls")
        self.assertEqual(catalog.payload["catalog"]["key"], catalog.key)
        self.assertEqual(catalog.payload["catalog"]["label"], "Base Controls")
        self.assertEqual(catalog.payload["controls"][0]["control_id"], "FW-RULE-001")
        self.assertEqual(
            catalog.payload["controls"][0]["queries"][0]["canonical_query"]["model"],
            "integrations.SecurityRule",
        )

    def test_apply_catalog_replaces_live_controls_and_creates_snapshot(self):
        self.create_live_control(
            control_id="FW-RULE-OLD-001",
            name="Old Control",
            from_zone="trust",
        )
        AssessmentRun.objects.create(name="Old Run", status=AssessmentRun.Status.COMPLETED)
        catalog = Catalog.objects.create(
            key="base-controls",
            label="Base Controls",
            version="1.0.0",
            description="Reusable baseline controls.",
            payload={
                "type": "optivedge.assessments.catalog",
                "schema_version": "1.0",
                "catalog": {
                    "key": "base-controls",
                    "label": "Base Controls",
                    "version": "1.0.0",
                    "description": "Reusable baseline controls.",
                },
                "controls": [
                    {
                        "control_id": "FW-RULE-NEW-001",
                        "name": "New Control",
                        "control_type": "security_rule",
                        "description": "New control description",
                        "rationale": "",
                        "audit": "",
                        "remediation": "Tighten rule scope.",
                        "short_remediation": "Tighten the rule's scope.",
                        "what_it_checks": "A rule that permits traffic limits what it allows to the flow it was written for.",
                        "why_it_matters": "A rule broader than the flow it carries is access nobody is watching.",
                        "where_to_confirm": "Policies > Security, the source and destination columns of the rule.",
                        "what_to_change": "Narrow the rule to the hosts and services the flow actually needs.",
                        "default_severity": "high",
                        "implementation_version": "v1",
                        "target_model": "integrations.SecurityRule",
                        "is_active": True,
                        "queries": [
                            {
                                "name": "Baseline",
                                "short_description": "Trust zone query.",
                                "canonical_query": build_security_rule_query("dmz"),
                                "is_baseline": True,
                                "adjusted_severity": None,
                                "is_active": True,
                            }
                        ],
                    }
                ],
            },
        )

        result = apply_catalog(
            catalog=catalog,
            application_environment=self.application_environment,
        )

        self.assertIsNotNone(result.snapshot_catalog)
        self.assertTrue(result.snapshot_catalog.is_snapshot)
        self.assertEqual(result.controls_created, 1)
        self.assertEqual(result.queries_created, 1)
        self.assertEqual(result.assessment_runs_deleted, 1)
        self.assertFalse(Control.objects.filter(control_id="FW-RULE-OLD-001").exists())
        self.assertTrue(Control.objects.filter(control_id="FW-RULE-NEW-001").exists())
        state = ApplicationEnvironmentCatalogState.objects.get(
            application_environment=self.application_environment,
        )
        self.assertEqual(state.current_catalog, catalog)

    @patch("assessments.controls_catalog.io.importers.load_seed_payload")
    def test_seed_catalogs_if_empty_loads_seeded_catalogs(self, mock_load_seed_payload):
        mock_load_seed_payload.return_value = {
            "type": "optivedge.assessments.catalog_seed",
            "schema_version": "1.0",
            "catalogs": [
                {
                    "type": "optivedge.assessments.catalog",
                    "schema_version": "1.0",
                    "catalog": {
                        "key": "base-controls",
                        "label": "Base Controls",
                        "version": "1.0.0",
                        "description": "Reusable baseline controls.",
                    },
                    "controls": [],
                }
            ],
        }

        result = seed_catalogs_if_empty()

        self.assertEqual(result.catalogs_created, 1)
        self.assertEqual(Catalog.objects.count(), 1)
        self.assertTrue(Catalog.objects.get().is_seeded)

    @patch("assessments.controls_catalog.io.importers.load_seed_payload")
    def test_refresh_seeded_catalogs_updates_existing_catalog_in_place(self, mock_load_seed_payload):
        stale_catalog = Catalog.objects.create(
            key="base-controls",
            label="Base Controls",
            version="1.0.0",
            description="stale description",
            payload={
                "type": "optivedge.assessments.catalog",
                "schema_version": "1.0",
                "catalog": {
                    "key": "base-controls",
                    "label": "Base Controls",
                    "version": "1.0.0",
                    "description": "stale description",
                },
                "controls": [],
            },
            is_seeded=True,
        )
        original_pk = stale_catalog.pk
        mock_load_seed_payload.return_value = {
            "type": "optivedge.assessments.catalog_seed",
            "schema_version": "1.0",
            "catalogs": [
                {
                    "type": "optivedge.assessments.catalog",
                    "schema_version": "1.0",
                    "catalog": {
                        "key": "base-controls",
                        "label": "Base Controls",
                        "version": "1.0.1",
                        "description": "refreshed description",
                    },
                    "controls": [
                        {
                            "control_id": "FW-RULE-NEW-001",
                            "name": "New Control",
                            "control_type": "security_rule",
                            "description": "New control description",
                            "rationale": "",
                            "audit": "",
                            "remediation": "Tighten rule scope.",
                            "short_remediation": "Tighten the rule's scope.",
                            "what_it_checks": "A rule that permits traffic limits what it allows to the flow it was written for.",
                            "why_it_matters": "A rule broader than the flow it carries is access nobody is watching.",
                            "where_to_confirm": "Policies > Security, the source and destination columns of the rule.",
                            "what_to_change": "Narrow the rule to the hosts and services the flow actually needs.",
                        "short_remediation": "Tighten the rule's scope.",
                        "what_it_checks": "A rule that permits traffic limits what it allows to the flow it was written for.",
                        "why_it_matters": "A rule broader than the flow it carries is access nobody is watching.",
                        "where_to_confirm": "Policies > Security, the source and destination columns of the rule.",
                        "what_to_change": "Narrow the rule to the hosts and services the flow actually needs.",
                            "default_severity": "high",
                            "implementation_version": "v1",
                            "target_model": "integrations.SecurityRule",
                            "is_active": True,
                            "queries": [
                                {
                                    "name": "Baseline",
                                    "short_description": "Trust zone query.",
                                    "canonical_query": build_security_rule_query("dmz"),
                                    "is_baseline": True,
                                    "adjusted_severity": None,
                                    "is_active": True,
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        result = refresh_seeded_catalogs()

        self.assertEqual(result.catalogs_created, 0)
        self.assertEqual(result.catalogs_updated, 1)
        refreshed = Catalog.objects.get(key="base-controls")
        self.assertEqual(refreshed.pk, original_pk)
        self.assertEqual(refreshed.version, "1.0.1")
        self.assertEqual(refreshed.description, "refreshed description")
        self.assertEqual(refreshed.payload["controls"][0]["control_id"], "FW-RULE-NEW-001")
        # Live controls are untouched - refresh only updates the Catalog row.
        self.assertFalse(Control.objects.exists())

    @patch("assessments.controls_catalog.io.importers.load_seed_payload")
    def test_refresh_seeded_catalogs_creates_catalog_if_missing(self, mock_load_seed_payload):
        mock_load_seed_payload.return_value = {
            "type": "optivedge.assessments.catalog_seed",
            "schema_version": "1.0",
            "catalogs": [
                {
                    "type": "optivedge.assessments.catalog",
                    "schema_version": "1.0",
                    "catalog": {
                        "key": "base-controls",
                        "label": "Base Controls",
                        "version": "1.0.0",
                        "description": "Reusable baseline controls.",
                    },
                    "controls": [],
                }
            ],
        }

        result = refresh_seeded_catalogs()

        self.assertEqual(result.catalogs_created, 1)
        self.assertEqual(result.catalogs_updated, 0)
        self.assertTrue(Catalog.objects.get(key="base-controls").is_seeded)

    def test_refresh_catalog_seed_view_updates_catalog_and_redirects(self):
        Catalog.objects.create(
            key="base",
            label="Base",
            version="v1",
            description="stale",
            payload={
                "type": "optivedge.assessments.catalog",
                "schema_version": "1.0",
                "catalog": {"key": "base", "label": "Base", "version": "v1", "description": "stale"},
                "controls": [],
            },
            is_seeded=True,
        )

        response = self.client.post(reverse("assessment_catalog_refresh_seed"))

        self.assertRedirects(response, reverse("assessment_system"))
        refreshed = Catalog.objects.get(key="base")
        self.assertNotEqual(refreshed.description, "stale")

    def test_catalog_pages_render_home_and_management_views(self):
        catalog = Catalog.objects.create(
            key="base-controls",
            label="Base Controls",
            version="1.0.0",
            description="Reusable baseline controls.",
            payload={
                "type": "optivedge.assessments.catalog",
                "schema_version": "1.0",
                "catalog": {
                    "key": "base-controls",
                    "label": "Base Controls",
                    "version": "1.0.0",
                    "description": "Reusable baseline controls.",
                },
                "controls": [],
            },
            is_seeded=True,
        )
        ApplicationEnvironmentCatalogState.objects.create(
            application_environment=self.application_environment,
            current_catalog=catalog,
        )

        home_response = self.client.get(reverse("home"))
        catalog_response = self.client.get(reverse("assessment_catalog_list"))

        self.assertEqual(home_response.status_code, 200)
        self.assertContains(home_response, "Client Settings")
        self.assertEqual(catalog_response.status_code, 200)
        self.assertContains(catalog_response, "Catalogs")
        self.assertContains(catalog_response, "Snapshot Current")


class CatalogDriftTargetModelTests(TestCase):
    """Verify that target_model is included in the drift fingerprint."""

    def _make_payload(self, target_model):
        # Minimal payload with no queries so the only variable is target_model.
        return {
            "type": "optivedge.assessments.catalog",
            "schema_version": "1.0",
            "catalog": {"key": "test", "label": "Test", "version": "v1", "description": ""},
            "controls": [{
                "control_id": "TM-DRIFT-001",
                "name": "Test",
                "control_type": "security_rule",
                "description": "test",
                "rationale": "", "audit": "", "remediation": "",
                "short_remediation": "Tighten the rule's scope.",
                "what_it_checks": "A rule that permits traffic limits what it allows to the flow it was written for.",
                "why_it_matters": "A rule broader than the flow it carries is access nobody is watching.",
                "where_to_confirm": "Policies > Security, the source and destination columns of the rule.",
                "what_to_change": "Narrow the rule to the hosts and services the flow actually needs.",
                "default_severity": "medium",
                "implementation_version": "v1",
                "target_model": target_model,
                "is_active": True,
                "queries": [],
            }],
        }

    def setUp(self):
        # Live control with no queries — matches the minimal payload structure.
        Control.objects.create(
            control_id="TM-DRIFT-001",
            name="Test",
            control_type=Control.ControlType.SECURITY_RULE,
            description="test",
            default_severity=Control.Severity.MEDIUM,
        )
        # target_model auto-set to "integrations.SecurityRule" by save()

    def test_matching_target_model_no_drift(self):
        payload = self._make_payload("integrations.SecurityRule")
        self.assertFalse(catalog_has_drifted(payload))

    def test_different_target_model_reports_drift(self):
        payload = self._make_payload("integrations.OtherModel")
        self.assertTrue(catalog_has_drifted(payload))


class CatalogSchemaTargetModelValidationTests(TestCase):
    def _base_payload(self, target_model, query_model):
        return {
            "type": "optivedge.assessments.catalog",
            "schema_version": "1.0",
            "catalog": {"key": "test", "label": "Test", "version": "v1", "description": ""},
            "controls": [{
                "control_id": "SCHEMA-TM-001",
                "name": "Test",
                "control_type": "security_rule",
                "description": "test",
                "rationale": "", "audit": "", "remediation": "",
                "short_remediation": "Tighten the rule's scope.",
                "what_it_checks": "A rule that permits traffic limits what it allows to the flow it was written for.",
                "why_it_matters": "A rule broader than the flow it carries is access nobody is watching.",
                "where_to_confirm": "Policies > Security, the source and destination columns of the rule.",
                "what_to_change": "Narrow the rule to the hosts and services the flow actually needs.",
                "default_severity": "medium",
                "implementation_version": "v1",
                "target_model": target_model,
                "is_active": True,
                "queries": [{
                    "name": "Baseline",
                    "short_description": "",
                    "canonical_query": {"model": query_model, "operator": "and", "clauses": [{"field": "from_zone", "op": "eq", "value": "trust"}]},
                    "is_baseline": True,
                    "adjusted_severity": None,
                    "is_active": True,
                }],
            }],
        }

    def test_matching_target_and_query_model_valid(self):
        payload = self._base_payload("integrations.SecurityRule", "integrations.SecurityRule")
        result = validate_catalog_payload(payload)
        self.assertEqual(result["controls"][0]["target_model"], "integrations.SecurityRule")

    def test_mismatched_target_and_query_model_invalid(self):
        from django.core.exceptions import ValidationError
        payload = self._base_payload("integrations.LoginBanner", "integrations.SecurityRule")
        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload)

    def test_security_rule_with_another_models_target_invalid(self):
        from django.core.exceptions import ValidationError
        payload = self._base_payload("integrations.LoginBanner", "integrations.LoginBanner")
        # control_type=security_rule but target_model=LoginBanner — contradicts save() derivation
        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload)

    def test_config_control_with_nonempty_target_model_invalid(self):
        from django.core.exceptions import ValidationError
        payload = self._base_payload("integrations.SecurityRule", "integrations.SecurityRule")
        payload["controls"][0]["control_type"] = "config"
        with self.assertRaises(ValidationError):
            validate_catalog_payload(payload)


def build_minimal_catalog_payload(*, key: str, label: str) -> dict:
    return {
        "type": "optivedge.assessments.catalog",
        "schema_version": "1.0",
        "catalog": {"key": key, "label": label, "version": "1.0.0", "description": ""},
        "controls": [],
    }


class CatalogViewTests(TestCase):
    def setUp(self):
        self.application_environment = ApplicationEnvironment.objects.create(
            client_name="Example Corp",
            client_short_name="EXAMPLE",
            opportunity_number="OP-1234567",
        )

    def test_create_from_current_view_creates_catalog_and_redirects(self):
        Control.objects.create(
            control_id="FW-RULE-VIEW-001",
            name="View Control",
            control_type=Control.ControlType.SECURITY_RULE,
            description="desc",
            remediation="remediate",
            default_severity=Control.Severity.MEDIUM,
        )

        response = self.client.post(
            reverse("assessment_catalog_create_from_current"),
            {"label": "View Snapshot", "version": "v1", "description": "created via view"},
        )

        self.assertRedirects(response, reverse("assessment_catalog_list"))
        self.assertTrue(Catalog.objects.filter(label="View Snapshot").exists())

    def test_create_from_current_view_errors_when_no_live_controls(self):
        response = self.client.post(
            reverse("assessment_catalog_create_from_current"),
            {"label": "Empty Snapshot", "version": "v1", "description": ""},
        )

        self.assertRedirects(response, reverse("assessment_catalog_list"))
        self.assertFalse(Catalog.objects.filter(label="Empty Snapshot").exists())

    def test_apply_view_applies_catalog_and_redirects(self):
        catalog = Catalog.objects.create(
            key="view-apply",
            label="View Apply",
            version="1.0.0",
            description="",
            payload=build_minimal_catalog_payload(key="view-apply", label="View Apply"),
        )

        response = self.client.post(
            reverse("assessment_catalog_apply", kwargs={"pk": catalog.pk}),
        )

        self.assertRedirects(response, reverse("assessment_catalog_list"))
        state = ApplicationEnvironmentCatalogState.objects.get(
            application_environment=self.application_environment,
        )
        self.assertEqual(state.current_catalog, catalog)

    def test_apply_view_requires_application_environment(self):
        self.application_environment.delete()
        catalog = Catalog.objects.create(
            key="view-apply-2",
            label="View Apply 2",
            version="1.0.0",
            description="",
            payload=build_minimal_catalog_payload(key="view-apply-2", label="View Apply 2"),
        )

        response = self.client.post(
            reverse("assessment_catalog_apply", kwargs={"pk": catalog.pk}),
        )

        self.assertRedirects(response, reverse("home"))
        self.assertFalse(ApplicationEnvironmentCatalogState.objects.exists())

    def test_download_view_returns_catalog_payload_as_json_attachment(self):
        catalog = Catalog.objects.create(
            key="view-download",
            label="View Download",
            version="1.0.0",
            description="",
            payload=build_minimal_catalog_payload(key="view-download", label="View Download"),
        )

        response = self.client.get(reverse("assessment_catalog_download", kwargs={"pk": catalog.pk}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("attachment;", response["Content-Disposition"])
        payload = json.loads(response.content)
        self.assertEqual(payload["catalog"]["key"], "view-download")

    def test_seed_download_view_returns_seed_payload_as_json_attachment(self):
        response = self.client.get(reverse("assessment_catalog_seed_download"))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        self.assertIn("attachment;", response["Content-Disposition"])
        payload = json.loads(response.content)
        self.assertEqual(payload["type"], "optivedge.assessments.catalog_seed")
