import urllib.parse
from unittest.mock import patch

from django.test import TestCase
from django.urls import reverse

from assessments.models import SecurityRuleSearchState
from assessments.plain_language.security_rules.client import StructuredResponseResult
from assessments.plain_language.security_rules.concepts import (
    detect_request_concepts,
    validate_detected_concepts,
)
from assessments.plain_language.security_rules.grounding import GroundedVocabularyCandidate
from assessments.plain_language.security_rules.exceptions import (
    PlainLanguageSecurityRuleQueryError,
)
from assessments.plain_language.security_rules.translator import (
    PlainLanguageSecurityRuleTranslation,
    translate_plain_language_security_rule_query,
)
from assessments.search.exceptions import SearchSyntaxError
from optivedge.integrations.models import ManagementStation, SecurityRuleSearchVocabularyEntry


class FakeResponsesClient:
    def __init__(self, payloads):
        self.payloads = payloads
        self.calls = []

    def generate_structured_json(self, *, system_prompt, user_prompt, response_format):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "response_format": response_format,
            }
        )
        payload = self.payloads[len(self.calls) - 1]
        return StructuredResponseResult(
            response_id=f"resp_{len(self.calls)}",
            model="gpt-5.5",
            payload=payload,
            raw_response={"id": f"resp_{len(self.calls)}"},
        )


class PlainLanguageSecurityRuleTranslatorTests(TestCase):
    def test_translate_plain_language_security_rule_query_repairs_invalid_first_attempt(self):
        client = FakeResponsesClient(
            [
                {
                    "model": "integrations.SecurityRule",
                    "operator": "and",
                    "clauses": [
                        {
                            "field": "from_zone",
                            "op": "matches",
                            "value": "trust",
                        }
                    ],
                },
                {
                    "model": "integrations.SecurityRule",
                    "operator": "and",
                    "clauses": [
                        {
                            "field": "from_zone",
                            "op": "eq",
                            "value": "trust",
                        }
                    ],
                },
            ]
        )

        translation = translate_plain_language_security_rule_query(
            "Show trust rules.",
            client=client,
        )

        self.assertEqual(translation.attempts, 2)
        self.assertEqual(translation.canonical_query["clauses"][0]["field"], "from_zone")
        self.assertEqual(translation.canonical_query["clauses"][0]["op"], "eq")
        self.assertEqual(len(client.calls), 2)
        self.assertIn("Validation error:", client.calls[1]["user_prompt"])

    def test_translate_plain_language_security_rule_query_repairs_missing_destination_clause(self):
        client = FakeResponsesClient(
            [
                {
                    "model": "integrations.SecurityRule",
                    "operator": "and",
                    "clauses": [
                        {
                            "operator": "or",
                            "clauses": [
                                {
                                    "field": "source_address_name",
                                    "op": "contains",
                                    "value": "ao-remote-workforce-vpn-users",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                                {
                                    "field": "source_address_name",
                                    "op": "contains",
                                    "value": "ao-managed-wireless-laptops",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                            ],
                        },
                        {
                            "operator": "or",
                            "clauses": [
                                {
                                    "field": "application",
                                    "op": "contains",
                                    "value": "ms-teams",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                                {
                                    "field": "application",
                                    "op": "contains",
                                    "value": "ms-office365-base",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                            ],
                        },
                        {
                            "operator": "or",
                            "clauses": [
                                {
                                    "field": "service",
                                    "op": "eq",
                                    "value": "any",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                                {
                                    "field": "service",
                                    "op": "eq",
                                    "value": "application-default",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                            ],
                        },
                    ],
                },
                {
                    "model": "integrations.SecurityRule",
                    "operator": "and",
                    "clauses": [
                        {
                            "operator": "or",
                            "clauses": [
                                {
                                    "field": "source_address_name",
                                    "op": "contains",
                                    "value": "ao-remote-workforce-vpn-users",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                                {
                                    "field": "source_address_name",
                                    "op": "contains",
                                    "value": "ao-managed-wireless-laptops",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                            ],
                        },
                        {
                            "field": "destination_address_name",
                            "op": "contains",
                            "value": "sanctioned-saas",
                            "negated": False,
                            "case_sensitive": False,
                            "include_any": False,
                        },
                        {
                            "operator": "or",
                            "clauses": [
                                {
                                    "field": "application",
                                    "op": "contains",
                                    "value": "ms-teams",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                                {
                                    "field": "application",
                                    "op": "contains",
                                    "value": "ms-office365-base",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                            ],
                        },
                        {
                            "operator": "or",
                            "clauses": [
                                {
                                    "field": "service",
                                    "op": "eq",
                                    "value": "any",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                                {
                                    "field": "service",
                                    "op": "eq",
                                    "value": "application-default",
                                    "negated": False,
                                    "case_sensitive": False,
                                    "include_any": False,
                                },
                            ],
                        },
                    ],
                },
            ]
        )

        translation = translate_plain_language_security_rule_query(
            (
                "Show security rules where the source address name contains either "
                "ao-remote-workforce-vpn-users or ao-managed-wireless-laptops AND the "
                "destination address name contains sanctioned-saas AND the application "
                "contains either ms-teams or ms-office365-base AND the service is "
                "either any or application-default."
            ),
            client=client,
        )

        self.assertEqual(translation.attempts, 2)
        self.assertIn("Validation error:", client.calls[1]["user_prompt"])
        self.assertIn("destination", client.calls[1]["user_prompt"].lower())
        self.assertEqual(
            translation.canonical_query["clauses"][1]["field"],
            "destination_address_name",
        )

    def test_translate_plain_language_security_rule_query_rejects_empty_request(self):
        with self.assertRaisesMessage(
            PlainLanguageSecurityRuleQueryError,
            "Plain-language query text must not be empty.",
        ):
            translate_plain_language_security_rule_query("   ")

    def test_detected_concepts_allow_source_zone_query_without_source_address_field(self):
        concepts = detect_request_concepts(
            "Show rules in source zone trust.",
            {},
            strong_grounding_score=6,
        )
        validate_detected_concepts(
            concepts,
            {"from_zone"},
            {"from_zone": ["trust"]},
        )

    def test_detected_concepts_reject_missing_destination_for_directional_query(self):
        concepts = detect_request_concepts(
            "Show Teams rules going to sanctioned SaaS.",
            {
                "destination_address_name": [
                    GroundedVocabularyCandidate(
                        canonical_value="ao-sanctioned-saas-provider-endpoints-01",
                        rule_count=5,
                        usage_count=7,
                        score=10,
                    ),
                ]
            },
            strong_grounding_score=6,
        )
        with self.assertRaisesMessage(SearchSyntaxError, "destination address"):
            validate_detected_concepts(
                concepts,
                {"application"},
                {"application": ["ms-teams"]},
            )

    def test_detected_concepts_do_not_infer_destination_address_when_destination_zone_is_explicit(self):
        concepts = detect_request_concepts(
            "Show enabled rules from source zone transit to destination zone internet.",
            {
                "destination_address_name": [
                    GroundedVocabularyCandidate(
                        canonical_value="ao-internet-services-01",
                        rule_count=8,
                        usage_count=10,
                        score=10,
                    ),
                ]
            },
            strong_grounding_score=6,
        )

        concept_names = {concept.name for concept in concepts}
        self.assertIn("source_zone", concept_names)
        self.assertIn("destination_zone", concept_names)
        self.assertNotIn("grounded_destination_address", concept_names)

    def test_detected_concepts_do_not_infer_source_address_when_source_zone_is_explicit(self):
        concepts = detect_request_concepts(
            "Show rules from source zone transit.",
            {
                "source_address_name": [
                    GroundedVocabularyCandidate(
                        canonical_value="ao-transit-users-01",
                        rule_count=4,
                        usage_count=6,
                        score=9,
                    ),
                ]
            },
            strong_grounding_score=6,
        )

        concept_names = {concept.name for concept in concepts}
        self.assertIn("source_zone", concept_names)
        self.assertNotIn("grounded_source_address", concept_names)

    def test_translate_plain_language_security_rule_query_includes_grounded_vocabulary_in_prompt(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        SecurityRuleSearchVocabularyEntry.objects.create(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.DESTINATION_ADDRESS_NAME,
            canonical_value="ao-sanctioned-saas-provider-endpoints-01",
            rule_count=5,
            usage_count=7,
        )
        SecurityRuleSearchVocabularyEntry.objects.create(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION,
            canonical_value="ms-office365-base",
            rule_count=4,
            usage_count=4,
        )

        client = FakeResponsesClient(
            [
                {
                    "model": "integrations.SecurityRule",
                    "operator": "and",
                    "clauses": [
                        {
                            "field": "destination_address_name",
                            "op": "contains",
                            "value": "ao-sanctioned-saas-provider-endpoints-01",
                            "negated": False,
                            "case_sensitive": False,
                            "include_any": False,
                        },
                        {
                            "field": "application",
                            "op": "contains",
                            "value": "ms-office365-base",
                            "negated": False,
                            "case_sensitive": False,
                            "include_any": False,
                        },
                    ],
                }
            ]
        )

        translate_plain_language_security_rule_query(
            "Show Office 365 rules going to sanctioned SaaS.",
            client=client,
        )

        self.assertEqual(len(client.calls), 1)
        self.assertIn(
            "ao-sanctioned-saas-provider-endpoints-01",
            client.calls[0]["user_prompt"],
        )
        self.assertIn(
            "ms-office365-base",
            client.calls[0]["user_prompt"],
        )

    def test_translate_plain_language_security_rule_query_repairs_valid_but_ungrounded_values(self):
        station = ManagementStation.objects.create(
            station_type=ManagementStation.StationType.PAN_PANORAMA,
            hostname="panorama.local",
        )
        SecurityRuleSearchVocabularyEntry.objects.create(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.DESTINATION_ADDRESS_NAME,
            canonical_value="ao-sanctioned-saas-provider-endpoints-01",
            rule_count=5,
            usage_count=7,
        )
        SecurityRuleSearchVocabularyEntry.objects.create(
            management_station=station,
            field_family=SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION,
            canonical_value="ms-office365-base",
            rule_count=4,
            usage_count=4,
        )

        client = FakeResponsesClient(
            [
                {
                    "model": "integrations.SecurityRule",
                    "operator": "and",
                    "clauses": [
                        {
                            "field": "destination_address_name",
                            "op": "contains",
                            "value": "sanctioned SaaS",
                            "negated": False,
                            "case_sensitive": False,
                            "include_any": False,
                        },
                        {
                            "field": "application",
                            "op": "contains",
                            "value": "Office 365",
                            "negated": False,
                            "case_sensitive": False,
                            "include_any": False,
                        },
                    ],
                },
                {
                    "model": "integrations.SecurityRule",
                    "operator": "and",
                    "clauses": [
                        {
                            "field": "destination_address_name",
                            "op": "contains",
                            "value": "sanctioned-saas",
                            "negated": False,
                            "case_sensitive": False,
                            "include_any": False,
                        },
                        {
                            "field": "application",
                            "op": "eq",
                            "value": "ms-office365-base",
                            "negated": False,
                            "case_sensitive": False,
                            "include_any": False,
                        },
                    ],
                },
            ]
        )

        translation = translate_plain_language_security_rule_query(
            "Show Office 365 rules going to sanctioned SaaS.",
            client=client,
        )

        self.assertEqual(translation.attempts, 2)
        self.assertIn("non-grounded values", client.calls[1]["user_prompt"])
        self.assertEqual(
            translation.canonical_query["clauses"][0]["value"],
            "sanctioned-saas",
        )
        self.assertEqual(
            translation.canonical_query["clauses"][1]["value"],
            "ms-office365-base",
        )


class PlainLanguageSecurityRuleQueryViewTests(TestCase):
    def test_get_renders_plain_language_query_page(self):
        response = self.client.get(reverse("assessment_security_rule_plain_language"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Plain-Language Security Rule Query")
        self.assertContains(response, "Build Query")

    def test_post_creates_search_state_and_redirects_into_builder(self):
        canonical_query = {
            "model": "integrations.SecurityRule",
            "operator": "and",
            "clauses": [
                {
                    "field": "source_address",
                    "op": "matches",
                    "value": "10.0.0.0/8",
                    "include_any": True,
                }
            ],
        }

        with patch(
            "assessments.plain_language.views.translate_plain_language_security_rule_query",
            return_value=PlainLanguageSecurityRuleTranslation(
                canonical_query=canonical_query,
                attempts=1,
                response_id="resp_test",
                model="gpt-5.5",
            ),
        ):
            response = self.client.post(
                reverse("assessment_security_rule_plain_language"),
                data={"request_text": "Show rules whose source matches 10.0.0.0/8, including any."},
            )

        self.assertEqual(response.status_code, 302)
        location = response["Location"]
        self.assertTrue(
            location.startswith(f"{reverse('assessment_security_rule_list')}?edit_search=1&search_state=")
        )

        search_state = SecurityRuleSearchState.objects.get()
        self.assertEqual(search_state.query_text, "Show rules whose source matches 10.0.0.0/8, including any.")
        self.assertEqual(search_state.canonical_query, canonical_query)

        parsed = urllib.parse.urlparse(location)
        params = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(params.get("edit_search"), ["1"])
        self.assertEqual(str(search_state.token), params["search_state"][0])

    def test_post_renders_translation_error_inline(self):
        with patch(
            "assessments.plain_language.views.translate_plain_language_security_rule_query",
            side_effect=PlainLanguageSecurityRuleQueryError("translation failed"),
        ):
            response = self.client.post(
                reverse("assessment_security_rule_plain_language"),
                data={"request_text": "Show the impossible thing."},
            )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "translation failed")
        self.assertEqual(SecurityRuleSearchState.objects.count(), 0)

    def test_get_with_search_state_prefills_existing_plain_language_prompt(self):
        search_state = SecurityRuleSearchState.objects.create(
            query_text="Show rules from transit to internet.",
            canonical_query={
                "model": "integrations.SecurityRule",
                "operator": "and",
                "clauses": [],
            },
        )

        response = self.client.get(
            reverse("assessment_security_rule_plain_language"),
            {"search_state": str(search_state.token)},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Editing the plain-language prompt used to generate the current builder query.",
        )
        self.assertContains(response, "Show rules from transit to internet.")
        self.assertContains(
            response,
            f'{reverse("assessment_security_rule_list")}?edit_search=1&amp;search_state={search_state.token}',
            html=False,
        )

    def test_security_rule_builder_shows_edit_prompt_link_when_query_text_exists(self):
        search_state = SecurityRuleSearchState.objects.create(
            query_text="Show rules whose source matches 10.0.0.0/8.",
            canonical_query={
                "model": "integrations.SecurityRule",
                "operator": "and",
                "clauses": [
                    {
                        "field": "source_address",
                        "op": "matches",
                        "value": "10.0.0.0/8",
                        "negated": False,
                        "case_sensitive": False,
                        "include_any": False,
                    }
                ],
            },
        )

        response = self.client.get(
            reverse("assessment_security_rule_list"),
            {
                "edit_search": "1",
                "search_state": str(search_state.token),
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            f'{reverse("assessment_security_rule_plain_language")}?search_state={search_state.token}',
            html=False,
        )
        self.assertContains(response, "Edit Prompt")
