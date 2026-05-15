"""Plain-language to canonical security-rule query translation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from assessments.plain_language.security_rules.concepts import (
    detect_request_concepts,
    validate_detected_concepts,
)
from assessments.plain_language.security_rules.grounding import (
    GroundedVocabularyCandidate,
    build_grounding_context_from_candidates,
    find_grounded_candidates,
)
from assessments.plain_language.security_rules.client import (
    OpenAIResponsesClient,
    StructuredResponseResult,
)
from assessments.plain_language.security_rules.exceptions import (
    PlainLanguageSecurityRuleQueryError,
)
from assessments.plain_language.security_rules.prompting import (
    build_initial_user_prompt,
    build_repair_user_prompt,
    build_security_rule_translation_system_prompt,
)
from assessments.plain_language.security_rules.schema import (
    build_security_rule_query_json_schema,
)
from assessments.search.exceptions import SearchSyntaxError
from assessments.search.syntax import validate_search_payload


@dataclass(frozen=True)
class PlainLanguageSecurityRuleTranslation:
    canonical_query: dict
    attempts: int
    response_id: str
    model: str

GROUNDED_FIELD_FAMILIES = {
    "source_address_name": "source_address_name",
    "destination_address_name": "destination_address_name",
    "application": "application",
    "service": "service",
}
STRONG_GROUNDING_SCORE = 6


def _collect_clause_fields(node: dict) -> set[str]:
    if "field" in node:
        return {node["field"]}

    fields: set[str] = set()
    for clause in node.get("clauses", []):
        fields.update(_collect_clause_fields(clause))
    return fields


def _collect_clause_values_by_field(node: dict) -> dict[str, list[str]]:
    if "field" in node:
        return {node["field"]: [node["value"]]}

    collected: dict[str, list[str]] = {}
    for clause in node.get("clauses", []):
        child_values = _collect_clause_values_by_field(clause)
        for field_name, values in child_values.items():
            collected.setdefault(field_name, []).extend(values)
    return collected


def validate_grounded_value_alignment(
    canonical_query: dict,
    grounded_candidates_by_family: dict[str, list[GroundedVocabularyCandidate]],
) -> None:
    if not grounded_candidates_by_family:
        return

    clause_values_by_field = _collect_clause_values_by_field(canonical_query)
    misaligned_families: list[str] = []

    for field_name, field_family in GROUNDED_FIELD_FAMILIES.items():
        candidates = grounded_candidates_by_family.get(field_family, [])
        if not candidates or candidates[0].score < STRONG_GROUNDING_SCORE:
            continue

        clause_values = clause_values_by_field.get(field_name, [])
        if not clause_values:
            continue
        if any(_clause_value_aligns_with_candidates(value, candidates) for value in clause_values):
            continue

        candidate_preview = ", ".join(candidate.canonical_value for candidate in candidates[:3])
        misaligned_families.append(f"{field_family} ({candidate_preview})")

    if misaligned_families:
        raise SearchSyntaxError(
            "Canonical query used non-grounded values despite strong local vocabulary candidates for: "
            + "; ".join(misaligned_families)
            + ". Prefer local canonical values, and prefer contains over eq when the request describes a broad family."
        )


def _clause_value_aligns_with_candidates(
    clause_value: str,
    candidates: list[GroundedVocabularyCandidate],
) -> bool:
    normalized_clause = _normalize_lookup_value(clause_value)
    compact_clause = _compact_lookup_value(clause_value)
    canonicalish = _looks_like_canonical_value(clause_value)

    for candidate in candidates:
        if clause_value == candidate.canonical_value:
            return True

        normalized_candidate = _normalize_lookup_value(candidate.canonical_value)
        compact_candidate = _compact_lookup_value(candidate.canonical_value)

        if canonicalish and (
            normalized_clause == normalized_candidate
            or (normalized_clause and normalized_clause in normalized_candidate)
            or (compact_clause and compact_clause in compact_candidate)
        ):
            return True

    return False


def _normalize_lookup_value(value: str) -> str:
    lowered = value.strip().lower()
    separated = re.sub(r"[^a-z0-9]+", " ", lowered)
    return re.sub(r"\s+", " ", separated).strip()


def _compact_lookup_value(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def _looks_like_canonical_value(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    if any(marker in stripped for marker in ("-", "_")):
        return True
    lowered = stripped.lower()
    return lowered.startswith(("ao", "ag", "ms", "svc", "tcp", "udp")) and " " not in stripped


def translate_plain_language_security_rule_query(
    request_text: str,
    *,
    client: OpenAIResponsesClient | None = None,
    max_attempts: int = 3,
) -> PlainLanguageSecurityRuleTranslation:
    trimmed_request = request_text.strip()
    if not trimmed_request:
        raise PlainLanguageSecurityRuleQueryError("Plain-language query text must not be empty.")

    translator_client = client or OpenAIResponsesClient()
    system_prompt = build_security_rule_translation_system_prompt()
    response_format = build_security_rule_query_json_schema()
    grounded_candidates_by_family = find_grounded_candidates(trimmed_request)
    grounding_context = build_grounding_context_from_candidates(grounded_candidates_by_family)
    detected_concepts = detect_request_concepts(
        trimmed_request,
        grounded_candidates_by_family,
        strong_grounding_score=STRONG_GROUNDING_SCORE,
    )

    previous_result: StructuredResponseResult | None = None
    last_error: str | None = None

    for attempt_number in range(1, max_attempts + 1):
        if attempt_number == 1:
            user_prompt = build_initial_user_prompt(
                trimmed_request,
                grounding_context=grounding_context,
            )
        else:
            previous_query_json = json.dumps(previous_result.payload, indent=2, sort_keys=True)
            user_prompt = build_repair_user_prompt(
                request_text=trimmed_request,
                previous_query_json=previous_query_json,
                validation_error=last_error or "Unknown validation error.",
                grounding_context=grounding_context,
            )

        result = translator_client.generate_structured_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
        )
        previous_result = result

        try:
            canonical_query = validate_search_payload(result.payload)
            clause_fields = _collect_clause_fields(canonical_query)
            clause_values_by_field = _collect_clause_values_by_field(canonical_query)
            validate_detected_concepts(
                detected_concepts,
                clause_fields,
                clause_values_by_field,
            )
            validate_grounded_value_alignment(canonical_query, grounded_candidates_by_family)
        except SearchSyntaxError as exc:
            last_error = str(exc)
            if attempt_number == max_attempts:
                raise PlainLanguageSecurityRuleQueryError(
                    f"OpenAI could not produce a valid security rule query: {last_error}"
                ) from exc
            continue

        return PlainLanguageSecurityRuleTranslation(
            canonical_query=canonical_query,
            attempts=attempt_number,
            response_id=result.response_id,
            model=result.model,
        )

    raise PlainLanguageSecurityRuleQueryError(
        "OpenAI could not produce a valid security rule query."
    )
