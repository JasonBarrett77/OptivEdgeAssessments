"""Concept detection and semantic validation for security-rule plain-language translation."""

from __future__ import annotations

import re
from dataclasses import dataclass

from assessments.plain_language.security_rules.grounding import GroundedVocabularyCandidate
from assessments.search.exceptions import SearchSyntaxError


STATE_FIELD = "disabled"


@dataclass(frozen=True, slots=True)
class RequestConcept:
    name: str
    acceptable_fields: frozenset[str]
    kind: str
    expected_disabled_value: str | None = None


EXPLICIT_CONCEPT_SPECS = (
    (
        "source_address",
        frozenset({"source_address", "source_address_name"}),
        "field_family",
        (
            r"\bsource\s+address(?:\s+name)?\b",
            r"\bsource\s+(?:object|objects|group|groups|token|tokens)\b",
            r"\bsource\s+(?:is|matches|includes|intersects|equals|exactly)\b",
        ),
        None,
    ),
    (
        "destination_address",
        frozenset({"destination_address", "destination_address_name"}),
        "field_family",
        (
            r"\bdestination\s+address(?:\s+name)?\b",
            r"\bdestination\s+(?:object|objects|group|groups|token|tokens)\b",
            r"\bdestination\s+(?:is|matches|includes|intersects|equals|exactly)\b",
        ),
        None,
    ),
    (
        "source_zone",
        frozenset({"from_zone"}),
        "field_family",
        (
            r"\bsource\s+zone\b",
            r"\bfrom\s+zone\b",
        ),
        None,
    ),
    (
        "destination_zone",
        frozenset({"to_zone"}),
        "field_family",
        (
            r"\bdestination\s+zone\b",
            r"\bto\s+zone\b",
        ),
        None,
    ),
    (
        "application",
        frozenset({"application"}),
        "field_family",
        (
            r"\bapplication\b",
            r"\bapplications\b",
            r"\bapp\b",
            r"\bapps\b",
        ),
        None,
    ),
    (
        "service",
        frozenset({"service"}),
        "field_family",
        (
            r"\bservice\b",
            r"\bservices\b",
        ),
        None,
    ),
    (
        "enabled_state",
        frozenset({STATE_FIELD}),
        "disabled_state",
        (
            r"\benabled\b",
            r"\bactive\b",
        ),
        "false",
    ),
    (
        "disabled_state",
        frozenset({STATE_FIELD}),
        "disabled_state",
        (
            r"\bdisabled\b",
            r"\bturned\s+off\b",
        ),
        "true",
    ),
)

GROUNDED_DIRECTIONAL_PATTERNS = (
    r"\bgoing\s+to\b",
    r"\breach\b",
    r"\breaches\b",
    r"\breaching\b",
    r"\baccess(?:ing)?\b",
    r"\btraffic\s+to\b",
    r"\bto\b",
)

GROUNDED_SOURCE_PATTERNS = (
    r"\bfrom\b",
    r"\blet\b",
    r"\ballow\b",
    r"\ballows\b",
    r"\bsource\b",
)


def detect_request_concepts(
    request_text: str,
    grounded_candidates_by_family: dict[str, list[GroundedVocabularyCandidate]],
    *,
    strong_grounding_score: int,
) -> list[RequestConcept]:
    concepts: list[RequestConcept] = []
    for name, acceptable_fields, kind, patterns, expected_disabled_value in EXPLICIT_CONCEPT_SPECS:
        if _matches_any_pattern(request_text, patterns):
            concepts.append(
                RequestConcept(
                    name=name,
                    acceptable_fields=acceptable_fields,
                    kind=kind,
                    expected_disabled_value=expected_disabled_value,
                )
            )

    explicit_concept_names = {concept.name for concept in concepts}

    if _has_strong_grounding(grounded_candidates_by_family.get("destination_address_name", []), strong_grounding_score):
        if (
            "destination_zone" not in explicit_concept_names
            and "destination_address" not in explicit_concept_names
            and _matches_any_pattern(request_text, GROUNDED_DIRECTIONAL_PATTERNS)
        ):
            _append_unique_concept(
                concepts,
                RequestConcept(
                    name="grounded_destination_address",
                    acceptable_fields=frozenset({"destination_address", "destination_address_name"}),
                    kind="field_family",
                ),
            )

    if _has_strong_grounding(grounded_candidates_by_family.get("source_address_name", []), strong_grounding_score):
        if (
            "source_zone" not in explicit_concept_names
            and "source_address" not in explicit_concept_names
            and _matches_any_pattern(request_text, GROUNDED_SOURCE_PATTERNS)
        ):
            _append_unique_concept(
                concepts,
                RequestConcept(
                    name="grounded_source_address",
                    acceptable_fields=frozenset({"source_address", "source_address_name"}),
                    kind="field_family",
                ),
            )

    return concepts


def validate_detected_concepts(
    concepts: list[RequestConcept],
    clause_fields: set[str],
    clause_values_by_field: dict[str, list[str]],
) -> None:
    missing_concepts: list[str] = []

    for concept in concepts:
        if concept.kind == "field_family":
            if not (clause_fields & concept.acceptable_fields):
                missing_concepts.append(concept.name.replace("_", " "))
            continue

        if concept.kind == "disabled_state":
            values = clause_values_by_field.get(STATE_FIELD, [])
            if concept.expected_disabled_value is None or concept.expected_disabled_value not in values:
                missing_concepts.append(concept.name.replace("_", " "))

    if missing_concepts:
        joined = ", ".join(missing_concepts)
        raise SearchSyntaxError(
            "Canonical query omitted or contradicted request concepts: "
            f"{joined}. Preserve each detected concept family from the original request."
        )


def _has_strong_grounding(
    candidates: list[GroundedVocabularyCandidate],
    strong_grounding_score: int,
) -> bool:
    return bool(candidates) and candidates[0].score >= strong_grounding_score


def _matches_any_pattern(request_text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, request_text, flags=re.IGNORECASE) for pattern in patterns)


def _append_unique_concept(concepts: list[RequestConcept], concept: RequestConcept) -> None:
    if concept not in concepts:
        concepts.append(concept)
