"""Lightweight grounding helpers for security-rule plain-language translation."""

from __future__ import annotations

import re
from dataclasses import dataclass

from django.db import OperationalError, ProgrammingError

from optivedge_integrations.integrations.models import SecurityRuleSearchVocabularyEntry


STOPWORDS = {
    "a",
    "an",
    "and",
    "any",
    "application",
    "applications",
    "address",
    "addresses",
    "destination",
    "find",
    "for",
    "from",
    "going",
    "in",
    "is",
    "name",
    "names",
    "of",
    "on",
    "or",
    "rule",
    "rules",
    "service",
    "services",
    "show",
    "source",
    "the",
    "to",
    "traffic",
    "where",
    "whose",
    "with",
}

FIELD_FAMILY_LABELS = {
    SecurityRuleSearchVocabularyEntry.FieldFamily.SOURCE_ADDRESS_NAME: "source_address_name",
    SecurityRuleSearchVocabularyEntry.FieldFamily.DESTINATION_ADDRESS_NAME: "destination_address_name",
    SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION: "application",
    SecurityRuleSearchVocabularyEntry.FieldFamily.SERVICE: "service",
}


@dataclass(frozen=True, slots=True)
class GroundedVocabularyCandidate:
    canonical_value: str
    rule_count: int
    usage_count: int
    score: int


def build_grounding_context(request_text: str, *, candidate_limit_per_family: int = 5) -> str:
    candidates_by_family = find_grounded_candidates(
        request_text,
        candidate_limit_per_family=candidate_limit_per_family,
    )
    return build_grounding_context_from_candidates(candidates_by_family)


def build_grounding_context_from_candidates(
    candidates_by_family: dict[str, list[GroundedVocabularyCandidate]],
) -> str:
    if not candidates_by_family:
        return ""

    lines = [
        "Local canonical vocabulary candidates relevant to this request:",
        "Prefer exact canonical values from this list when they fit the request.",
    ]
    for field_family in SecurityRuleSearchVocabularyEntry.FieldFamily.values:
        candidates = candidates_by_family.get(field_family, [])
        if not candidates:
            continue
        lines.append(f"- {FIELD_FAMILY_LABELS[field_family]} candidates:")
        for candidate in candidates:
            lines.append(
                f"  - {candidate.canonical_value} "
                f"(rules: {candidate.rule_count}, uses: {candidate.usage_count})"
            )
    return "\n".join(lines)


def find_grounded_candidates(
    request_text: str,
    *,
    candidate_limit_per_family: int = 5,
) -> dict[str, list[GroundedVocabularyCandidate]]:
    normalized_request = SecurityRuleSearchVocabularyEntry.normalize_lookup_value(request_text)
    compact_request = SecurityRuleSearchVocabularyEntry.compact_lookup_value(request_text)
    request_tokens = _tokenize_text(request_text)
    if not request_tokens and not normalized_request and not compact_request:
        return {}

    try:
        vocabulary_entries = list(
            SecurityRuleSearchVocabularyEntry.objects.order_by(
                "field_family",
                "-rule_count",
                "-usage_count",
                "canonical_value",
                "pk",
            )
        )
    except (OperationalError, ProgrammingError):
        return {}

    results: dict[str, list[GroundedVocabularyCandidate]] = {}
    for field_family in SecurityRuleSearchVocabularyEntry.FieldFamily.values:
        scored_candidates: list[GroundedVocabularyCandidate] = []
        for entry in vocabulary_entries:
            if entry.field_family != field_family:
                continue
            score = _score_vocabulary_entry(
                entry,
                normalized_request=normalized_request,
                compact_request=compact_request,
                request_tokens=request_tokens,
            )
            if score <= 0:
                continue
            scored_candidates.append(
                GroundedVocabularyCandidate(
                    canonical_value=entry.canonical_value,
                    rule_count=entry.rule_count,
                    usage_count=entry.usage_count,
                    score=score,
                )
            )

        if not scored_candidates:
            continue

        scored_candidates.sort(
            key=lambda candidate: (
                -candidate.score,
                -candidate.rule_count,
                -candidate.usage_count,
                candidate.canonical_value,
            )
        )
        results[field_family] = scored_candidates[:candidate_limit_per_family]
    return results


def _score_vocabulary_entry(
    entry: SecurityRuleSearchVocabularyEntry,
    *,
    normalized_request: str,
    compact_request: str,
    request_tokens: set[str],
) -> int:
    score = 0
    if entry.normalized_value and entry.normalized_value in normalized_request:
        score += 12
    if entry.compact_value and entry.compact_value in compact_request:
        score += 10

    entry_tokens = _tokenize_text(entry.canonical_value)
    overlap = entry_tokens & request_tokens
    score += len(overlap) * 3

    if overlap and len(entry_tokens) <= len(overlap):
        score += 4

    if entry.field_family in {
        SecurityRuleSearchVocabularyEntry.FieldFamily.APPLICATION,
        SecurityRuleSearchVocabularyEntry.FieldFamily.SERVICE,
    } and overlap:
        score += 2

    return score


def _tokenize_text(value: str) -> set[str]:
    normalized = SecurityRuleSearchVocabularyEntry.normalize_lookup_value(value)
    primary_tokens = set(token for token in normalized.split() if token and token not in STOPWORDS)
    segmented_tokens = {
        token
        for token in re.findall(r"[a-z]+|\d+", value.lower())
        if token and token not in STOPWORDS
    }
    return primary_tokens | segmented_tokens
