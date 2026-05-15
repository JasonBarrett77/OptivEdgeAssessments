"""Exceptions for plain-language security-rule query translation."""

from __future__ import annotations


class PlainLanguageSecurityRuleQueryError(Exception):
    """Base error for plain-language security-rule query translation."""


class OpenAIResponsesError(PlainLanguageSecurityRuleQueryError):
    """Responses API request or parsing error."""


class OpenAIResponsesRefusalError(PlainLanguageSecurityRuleQueryError):
    """Model refusal while translating plain language into a rule query."""

