"""Minimal OpenAI Responses API client for plain-language translation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib import error, request

from assessments.plain_language.security_rules.exceptions import (
    OpenAIResponsesError,
    OpenAIResponsesRefusalError,
)


RESPONSES_API_URL = "https://api.openai.com/v1/responses"


def get_development_openai_api_key() -> str:
    from _scratch.openai_key import get_openai_api_key

    return get_openai_api_key()


@dataclass(frozen=True)
class StructuredResponseResult:
    response_id: str
    model: str
    payload: dict[str, Any]
    raw_response: dict[str, Any]


class OpenAIResponsesClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "gpt-5.5",
        service_tier: str = "flex",
        reasoning_effort: str = "medium",
        timeout_seconds: float = 180.0,
    ):
        self.api_key = api_key or get_development_openai_api_key()
        self.model = model
        self.service_tier = service_tier
        self.reasoning_effort = reasoning_effort
        self.timeout_seconds = timeout_seconds

    def generate_structured_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_format: dict[str, Any],
    ) -> StructuredResponseResult:
        payload = self._post(
            {
                "model": self.model,
                "service_tier": self.service_tier,
                "reasoning": {"effort": self.reasoning_effort},
                "input": [
                    {
                        "role": "system",
                        "content": [{"type": "input_text", "text": system_prompt}],
                    },
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": user_prompt}],
                    },
                ],
                "text": {
                    "format": {
                        "type": "json_schema",
                        **response_format,
                    }
                },
            }
        )
        output_text = self._extract_output_text(payload)
        try:
            parsed_payload = json.loads(output_text)
        except json.JSONDecodeError as exc:
            raise OpenAIResponsesError("OpenAI returned invalid JSON for the security rule query.") from exc

        return StructuredResponseResult(
            response_id=payload.get("id", ""),
            model=payload.get("model", self.model),
            payload=parsed_payload,
            raw_response=payload,
        )

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        encoded_payload = json.dumps(payload).encode("utf-8")
        http_request = request.Request(
            RESPONSES_API_URL,
            data=encoded_payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with request.urlopen(http_request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            try:
                error_payload = json.loads(detail)
                message = error_payload.get("error", {}).get("message", detail)
            except json.JSONDecodeError:
                message = detail or str(exc)
            raise OpenAIResponsesError(f"OpenAI Responses API request failed: {message}") from exc
        except error.URLError as exc:
            raise OpenAIResponsesError(f"OpenAI Responses API request failed: {exc.reason}") from exc

    def _extract_output_text(self, payload: dict[str, Any]) -> str:
        output_text = payload.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text

        for output_item in payload.get("output", []):
            if output_item.get("type") != "message":
                continue
            for content_item in output_item.get("content", []):
                if content_item.get("type") == "output_text":
                    text_value = content_item.get("text", "")
                    if text_value.strip():
                        return text_value
                if content_item.get("type") == "refusal":
                    refusal_text = content_item.get("refusal", "").strip() or "The model refused the request."
                    raise OpenAIResponsesRefusalError(refusal_text)

        raise OpenAIResponsesError("OpenAI returned no structured output text for the security rule query.")

