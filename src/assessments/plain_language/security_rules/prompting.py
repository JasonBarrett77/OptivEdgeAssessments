"""Prompt construction for plain-language security-rule translation."""

from __future__ import annotations

from functools import lru_cache

from assessments.search.security_rules.compiler import FIELD_OPERATOR_REGISTRY


FIELD_DESCRIPTIONS = {
    "action": "Rule action such as allow or deny.",
    "application": "Application member values on the rule.",
    "config_source": "Rule config source like local or pushed_pre.",
    "description": "Rule description text.",
    "disabled": "Disabled state using true/false string values.",
    "destination_address": "Semantic IPv4 destination matching using matches/includes/exactly/intersects/equals.",
    "destination_address_name": "Destination object or group names, or raw destination tokens.",
    "from_zone": "Source zone members.",
    "log_end": "End-of-session logging state using true/false string values.",
    "log_setting": "Log forwarding/profile name.",
    "log_start": "Start-of-session logging state using true/false string values.",
    "management_station": "Management station name or hostname.",
    "name": "Rule name.",
    "provenance": "Device-group or provenance label.",
    "rule_type": "Rule type such as universal or intrazone.",
    "service": "Service member values on the rule.",
    "source_address": "Semantic IPv4 source matching using matches/includes/exactly/intersects/equals.",
    "source_address_name": "Source object or group names, or raw source tokens.",
    "to_zone": "Destination zone members.",
    "vsys_display_name": "VSYS display name.",
    "vsys_name": "VSYS identifier.",
}


@lru_cache(maxsize=1)
def build_security_rule_translation_system_prompt() -> str:
    field_lines = []
    for field_name, supported_operators in sorted(FIELD_OPERATOR_REGISTRY.items()):
        description = FIELD_DESCRIPTIONS.get(field_name, "")
        field_lines.append(
            f"- {field_name}: operators {', '.join(sorted(supported_operators))}. {description}"
        )

    return "\n".join(
        [
            "You translate plain-language firewall security-rule search requests into canonical JSON.",
            "Return a canonical search object for the assessments security-rule builder.",
            "The root model must always be integrations.SecurityRule.",
            "Use only supported fields and operators. Never invent fields, operators, or keys.",
            "Always return the broadest correct query that satisfies the request, but never broaden by dropping an explicit user constraint.",
            "Preserve every explicit condition from the user request.",
            "If the request contains multiple AND-connected requirements, the canonical query must encode all of them.",
            "Do not omit a source, destination, application, or service constraint just because another clause seems related or narrower.",
            "If the user explicitly mentions source, destination, application, or service, include at least one corresponding clause for that concept.",
            "When local canonical vocabulary candidates are provided, prefer those exact canonical values over paraphrased English whenever they fit the request.",
            "Prefer eq when the request clearly asks for an exact canonical local token or a specific local identifier from the candidate list.",
            "Prefer contains when the request refers to a broader family, category, or shared stem rather than one exact local token.",
            "For broad destination families such as sanctioned-saas, a single contains clause on the shared canonical stem is usually better than many exact eq clauses.",
            "Use string values for all clause values, including boolean-like values such as true or false.",
            "Every clause must include explicit negated, case_sensitive, and include_any boolean keys.",
            "When the request says a rule is 'in' or 'on' a short firewall context label such as edge, perimeter, access, application, enterprise, or a VSYS-like name, prefer vsys_display_name unless the user explicitly says device group or provenance.",
            "Use provenance only when the user explicitly asks about device-group or provenance labels.",
            "If the user refers to address object names, address group names, or raw address tokens, use source_address_name or destination_address_name.",
            "If the user refers to a destination object family such as sanctioned SaaS, internet services, portals, servers, or endpoint groups, do not collapse that into an application clause; keep it as a destination_address_name or destination_address clause as appropriate.",
            "If the user refers to IPv4 hosts, CIDRs, ranges, or asks whether traffic would match/overlap/include an IP space, use source_address or destination_address.",
            "Semantic source_address and destination_address rules:",
            "- matches: every address in the queried IPv4 host/CIDR/range must be matched by the rule.",
            "- includes: the effective resolved member set includes the queried IPv4 value.",
            "- exactly: at least one effective member equals the queried IPv4 value exactly.",
            "- intersects: any overlap with the queried IPv4 value.",
            "- equals: the merged effective IPv4 member set equals the queried IPv4 value exactly.",
            "- Semantic address values only support IPv4 host, CIDR, range, or the literal value any.",
            "- include_any defaults false. Set include_any to true only when the user explicitly wants rules with any in the source/destination to count, or when the user explicitly queries for any.",
            "Use negated=true only when the request explicitly excludes or negates a condition.",
            "Use case_sensitive=true only when the user explicitly requests case-sensitive matching.",
            "Do not add empty groups or redundant clauses.",
            "Supported fields and operators:",
            *field_lines,
        ]
    )


def build_initial_user_prompt(request_text: str, *, grounding_context: str = "") -> str:
    lines = [
        "Translate the following plain-language security rule query into canonical JSON.",
        "Return only the query content required by the schema.",
    ]
    if grounding_context:
        lines.extend(
            [
                "",
                grounding_context.strip(),
            ]
        )
    lines.extend(
        [
            "",
            request_text.strip(),
        ]
    )
    return "\n".join(lines)


def build_repair_user_prompt(
    *,
    request_text: str,
    previous_query_json: str,
    validation_error: str,
    grounding_context: str = "",
) -> str:
    lines = [
        "Repair the previous canonical query so it becomes valid and better matches the original request.",
        f"Original request: {request_text.strip()}",
        f"Validation error: {validation_error}",
    ]
    if grounding_context:
        lines.extend(
            [
                "Local canonical vocabulary candidates:",
                grounding_context.strip(),
            ]
        )
    lines.extend(
        [
            "If local canonical vocabulary candidates fit the request better than your previous free-text values, rewrite the clause values to use them.",
            "Prefer eq only for exact local tokens. Prefer contains for broader family/category requests.",
            "Previous query JSON:",
            previous_query_json,
            "Return only the corrected query content required by the schema.",
        ]
    )
    return "\n".join(lines)
