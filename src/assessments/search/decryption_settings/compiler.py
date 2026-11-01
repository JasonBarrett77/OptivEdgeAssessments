"""Canonical search compiler for one appliance's forward-proxy signing designation. PAN-DCP-006.

ONE ROW PER APPLIANCE AND THE ROW IS A VERDICT OVER THE WHOLE `/config/shared/ssl-decrypt` NODE,
not over one designation slot. The commonest failing state is that NO certificate is designated
at all - the node was absent on three of the four lab appliances before stage 6 built a
designation on one of them, and the firewall says so in its own words: `show system setting
ssl-decrypt certificate` answers `No SSL Decryption CERT`. A per-slot grain would have no row to
report on in exactly that state, which is why stage 5 declared the conclusions as columns.

THE TWO REGISTERED VERDICTS ARE THE ONLY TWO COLUMNS A CLAUSE OF THIS DOMAIN RESTS ON, and both
are quantifiers that FOLLOW A REFERENCE or COMPARE COLUMNS TO EACH OTHER - which is why neither
could have been a clause over the four stored names:

* `forward_trust_is_designated_local_ca` walks the designated name into `Certificate` and reads
  `is_ca` and `is_self_signed` off the row it lands on. A predicate compares one field to one
  literal and cannot traverse.
* `untrust_distinct_from_trust` compares the two untrust slots against the two trust slots -
  four columns of one row against each other, which the predicate language has no shape for at
  all.

BOTH DEFAULT FALSE AND FALSE IS THE FIRING SIDE, so an unrecomputed row reports itself rather
than passing. Each covers TWO distinct failing states that read differently in prose - nothing
designated, or something designated that is the wrong thing - and they are one column each
because `clauses` is one conjunction with no OR. The generator's sentence is what separates them
for a reader; see `decryption_settings_findings`.

THE FOUR DESIGNATION SLOTS ARE DELIBERATELY NOT REGISTERED. `forward_trust_cert_rsa`,
`forward_trust_cert_ecdsa`, `forward_untrust_cert_rsa` and `forward_untrust_cert_ecdsa` are all
marked `needs_compiler_field` by stage 5 and `presented: true`, and no clause, no grading column
and no `undetermined` of this domain names one: PAN-DCP-006's two expression records clause on
the two verdicts above instead. They are what a READER is shown so a finding can name WHICH slot
is empty, which is stage 9's business, and registering them would ship a search surface no
control asks for. The same rule the shipped `security_profile` compiler applies to `has_rules`.

`hostname` AND `serial_number` ARE STAGE 5's ONE `appliance` COLUMN, SPELT AS TWO FIELDS, which
is what every shipped compiler in this package does and what the stage contract names as the
convention rather than the exception. Stage 5 marks that column `searchable: already` - which
was true of the COLUMN and false of the search surface, because this model had no compiler at
all until this file. One field cannot serve both spellings: an assessor pastes a hostname and a
Panorama operator pastes a serial.

NO `is_empty` MEMBER IS OFFERED FOR A BOOLEAN AND NONE IS NEEDED. `eq false` reaches the firing
side of both verdicts positively, because both are `BooleanField(default=False)` and
non-nullable - there is no third state for an operator to reach.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import DecryptionSettings

DECRYPTION_SETTINGS_MODEL = "integrations.DecryptionSettings"


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
        predicate = Q()
        for lookup in lookups:
            predicate &= Q(**{lookup: ""}) | Q(**{f"{lookup}__isnull": True})
        return predicate
    if not isinstance(value, str) or not value.strip():
        raise SearchSyntaxError(f"{field_name} search value must be a non-empty string.")
    suffix = {"eq": "iexact", "contains": "icontains"}.get(op, "iexact")
    predicate = Q()
    for lookup in lookups:
        predicate |= Q(**{f"{lookup}__{suffix}": value.strip()})
    return predicate


def build_text_compiler(field_name, *lookups):
    def compiler(clause):
        return DecryptionSettings.objects.filter(
            _text_filter(field_name, lookups, clause)).values("pk")
    compiler.SUPPORTED_OPERATORS = TEXT_OPERATORS
    return compiler


def build_boolean_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op != "eq":
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        if not isinstance(value, bool):
            raise SearchSyntaxError(f"{field_name} search value must be a boolean.")
        return DecryptionSettings.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column, as two fields. The designation is device-wide, so the row
    # takes an appliance DIRECTLY - there is no enforcement point and no vsys on this model, and
    # so no second lookup path per field, which is the one way this differs from every other
    # compiler in this package.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # PAN-DCP-006[0]'s assertion. FALSE covers both failing states - nothing designated at all,
    # or a designated name that does not resolve to a locally-held, self-signed certificate
    # authority this appliance holds. A name resolving to NO certificate row is false rather than
    # unknown, deliberately: a designation pointing at nothing is a worse state than none.
    "forward_trust_is_designated_local_ca": build_boolean_compiler(
        "forward_trust_is_designated_local_ca", "forward_trust_is_designated_local_ca"),
    # PAN-DCP-006[1]'s assertion. FALSE where no untrust authority is designated at all AND false
    # where one is designated and a trust slot names the same certificate. Compared across both
    # algorithm slots of each, which is four columns rather than two.
    "untrust_distinct_from_trust": build_boolean_compiler(
        "untrust_distinct_from_trust", "untrust_distinct_from_trust"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_decryption_settings_search_node(node):
    if "operator" in node:
        return _compile_group(node)
    return _compile_clause(node)


def _compile_group(group):
    compiled = [compile_decryption_settings_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def _compile_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause["negated"] else predicate
