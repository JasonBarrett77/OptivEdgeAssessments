"""Canonical search compiler for one GlobalProtect gateway entry of one vsys.
PAN-GPG-001, -006, -007.

NO ROW OF THIS MODEL EXISTS IN THE MEASURED ESTATE, and that is the first thing a reader of this
file needs. Stage 6 spent eleven lease windows trying to commit a gateway on the one
candidate-clean appliance in the lab and met a new commit requirement each time; the merged
configuration carries no `global-protect-gateway` key under any of the twelve virtual systems of
the four appliances, and `action=show` raises `No such node` at that xpath on all twelve. So every
field below COMPILES and not one of them has ever been shown to match. That is a weaker guarantee
than the shipped compilers beside it and it is stated rather than implied.

ONE DIALOG, TWO SUBTREES, AND THE COLUMNS DIVIDE ALONG THAT SEAM. Network > GlobalProtect >
Gateways writes a vsys-scoped entry AND a device-local entry of the SAME NAME under
`network/tunnel`. The second half carries the transport - `tunnel_mode`, `ipsec_enabled`, the app
crypto binding - which is why PAN-GPG-006's three records cascade the way they do and why
`networking_half_present` is registered: a gateway whose join failed is reading nothing on three of
the fields below and a reader of the finding has to be told so.

FIVE COLUMNS HERE ARE RESOLVED THROUGH A NAME ONTO ANOTHER MODEL'S ROW, and the resolution happens
at normalisation because the query grammar has no edge to walk and no second field slot.
`tls_profile_resolves_to_an_explicit_floor` is the two-way disjunction PAN-GPG-001 asserts - the
bound name reached no row, OR the row it reached states no floor - collapsed into one boolean
because a clause list is one conjunction with no OR. `client_certificate_is_a_second_factor` is the
same shape over the certificate profile and the per-platform rows. Each one's default sits on the
side that FIRES, so a row nobody recomputed reports itself rather than passing.

THREE COLUMNS ARE `null=True` BOOLEANS AND THEY ARE NOT INTERCHANGEABLE WITH THE REST.
`tunnel_mode`, `ipsec_enabled` and `block_quarantined_devices` store NULL where the read did not
carry the key, and the boolean builder below offers `eq` alone - so a POSITIVE clause over any of
them matches no NULL row. The consequence differs per column and the difference is the whole reason
three `_known` companions are registered beside them:

* `tunnel_mode` - the device REFUSES to commit a gateway that omits it (`validate full` job 259,
  "missing tunnel-mode"), so on any committed gateway the failing state is a stored FALSE and the
  NULL is a collection failure rather than a device state. Stage 5 calls this column
  `cannot_be_unknown` and that is defensible for exactly this reason, not because the column is
  non-nullable. It is nullable.
* `ipsec_enabled` - NULL on an absent key, and stage 4 declined to licence either reading of that
  absence. `ipsec_enabled_known` is what keeps those rows inside PAN-GPG-006's comparison.
* `block_quarantined_devices` - NULL on an absent key, same refusal. NO QUERY IN THIS REPOSITORY
  REACHES IT: PAN-GPG-005's third record is the only assertion over it and that control targets
  `integrations.GlobalProtectEnforcementPoint`, with no relation between the two models in either
  direction. It is registered so that the day a control owns it there is a surface, and so a
  finding can colour the cell; see this module's last paragraph.

THE THREE `_known` COMPANIONS ARE REGISTERED BECAUSE A NULL IS NOT REACHABLE OTHERWISE. There is no
is-null operator anywhere in this query language and `is_empty` is a TEXT operator with no boolean
equivalent, so "nobody read this" is expressible only as a clause on a separate materialised
boolean. `login_lifetime_known`, `inactivity_logout_known` and `ipsec_enabled_known` are those
booleans, each `default=False`, and each is claused on by one of this domain's queries at the
severity its own assertion record declares.

`bound_app_crypto_first_encryption` IS A TEXT FIELD AND NOT A CHOICE FIELD, deliberately. Its
measured value set is three members - `aes-128-cbc`, `aes-128-gcm`, `aes-256-gcm` - and the column
is `CharField(max_length=32, blank=True)` whose normaliser returns `""` where the gateway binds no
profile or the bound name resolves to nothing the collection carries. The empty string is therefore
a REACHABLE value absent from any `choices` tuple, which is the shape `build_choice_compiler`
cannot serve: it refuses every value its own `choices` does not list, so it could express no query
for the unmeasured state at all. The text builder's `is_empty` arm is the only operator here that
reaches it.

AND `eq ""` DOES NOT COMPILE, which decides how PAN-GPG-006's grading is written. The guard below
raises `SearchSyntaxError` on an empty `eq` value and `evaluate_queryset_control_queries` SWALLOWS
that as a skipped query - no exception, no log line, one integer on the return value - so a
calibration written as `eq ""` would vanish and the control would ship narrower than its artifact
says. Measured against this domain's own grading: NONE of PAN-GPG-006[2]'s three placements is the
empty string, so no member of that partition needs `is_empty` and the question lands nowhere. The
empty state is still reported, by the boolean beside the value column:
`app_crypto_offers_gcm_first` is materialised FALSE for it and is the assertion clause.

NO JSONField IS REGISTERED HERE AND NONE EXISTS ON THIS MODEL. `test_findings_rest_on_columns`
compiles every registered field with every operator it advertises and walks the resulting query
tree for a JSONField reference, failing rather than skipping. It also probes each field with a
fixed value list and treats a field that accepts NONE of them as a failure - which the three
builders below satisfy: the text builder takes `""` through its `is_empty` arm and `"probe"`
otherwise, the boolean builder takes `True`, and the integer builder takes `1` after rejecting
`bool` explicitly, since `isinstance(True, int)` is true in Python and `True` is probed first.

WHAT NO QUERY ON THIS MODEL CAN REACH. Whether the gateway is internet-facing or internal - the
configuration is identical on both and PAN-GPG-001 leaves it as the engineer's question. Whether
the certificate a gateway presents chains to an authority its endpoints already trust: that is
PAN-GPG-001's second record, discharged `engineer_answers`, and it owes no query. And whether a
value was PUSHED rather than set locally: stage 4 measured that no element of this object carries
`@ptpl` or `@src` on an appliance where `network/interface` does.
"""

from __future__ import annotations

from django.db.models import Q, Subquery

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.device_configuration.fields.scalar_text import (
    SUPPORTED_OPERATORS as TEXT_OPERATORS,
)
from optivedge_integrations.integrations.models import GlobalProtectGateway

GLOBALPROTECT_GATEWAY_MODEL = "integrations.GlobalProtectGateway"

INTEGER_OPERATORS = {"eq", "gt", "gte", "lt", "lte"}


def _text_filter(field_name, lookups, clause):
    op, value = clause["op"], clause["value"]
    if op not in TEXT_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    if op == "is_empty":
        # THE `__isnull` TERM IS OR-ED BESIDE `field=""` PER LOOKUP PATH, which is the shape
        # `search/security_profile/compiler.py` and the portal's client-auth compiler both carry.
        # It matters on this model: `cookie_encrypt_decrypt_cert`'s sibling on the agent
        # configuration is `null=True`, and without this term an `is_empty` clause written for
        # "nothing is bound here" would match no row of the exact population it was written for.
        predicate = Q()
        if not isinstance(value, str) or value.strip():
            raise SearchSyntaxError(f"{field_name} is_empty expects an empty string.")
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
        return GlobalProtectGateway.objects.filter(
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
        return GlobalProtectGateway.objects.filter(**{lookup_field: value}).values("pk")
    compiler.SUPPORTED_OPERATORS = {"eq"}
    return compiler


def build_integer_compiler(field_name, lookup_field):
    def compiler(clause):
        op, value = clause["op"], clause["value"]
        if op not in INTEGER_OPERATORS:
            raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
        # `bool` IS REJECTED BEFORE `int` and the order is not stylistic: `isinstance(True, int)`
        # is true in Python, and `test_findings_rest_on_columns` probes `True` before `1`.
        if isinstance(value, bool) or not isinstance(value, int):
            raise SearchSyntaxError(f"{field_name} search value must be an integer.")
        suffix = {"eq": "exact"}.get(op, op)
        return GlobalProtectGateway.objects.filter(
            **{f"{lookup_field}__{suffix}": value}).values("pk")
    compiler.SUPPORTED_OPERATORS = INTEGER_OPERATORS
    return compiler


FIELD_COMPILERS = {
    # Stage 5's `appliance` column as two fields, which is what every shipped compiler does.
    # `appliance` is non-nullable on `ApplianceScopedObject`, so there is no group fallback. ON AN
    # HA PAIR THE SAME GATEWAY ARRIVES ON BOTH PEERS and nothing deduplicates it, so the serial is
    # what a reader reconciles two identical rows by.
    "hostname": build_text_compiler("hostname", "appliance__hostname"),
    "serial_number": build_text_compiler("serial_number", "appliance__serial_number"),
    # The row's own grain. The gateway exists ONLY under a vsys entry - stage 4 measured the
    # shared and device-local spellings of the vsys half both answering code=6 "Invalid sequence" -
    # so there is no shared-scope gateway for a query to miss.
    "vsys_name": build_text_compiler("vsys_name", "vsys_name"),
    # The gateway's own entry name, which is what an engineer opens and what the finding prints.
    # Operator-chosen and not unique across the twelve virtual systems of this estate, which is
    # why the finding model declares `subject_scope` beside it.
    "entry_name": build_text_compiler("entry_name", "name"),

    # ---------------------------------------------------------- PAN-GPG-001, the TLS binding
    # PAN-GPG-001's ASSERTION and its only clause. The two-way disjunction collapsed at
    # normalisation: false where the bound name reached no row the collection carries, AND false
    # where the row it reached states no protocol floor. Those are two remediations on two
    # objects and the finding's sentence separates them from the columns beside this one.
    "tls_profile_resolves_to_an_explicit_floor": build_boolean_compiler(
        "tls_profile_resolves_to_an_explicit_floor",
        "tls_profile_resolves_to_an_explicit_floor"),
    # The name that was bound, and what it resolved to. Registered for the reader rather than for
    # a clause: an engineer repoints the NAME, and the resolved floor is what says why.
    # MANDATORY AT COMMIT, measured - `validate full` job 259 reported the binding missing - so a
    # query written as "the binding is absent" would be dead code on every committed gateway.
    "ssl_tls_service_profile": build_text_compiler(
        "ssl_tls_service_profile", "ssl_tls_service_profile"),
    "bound_tls_min_version": build_text_compiler(
        "bound_tls_min_version", "bound_tls_min_version"),

    # ------------------------------------------------- PAN-GPG-002's gateway half, reached here
    # PAN-GPG-002's SECOND RECORD asserts on this column, and that control's target is the
    # client-authentication ROW rather than this model - so no query of PAN-GPG-002 compiles
    # against this compiler. It is reached instead through the row's own nullable `gateway` FK,
    # registered on the client-auth compiler as `gateway_client_certificate_is_a_second_factor`.
    # Registered HERE as well because the column is this model's and a reader of a gateway
    # finding needs the cell; the two registrations serve different grains.
    "client_certificate_is_a_second_factor": build_boolean_compiler(
        "client_certificate_is_a_second_factor", "client_certificate_is_a_second_factor"),
    # The two inputs that verdict resolves from, registered so a finding can say WHICH half
    # failed - a gateway binding no certificate profile at all is a different remediation from one
    # whose per-platform rows accept a certificate INSTEAD of credentials.
    "certificate_profile_name": build_text_compiler(
        "certificate_profile_name", "certificate_profile_name"),
    "bound_certificate_profile_blocks_unauthenticated_cert": build_boolean_compiler(
        "bound_certificate_profile_blocks_unauthenticated_cert",
        "bound_certificate_profile_blocks_unauthenticated_cert"),
    "any_client_auth_row_permits_either_or": build_boolean_compiler(
        "any_client_auth_row_permits_either_or", "any_client_auth_row_permits_either_or"),

    # --------------------------------------------------------- PAN-GPG-005's gateway half: NONE
    # REGISTERED AND QUERIED BY NOTHING, and the reason is a grain and not an oversight.
    # PAN-GPG-005's third assertion record is an INVERTED record over these two columns together -
    # it fires unless BOTH hold - but that control targets
    # `integrations.GlobalProtectEnforcementPoint`, because its posture-pipeline record is the
    # only assertion in the whole domain with a stage 6 verdict to be graded against.
    # `probe.relation_between GlobalProtectEnforcementPoint GlobalProtectGateway` finds NO
    # RELATION IN EITHER DIRECTION, so ruling 6's relation remedy has nothing to walk and that
    # half is silent. The stage 8 artifact records it in `subjects_in_two_models`.
    #
    # `block_quarantined_devices` IS `null=True` AND THE BOOLEAN BUILDER OFFERS `eq` ALONE, so
    # were a control ever to own it, the inverted record's NEGATED form is what reaches the NULL
    # rows: `compile_search_clause` inverts the pk SET and not the column, so `NOT eq true`
    # selects the rows holding NULL as well as those holding false. A positive `eq false` would
    # not. That is the right form for an inverted record anyway, since an unmeasured quarantine
    # refusal must fire.
    "block_quarantined_devices": build_boolean_compiler(
        "block_quarantined_devices", "block_quarantined_devices"),
    "automatic_quarantine_path_exists": build_boolean_compiler(
        "automatic_quarantine_path_exists", "automatic_quarantine_path_exists"),

    # ------------------------------------------------- PAN-GPG-006, the transport and its crypto
    # PAN-GPG-006's three records cascade over these two columns and the cascade is mutually
    # exclusive by construction: record 0 fires on `tunnel_mode` false, record 1 on `tunnel_mode`
    # true AND `ipsec_enabled` false, record 2 on `ipsec_enabled` true AND the algorithm order
    # wrong. No row can match two of the three, which is what makes the baseline-tier calibration
    # on record 2's grading safe to build.
    "tunnel_mode": build_boolean_compiler("tunnel_mode", "tunnel_mode"),
    "ipsec_enabled": build_boolean_compiler("ipsec_enabled", "ipsec_enabled"),
    # PAN-GPG-006[2]'s ASSERTION. A boolean beside the value column because the value CAN BE
    # EMPTY: `is not aes-256-gcm` over an empty string answers nothing, and a materialised false
    # turns that silence into a finding.
    "app_crypto_offers_gcm_first": build_boolean_compiler(
        "app_crypto_offers_gcm_first", "app_crypto_offers_gcm_first"),
    # PAN-GPG-006[2]'s GRADING COLUMN, named by no clause of this domain - which is why it is
    # owed a field at all. A grading column is owed one even where no clause mentions it, because
    # a calibration query compiles against it. Three placements, all three non-empty, so no member
    # of that partition needs `is_empty`; see the module docstring.
    "bound_app_crypto_first_encryption": build_text_compiler(
        "bound_app_crypto_first_encryption", "bound_app_crypto_first_encryption"),
    # The profile NAME an engineer edits, and whether the device-local half was joined at all.
    # Registered for the reader: a gateway whose networking half is missing is reading nothing on
    # the three fields above, and a finding that does not say so sends somebody to the wrong panel.
    "ipsec_crypto_profile_name": build_text_compiler(
        "ipsec_crypto_profile_name", "ipsec_crypto_profile_name"),
    "networking_half_present": build_boolean_compiler(
        "networking_half_present", "networking_half_present"),

    # -------------------------------------------------------- PAN-GPG-007, the session bounds
    # PAN-GPG-007[0]'s ASSERTION AND ITS GRADING COLUMN - the same column in both roles, which is
    # why its calibrations are bounded RANGES rather than open thresholds. The worst MATCHED
    # calibration wins and the baseline tier is discarded the moment one matches, so an
    # open-ended `gt 24` query carrying the lower tier would capture every row the higher band is
    # for. Stage 5 states that requirement on the grading itself.
    #
    # `null=True`, and for an INTEGER column that is safe in a way it is not for text: every
    # integer operator compiles to a comparison, so there is no operator a NULL could have
    # satisfied. What it means is that a gateway whose login lifetime nobody read PASSES
    # `gt 24` in silence - the commonest state in this estate, because stage 4 found no agent role
    # entry on any appliance - and `login_lifetime_known` below is the only thing that reaches it.
    "login_lifetime_hours": build_integer_compiler(
        "login_lifetime_hours", "login_lifetime_hours"),
    # PAN-GPG-007[1]'s ASSERTION. Same nullability, same consequence, and the temptation is
    # sharper: the vendor DOCUMENTS a 180-minute default that would already satisfy the control,
    # so materialising it would turn a silence into a pass with a citation attached.
    "inactivity_logout_minutes": build_integer_compiler(
        "inactivity_logout_minutes", "inactivity_logout_minutes"),
    # The value as the administrator typed it and the unit they chose. Registered so a
    # remediation can name the number on the screen rather than the converted one; no clause rests
    # on either, and stage 7 recorded the as-entered column as surplus against the clauses while
    # building it as declared.
    "login_lifetime_unit": build_text_compiler("login_lifetime_unit", "login_lifetime_unit"),
    "login_lifetime_as_entered": build_integer_compiler(
        "login_lifetime_as_entered", "login_lifetime_as_entered"),

    # ---------------------------------------------- the three "did anybody read this" companions
    # THE ONLY WAY A NULL IS REACHABLE IN THIS LANGUAGE. There is no is-null operator, `is_empty`
    # is text-only, and SQL answers every positive comparison over a NULL with no match - so a
    # column whose unknown reads as COMPLIANT needs a separate materialised boolean or the estate
    # nobody measured reads as clean. Each of these three is claused on by one query of this
    # domain, at the severity its own assertion record declares, and each is `default=False` so
    # that a row nobody recomputed reports itself.
    #
    # THE CLAUSE STAYS ON THE DOMAIN CONTROL AND THAT IS NOT WHERE IT BELONGS. A coverage
    # statement is a different claim with a different remediation - one says the configuration is
    # wrong, the other says we could not see it - and it should live on a coverage control over
    # this subject. None exists: `_CONTROL_TYPE_TARGET_MODEL` is one-to-one and the `coverage`
    # type targets `integrations.AddressObject`, so a coverage control here needs a new control
    # type AND a new control id, both outside a build run's roster. The request is filed under
    # `archive/requests/open/` and the stage 8 artifact records every one of these as ranking
    # case 2.
    "login_lifetime_known": build_boolean_compiler(
        "login_lifetime_known", "login_lifetime_known"),
    "inactivity_logout_known": build_boolean_compiler(
        "inactivity_logout_known", "inactivity_logout_known"),
    "ipsec_enabled_known": build_boolean_compiler(
        "ipsec_enabled_known", "ipsec_enabled_known"),

    # ----------------------------------------------------------------- the licence, for a reader
    # DELIBERATELY NOT CLAUSED ON, and the reason is the applicability trap: a clause on a "did we
    # collect it" column SUPPRESSES the control when the answer is no, where an assertion clause
    # on the same field would raise it. Two of the four lab appliances answer `{'licenses': None}`,
    # which is the instrument saying nothing rather than saying unlicensed. The licence goes into
    # the finding's WORDING instead, which is what the generator does with it.
    "globalprotect_gateway_licensed": build_boolean_compiler(
        "globalprotect_gateway_licensed", "globalprotect_gateway_licensed"),
    "licence_state_known": build_boolean_compiler(
        "licence_state_known", "licence_state_known"),
}

FIELD_OPERATOR_REGISTRY = {
    field_name: compiler.SUPPORTED_OPERATORS
    for field_name, compiler in FIELD_COMPILERS.items()
}


def compile_globalprotect_gateway_search_node(node):
    if "operator" in node:
        return compile_search_group(node)
    return compile_search_clause(node)


def compile_search_group(group):
    compiled = [compile_globalprotect_gateway_search_node(c) for c in group["clauses"]]
    predicate = compiled[0]
    for clause in compiled[1:]:
        predicate = predicate & clause if group["operator"] == "and" else predicate | clause
    return predicate


def compile_search_clause(clause):
    compiler = FIELD_COMPILERS.get(clause["field"])
    if compiler is None:
        raise SearchSyntaxError(f"Unsupported search field: {clause['field']}.")
    predicate = Q(pk__in=Subquery(compiler(clause)))
    return ~predicate if clause["negated"] else predicate
