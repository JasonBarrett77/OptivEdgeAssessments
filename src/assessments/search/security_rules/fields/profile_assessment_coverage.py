"""Whether the threat-profile assessment RAN over a rule. A coverage question, not a setting.

`vulnerability_verdict_written` is the one field in this package that says nothing about the
device. Every other security-rule field reports a configuration; this one reports whether we
looked. It is in a module of its own so that distinction is visible in the code, because the
two carry different remediations: a configuration finding is cleared by the customer, and this
one is cleared by us re-running the collection.

**WHAT IT IS AND WHAT IT IS NOT.** The coverage pass sets it True for every rule it reaches -
unconditionally, including the no-profile case, where it still writes a verdict row per
assertion with a NULL `satisfied`. So it is not "a profile resolved" and not "the verdict
passed". The only thing it can be False on is a rule the pass has never run over: one
collected before the column existed, or a refresh that failed between rule normalization and
the coverage pass.

**WHY A CLAUSE NEEDS IT.** `<verdict> equals false` matches False OR NULL, which is what makes
a missing profile report. It cannot reach a rule with NO verdict row at all: the verdict
compilers filter on `profile_verdicts__assertion` before they look at the value, so a rule the
pass never touched matches nothing and passes every vulnerability control in silence. That is
the unknown-reads-as-compliant case the pipeline's stage 5 names, and this column is the
companion that fires on it.

**WHERE THIS CLAUSE LIVES IS AN OPEN QUESTION AND NOT A SETTLED ONE.** The pipeline's stage 8
contract holds that a coverage statement belongs to a coverage control over the subject rather
than to a second query on the domain's own control, so that a reader can tell "the
configuration is wrong" from "we could not see it" on the row. There is no coverage control
over `integrations.SecurityRule` today - `_CONTROL_TYPE_TARGET_MODEL` is one-to-one and points
`coverage` at `integrations.AddressObject` - and minting one is a control-id decision. So the
clause rides on each vulnerability control as a second active query at that control's OWN
severity tier, which is what stage 5 declares and what four earlier pipeline runs shipped for
the same shape. `matched_query_names` on the finding is what tells the two apart meanwhile.
"""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from assessments.search.security_rules.fields.scalar_boolean import parse_boolean_value
from optivedge_integrations.integrations.models import SecurityRule

SUPPORTED_OPERATORS = {"eq"}


def compile_vulnerability_verdict_written_clause(clause):
    field_name = "vulnerability_verdict_written"
    op = clause["op"]
    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for {field_name}: {op}.")
    value = parse_boolean_value(clause["value"], field_name=field_name)
    # A PLAIN COLUMN COMPARISON, and that is worth saying because the verdict fields beside it
    # are not. The column is `BooleanField(default=False)` and non-nullable, so `eq false` is an
    # ordinary match with no NULL arm to fold in and no is-null operator needed.
    return SecurityRule.objects.filter(**{field_name: value}).values("pk")


compile_vulnerability_verdict_written_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
