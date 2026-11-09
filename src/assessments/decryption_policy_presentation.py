"""Readers and proposed headings for the three decryption-policy findings tabs.

`decryption-policy`, 2026-11-02. Three subjects, three grains, three tabs:

- `integrations.DecryptionPolicyRule` - one named rule in one rulebase of one virtual system.
  Seven controls: PAN-DEC-002, -003, -005, -006, -007, -008, -010.
- `integrations.DecryptionRulebaseVerdict` - one virtual system's whole decryption rulebase as a
  conclusion over all of its rules. PAN-DEC-001 and -009.
- `integrations.SslDecryptionExclusion` - one exclusion the organization added itself, in one
  scope of one appliance. PAN-DEC-004's first record.

A FOURTH MODEL EXISTS AND GETS NOTHING HERE, said rather than left to arithmetic.
`integrations.SslDecryptionVendorExclusionOptOut` carries PAN-DEC-004's SECOND record, has a
registered findings generator that writes nothing by design, and is named by NO SHIPPED QUERY -
measured over the seed payload, which carries 21 PAN-DEC queries across the three models above
and none against this one. So it is owed no rail item (`AWAITING_PRESENTATION`'s debt is against
`query_results_url`, and a model no query names has nothing to resolve) and no tab
(`check_every_finding_reached_a_tab` is about findings that exist, and none can). Its generator's
own docstring carries the three reasons - one control type maps to one target model so the two
halves cannot share a catalog id; `probe.relation_between` finds no relation to walk in either
direction; and no estate can make it fire, because the vendor's own exclusion list answers a
truthy EMPTY envelope to `action=get` and only `show predefined` returns the 330 or 385 entries,
which nothing issues on a collection run. Splitting PAN-DEC-004 into two catalog ids is Jason's
decision and is recorded in that docstring.

EVERY HEADING IN THIS MODULE IS A PROPOSAL (P399). Jason takes the heading pass once across many
domains; what is decided here is the column SET, which comes from the controls' own clauses.
Seventeen clause fields over three models and NOT ONE of them had a heading before today - there
was no sheet for any of these three control types to inherit a `setting_labels` entry from - so
without this module all seventeen would head a customer-facing column with a Django field name.
Each entry below says where its words come from: the vendor's own Web Interface Help where PAN-OS
has a word for the thing, and plainly OURS where it does not.

THE SOURCE FOR EVERY VENDOR WORD IS ONE SECTION. PAN-OS Web Interface Help 11.2,
`Policies > Decryption`, p.170-175 - its five field tables are General (p.170-171), Source
(p.171), Destination (p.173), Service/URL Category (p.173) and Options (p.174-175). The
exclusion's words are from `Device > Certificate Management > SSL Decryption Exclusion`,
p.901-903 of the same document. Both section paths are the corpus's own, and both exist in all
three indexed Help versions (11.1, 11.2, 12.2).
"""
from __future__ import annotations

from .artifacts.sheets import findings as findings_sheet

DERIVED = findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label


def joined(rows) -> str:
    """A criterion's members in the DEVICE'S OWN ORDER, one per line.

    One per line rather than a comma list, which is Jason's rule of 2026-09-18 as the security
    rules sheet records it: a criterion names objects whose own names contain hyphens and read as
    phrases, so a wrapped comma list makes the boundary between two of them a guess. The same
    helper is spelled out here rather than imported from `security_rules`, because that one
    defaults its attribute to `value` for a `SecurityRuleValue` and takes `raw_value` for the
    address sides - a `DecryptionPolicyRuleValue` has only `value`, and borrowing a helper whose
    default happens to fit is how the next model's rename breaks this tab silently.

    THE ORDER IS THE DEVICE'S AND NOTHING HERE RANKS IT. `DecryptionPolicyRuleValue.Meta` orders
    on `position`, which the normalizer fills from the member list's own index, because a
    criterion is a set the dataplane matches against.

    "(empty)" is NOT reachable on this object and the fallback is kept anyway. All five criteria
    are materialised by the normalizer: three of them (`category`, `source-user`, `service`) have
    a measured implicit of `["any"]` for an absent key, and the other two are mandatory at commit
    validation. A rule with no member row of a kind would be a shape nobody has seen, and
    printing a blank cell for it would read as a gap in the collection.
    """
    return "\n".join(str(row.value) for row in rows) or "(empty)"


#: THE FIVE CRITERIA WHOSE VALUE IS NOT ON THE RULE ROW, and the five readers are a REQUIREMENT
#: rather than a judgement - which is worth stating precisely, because the stage contract's
#: finding 4 frames a `value_readers` entry as a choice with a price attached and here there is
#: no choice to make.
#:
#: MEASURED. `category`, `source`, `destination`, `source_user` and `service` are each a clause
#: field of a shipped PAN-DEC query and NONE of them is a field of `DecryptionPolicyRule`:
#: `_meta.get_field()` raises `FieldDoesNotExist` and `hasattr` is False for all five. The values
#: live on the five `DecryptionPolicyRuleValue` subclasses. `tested_fields` reaches its own
#: `raise ValueError` on the first of them - "PAN-DEC-002 tests 'source', which
#: DecryptionPolicyRule neither stores nor computes. A value held on related rows needs a
#: value_reader on the sheet" - so WITHOUT these five entries the tab cannot be built at all.
#: `security_rules.SOURCES_READER` and its siblings are the same shape over the security
#: rulebase's own member rows, and this follows them.
#:
#: AND THE PRICE IS PAID WHETHER OR NOT A READER IS DECLARED, which is the half this comment
#: exists for. `tested_fields` hands a reader's field `stored=False`; `remediation_accessor` then
#: skips `provenance_of(field)` entirely for a `stored=False` field and walks to the object's
#: `__entry__` row. So the five `FieldProvenance` rows the normalizer writes FOR THESE EXACT
#: COLUMNS are unreachable on a findings row - and it wrote them on purpose. Its own words: "A
#: ROW FOR THE LIST'S OWN NODE, which the member rows cannot carry ... For `category`,
#: `source-user` and `service` that absence is a measured vendor fact and it is the firing side,
#: so a reader is owed the difference between 'the rule says any' and 'nobody wrote one'."
#:
#: THAT DIFFERENCE IS NOT RECOVERABLE FROM THIS SHEET and it is recorded rather than worked
#: around. The member rows cannot carry it: `member_list` materialises `["any"]` for an absent
#: key with `prov=None`, which stores the same empty `prov` string a locally-written `any` gets,
#: so the two states are identical on every row a reader can see. `read_value` calls
#: `reader.read(subject)` with ONE argument, so a reader cannot reach `provenance_of` either, and
#: a reader's `provenance` string is static per COLUMN rather than per row. The only sheet option
#: that would preserve the row is not declaring the reader, and that option raises.
#:
#: SO `provenance` IS THE DERIVED LABEL, DELIBERATELY, AND IT IS NOT WHAT THE CELL PRINTS.
#: `build_rows` treats a reader whose `provenance` is exactly that label as a request to let the
#: object answer - "the prose stands only where it cannot" - and resolves the cell to the rule's
#: own `__entry__` provenance row, which the normalizer does write. So the cell reads where the
#: RULE came from (local, device group, template) rather than the word "Derived", which is the
#: useful answer for a criterion and is the same answer the security rules sheet gives for the
#: same reason: a rule is pushed as a unit and an override replaces all of an object's values.
CATEGORY_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.decryptionpolicyrulecategorys.all()),
    provenance=DERIVED,
)
SOURCE_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.decryptionpolicyrulesources.all()),
    provenance=DERIVED,
)
DESTINATION_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.decryptionpolicyruledestinations.all()),
    provenance=DERIVED,
)
SOURCE_USER_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.decryptionpolicyrulesourceusers.all()),
    provenance=DERIVED,
)
SERVICE_READER = findings_sheet.ValueReader(
    read=lambda rule: joined(rule.decryptionpolicyruleservices.all()),
    provenance=DERIVED,
)

#: NO `members=` ON ANY OF THE FIVE, and that is measured rather than stylistic. A reader with
#: `members` sends `member_provenance_index` to build a `FieldProvenance` index over the child
#: rows, and a `DecryptionPolicyRuleValue` has no provenance rows to index: it records its marker
#: in a plain `prov` CharField, which the model's own docstring names as "the documented exception
#: for member and tag models". The security rules sheet's address and service readers pass no
#: `members` for exactly this reason.
RULE_VALUE_READERS = {
    "category": CATEGORY_READER,
    "source": SOURCE_READER,
    "destination": DESTINATION_READER,
    "source_user": SOURCE_USER_READER,
    "service": SERVICE_READER,
}


#: PROPOSED HEADINGS for the Decryption Rules tab's fourteen derived setting columns - every
#: clause field of the seven controls that report here, in `tested_fields` order.
#:
#: CHECKED FOR COLLISIONS DELIBERATELY, because nothing in either repository checks that a tab's
#: headings are unique and a duplicate header is a workbook Excel refuses to open - xlsxwriter
#: drops the table with a warning and leaves a sheet of stray cells. The near misses on this tab
#: are the three log-related columns (`log_fail`, `success_record_disposition`) and the two user
#: columns (`source_user`, `source_user_is_keyword_population`), which is why the vendor's bare
#: "Source User" is kept for the criterion and the verdict beside it is worded as a question about
#: the criterion's CONTENTS rather than reusing the word.
RULE_SETTING_LABELS = {
    # VENDOR'S OWN WORD. Help p.174: "Action - Select decrypt or no-decrypt for the traffic." The
    # APPLICABILITY clause of six of the seven controls, pinned to `no-decrypt`: every one of them
    # is about a rule that leaves traffic encrypted, and this column is what tells a reader why a
    # rule with `decrypt` on it drew no row.
    "action": "Action",
    # VENDOR'S OWN WORD, in the vendor's own polarity. "Disabled" is the heading the DoS rules tab
    # already uses for the same concept on a sibling rulebase, kept character for character so one
    # idea does not read two ways on two tabs.
    #
    # IT IS ON NINE OF THE TEN CONTROLS AND IT IS AN APPLICABILITY CLAUSE PINNED TO FALSE, which
    # makes this column load-bearing rather than decorative. Jason, 2026-10-14: "keep disabled
    # rules in scope" - so the row has to say which side of that it is on. What the clause actually
    # does is narrower than the ruling and the difference is visible here: a rule carrying
    # `disabled: yes` is OUT of the population and draws no row, so this cell reads "No" on every
    # row this tab has. The ruling is honoured by the model's default (`disabled` defaults False,
    # so a rule nobody read stays INSIDE the population) rather than by the clause, and a row
    # reading "No" here is the evidence that the rule assessed is one in force.
    "disabled": "Disabled",
    # VENDOR'S OWN WORD, help p.173: "URL Category Tab - Select URL categories for the decryption
    # rule. Choose any to match any sessions regardless of the URL category." "URL Category" and
    # not "Category": the device's key is `category` and the vendor's label for it names what the
    # categories are OF, which is the difference between this criterion and a content class.
    "category": "URL Category",
    # VENDOR'S OWN WORD, help p.171: "Source Address - Click Add to add source addresses, address
    # groups, or regions (default is any)."
    "source": "Source Address",
    # VENDOR'S OWN WORD, help p.173: "Destination Address - Click Add to add destination addresses,
    # address groups, or regions (default is any)."
    "destination": "Destination Address",
    # VENDOR'S OWN WORD, help 12.2 `Policies > Decryption` Source tab: "Source User - Click Add to
    # choose the source users or groups of users subject to the policy." Taken from 12.2 because
    # the 11.2 rendering of the same table in this corpus does not reach the field; the label is
    # identical in both and the key is `source-user`.
    "source_user": "Source User",
    # VENDOR'S OWN WORD, help p.173: "Service - Apply the decryption policy to traffic based on
    # specific TCP port numbers."
    "service": "Service",
    # VENDOR'S OWN WORD, help p.171: "Description - Enter a description for the rule (up to 1024
    # characters)." PAN-DEC-003's assertion is that it is EMPTY, and the column is where a reader
    # sees that it is.
    "description": "Description",
    # OURS. The vendor has no word for this: it is a quantifier this assessment computes over the
    # member rows of Source User, and `probe.corpus` returns the vendor's label for the CRITERION
    # and nothing at this position.
    #
    # PHRASED SO THAT "Yes" IS PLAINLY THE PROBLEM. The column defaults TRUE and True is the firing
    # side, so a heading in the other polarity - "Exemption names reviewable principals" - would
    # put "No" in the firing cell and "Yes" in the healthy one, which is the failure this stage
    # exists to catch: a row whose most reassuring cell is the finding. The `device-id-iot` run
    # made the same call on `rules_matching_on_device_count` and recorded it as the one heading
    # that was a safety decision rather than a wording one.
    #
    # "keyword" IS THE DEVICE'S OWN VOCABULARY and the word is doing work: the four values this
    # tests for - any, known-user, unknown, pre-logon - are not principals at all, so an exemption
    # drawn entirely from them names a population nobody can review or revoke. WHAT IT CANNOT DO
    # is tell a directory group from one individual, which the normalizer records: False here means
    # only "at least one member is a principal of unknown kind".
    "source_user_is_keyword_population": "Exempt population is only platform keywords",
    # THE VENDOR'S WORD IS "Negate" AND THE HEADING SPELLS OUT WHAT IT NEGATES. Help p.171, on
    # Source Address: "Select Negate to choose any address except the configured ones." A column
    # headed bare "Negate" beside a Source Address column would read as a property of the heading
    # above it rather than of this rule, and the store holds the key in THE VENDOR'S OWN POLARITY -
    # true means the device's key is `yes`, which means the match is inverted - so the heading says
    # inverted and the cell says Yes.
    "negate_source": "Source match is inverted",
    # VENDOR'S OWN WORD, help p.174: "Decryption Profile - Attach a Decryption profile to the
    # policy rule in order to block and control certain aspects of the traffic."
    #
    # EMPTY HERE DOES NOT MEAN NOTHING IS APPLIED and the column cannot say which it is. Stage 4
    # measured the same absent key resolving to the predefined profile named `default` under some
    # conditions and to nothing under others, and nothing is materialised - which is why
    # PAN-DEC-008 confines itself with an applicability clause on `action equals no-decrypt`, one
    # of the conditions under which the absence was measured resolving to nothing. The cell reads
    # `(empty)` for that state, which is `display_value`'s word for an empty string and is honest:
    # the key is absent, and what the device would do with it is not a reading this tab has.
    "profile_name": "Decryption Profile",
    # VENDOR'S OWN WORD, help p.175: "Log Unsuccessful SSL Handshake - Creates detailed logs of
    # unsuccessful SSL Decryption handshakes so you can find the cause of decryption issues.
    # Enabled by default." The vendor's "Enabled by default" is the second of two agreeing sources
    # for the measured implicit - absent means yes - which the model records.
    "log_fail": "Log Unsuccessful SSL Handshake",
    # OURS, AND AN APPLICABILITY GATE. The vendor has no word for it: it is a disjunction over the
    # two actions that open a session, which the query grammar cannot write - `clauses` is one
    # conjunction with no OR and there is no `in` operator.
    #
    # "Opens the session" rather than "Decrypts": `decrypt-and-forward` also opens it, and the
    # whole reason this column is a boolean rather than a clause on `action` is that an
    # applicability clause naming one of the two values would silently exclude every rule carrying
    # the other.
    "opens_session": "Opens the session it matches",
    # OURS. The vendor has two separate switches here - "Log Successful SSL Handshake" (p.174,
    # "Disabled by default") and "Log Forwarding" (p.175, "Specify the method and location to
    # forward ... logs") - and no word for the three-state reading over both of them. The three
    # states print as the device-facing tokens `no-record`, `kept-not-forwarded` and
    # `kept-and-forwarded`, which the model holds deliberately.
    #
    # ONE COLUMN AND NOT TWO, which is the normalizer's measurement rather than a presentation
    # choice: PAN-DEC-010's second half is graded at two severities, a grading holds exactly one
    # column, and the two states differ by two columns at once. Graded on the successful-handshake
    # switch alone, the placement for "the record is kept but nothing forwards it" compiles to a
    # query that fires on EVERY rule keeping the record, including the ones forwarding it
    # correctly.
    #
    # NOT HEADED "Log Successful SSL Handshake", deliberately, although that is the vendor's word
    # for the switch this is mostly about. The column is not that switch - it is a verdict over
    # that switch AND the forwarding profile - and borrowing the vendor's label for a value the
    # vendor's screen does not hold would tell a reader to go and look at one checkbox for a cell
    # that answers about two.
    "success_record_disposition": "Record of a successful session",
}


#: PROPOSED HEADINGS for the Decryption Coverage tab's three derived setting columns - every clause
#: field of PAN-DEC-001 and PAN-DEC-009.
#:
#: ALL THREE ARE OURS AND THE VENDOR HAS NO WORD FOR ANY OF THEM, which is measured rather than
#: assumed: `Policies > Decryption` (help 11.2 p.170-175) describes the rule and its five field
#: tables and names no state of a RULEBASE at all. Each of these is a conclusion this assessment
#: computes over all the rules in force at one enforcement point, and the reason the subject exists
#: is that the commonest failing state is that there is no rule to compare against - a predicate
#: has no quantifier over related rows and cannot compare against a row that is not there.
#:
#: EACH IS PHRASED SO THAT THE FIRING ANSWER READS AS THE PROBLEM. All three default to the firing
#: value, deliberately and for the reason stage 5 gives - an enforcement point nobody collected
#: reports itself rather than passing - so a heading in the wrong polarity would put the reassuring
#: word in the firing cell on exactly the rows nobody read.
RULEBASE_SETTING_LABELS = {
    # PAN-DEC-001's BASELINE column. "Any rule" and not "This policy": the value is an existential
    # over the rules in force, and FALSE - the firing side and the migration default - covers two
    # states a reader fixes differently, which is what the disposition column beside it is for.
    #
    # "outbound web session" is the control's own subject and is narrower than the column name
    # suggests on its own: the verdict is computed over the `ssl-forward-proxy` branch only,
    # because a rule with `action: decrypt` on the inbound-inspection branch opens inbound traffic
    # and no outbound web.
    "opens_outbound_web": "Any rule opens an outbound web session",
    # THE COLUMN THAT CARRIES THE SEVERITY, and the four values are four configurations somebody
    # can go and look at rather than four remedies. "Strongest" is the computation: the value is
    # what the most permissive in-force forward-proxy rule does, so a single decrypting rule moves
    # the whole enforcement point off the firing value.
    #
    # `no-rule-opens-outbound-web` is both the firing value and the migration default, which stage
    # 5 required explicitly: a CharField migrated empty would match no placement and the control
    # would report nothing on every enforcement point in the estate until the recompute ran.
    "outbound_web_disposition": "What any outbound web session meets",
    # PAN-DEC-009's one clause, asserted against `no-inbound-inspection-rule`. "the organisation's
    # own published servers" is what the control is about and is left out of the heading because
    # the column cannot establish it: the verdict reads whether the inbound branch is present
    # anywhere on this enforcement point, not whether the servers behind it are the published ones.
    #
    # NO RANK OF THIS CONTROL HAD BEEN SEEN IN A POPULATED ESTATE before stage 6 built one, which
    # the model records.
    "inbound_inspection_posture": "Inbound TLS inspection",
}


#: PROPOSED HEADING for the SSL Decryption Exclusions tab's one derived setting column.
#:
#: VENDOR'S OWN WORD, help 11.2 p.902 verbatim: "Description - (Optional) Describe the application
#: that you are excluding from decryption, including why the application breaks when decrypted."
#: The vendor's own sentence is the whole of PAN-DEC-004's first record: the control asserts the
#: field is empty, and what a reader needs beside that is the vendor's reason for the field
#: existing.
EXCLUSION_SETTING_LABELS = {
    "description": "Description",
}


def exclusion_excludes(exclusion, _provenance_of) -> str:
    """Whether this entry actually keeps the named server encrypted - the vendor's `Exclude`.

    A SUBJECT COLUMN AND NOT A DERIVED ONE, because no shipped query clauses on it: `exclude` is
    not in `search/ssl_decryption_exclusion/compiler.py`'s registry either, which is the same
    fact from the other side - the repo's rule is that only a column a control asks for is
    registered. So it draws no setting column, cannot be the value at fault, and is here as the
    evidence a reader of PAN-DEC-004's finding needs: an exclusion carrying no reason is a
    different thing depending on whether it is in force.

    IT NAMES NO `field`, which on a column whose attribute no clause tests is the safe side of
    lesson 5 rather than the unsafe one: a subject column that declares no field does not suppress
    the derived column for the same attribute, and here there is no derived column to suppress.

    Help 11.2 p.902: "Exclude - Exclude the application from decryption. Disable this option to
    start decrypting an application that was previously excluded from decryption." FALSE where the
    key is absent is a BARE UNCOMMITTED entry and not a decision, which the model records and this
    cell cannot distinguish - the key is mandatory at commit validation, measured at both scopes,
    so no committed exclusion is observed without it.
    """
    return findings_sheet.display_value(exclusion.exclude)


def rules_in_force(verdict, _provenance_of) -> str:
    """How many rules are in force at this enforcement point, across every scope that reaches it.

    THE EVIDENCE BEHIND ALL THREE VERDICTS and the one cell that tells their shared failing state
    apart from the other one. `opens_outbound_web` reads False both where there is no decryption
    rulebase at all and where every rule in it leaves traffic encrypted, and those are different
    pieces of work - the first is "write a decryption policy" and the second is "change the rules
    you have". Zero here says which.

    PRINTED AS A NUMBER rather than through `display_value`, on the ruling the two existing count
    columns in this repository took: zero is the reportable end, and a word like "Nothing" on a
    column named for a count reads as "not counted" instead of "none found".

    NO `field` AND NO SETTING COLUMN. `rule_count` is in the model's `DERIVED_FIELDS` and no
    shipped query clauses on it, so `setting_columns` derives nothing for it and there is no
    duplicate for this column to collide with.
    """
    return str(verdict.rule_count)


def rule_rulebase(rule, _provenance_of) -> str:
    """Which of the three rulebases this rule came from - local, pushed pre, or pushed post.

    PART OF THE ROW'S IDENTITY AND NOT DECORATION. Stage 5 made `config_source` one of the four
    identity columns for this subject with a measured reason: the same rule NAME may exist in a
    pre-rulebase and a post-rulebase at the same scope, and those are two different objects a
    reader must tell apart. The model's own uniqueness constraint keys on
    (enforcement_point, config_source, rule_name) for the same reason.

    IT NAMES NO `field` DELIBERATELY. `config_source` is a stored column that no PAN-DEC query
    clauses on, so there is no derived setting column for this to suppress and no collision - and
    declaring a field a control does not test would offer this cell to the value-at-fault mark,
    which can only ever be wrong: where the rule came from is never the thing to change.

    UNEXERCISED IN THIS LAB, which is worth a reader knowing before they trust a `Local` on every
    row: re-measured on all four appliances, the pushed pre- and post-rulebases hold `security` and
    `default-security-rules` and no `decryption` child at all, so every row in the measured estate
    is local.
    """
    return rule.get_config_source_display()
