# Writing a control block

What each row of a Detailed Findings and Recommendations block carries, who it belongs to, and
the rules its sentence has to satisfy. Read it before writing or changing any of the four
catalogue lines a client reads. The framework research behind the rules is an appendix at the end;
the rules themselves come first.

## The reader

A stakeholder at the assessed organization, holding a document with 263 blocks, deciding which
five matter. Not a firewall engineer, though one will read the middle of the block later. They
triage on consequence rather than on the standard. Jason, 2026-11-17: *"The reader will train
themself to read the top and the bottom, then move to the middle only as needed."*

**A sentence that needs a neighbouring block to make sense is a sentence that fails.** The blocks
of one control are scattered through the section by severity: PAN-POL-002's five land at positions
2, 36, 118, 220 and 262.

## The rows, in order

| Row | Belongs to | Field | Cap |
|---|---|---|---|
| the title strip | the control | `Control.name` | |
| Control ID + Risk Rating | the finding | | |
| **Risk** — what goes wrong | the control | `why_it_matters` | 240 |
| **Requirement** — the standard | the control | `what_it_checks` | 320 |
| **Evidence** — what was found | **the query** | `ControlQuery.short_description` | **255** |
| **Remediation** — the change | the control | `what_to_change` | 280 |
| Occurrences | the finding | | |
| Affected Devices | the finding | | |

Row order and labels are `DETAIL_LINES` and `control_detail_rows` in `artifacts/health_check.py`,
whose comment carries both orderings and why the second won.

## The one rule behind all the others

**Three of those rows belong to the control and one belongs to the query, and the block prints
once per control AND severity.** A control grading at several severities prints several blocks
whose Risk, Requirement and Remediation are identical, so the Evidence row is the only line that
can tell them apart.

63 of the 218 controls grade at more than one severity. Before this work, 98 of the 108 blocks
that share a control with another block said nothing a reader could tell the grades apart by.

Every fault this document prevents is a version of putting control-level text where a row-level
answer belongs, or leaving the row-level line empty.

---

## Requirement

One present-tense sentence stating the condition the firewall must satisfy to pass. 320 characters.

1. **Open on the subject and the concept, then land the number.** The CIS and DISA form: *"Ensure
   minimum password length is 14 or more characters"*, *"The Palo Alto Networks security platform
   must terminate communications sessions after 15 minutes of inactivity"*. Neither is a bare
   threshold.
2. **State the whole of what the baseline fires on.** Read the condition off the baseline query and
   invert it. PAN-POL-002 said *"limits at least one side"* while its baseline fires when EITHER
   side is over 8,192 addresses — a weaker standard than the control enforces.
3. **Carry the number the control enforces, read off the query and never off the old prose.**
   PAN-AUTH-002 enforced fifteen characters and told clients twelve for as long as the number came
   from prose.
4. **For a graded control, state the pass bar, not a band.** The bands belong to Evidence.
5. **Say nothing about how we established it.** Not what we counted, not what we followed through,
   not where we looked, not what we could not resolve. That is Evidence's question, and the
   engineer-facing `audit` field already carries the long version.

## Evidence

One or two sentences per query, saying what this grade means on this firewall.

**255 characters, and the cap is the column:** `ControlQuery.short_description` is
`CharField(max_length=255)`, so a longer sentence fails rather than reads badly. The longest
shipped today is 254.

**Two consumers and no others:** the health check's Evidence row (`matched_phrase`), and the
control-query edit form, where the field is labelled Description. No workbook sheet, no
remediation page, no findings row — the workbook's Matched queries column prints query names.

**The baseline sentence is what prints when nothing more specific matched.** A block drops it
whenever a calibration also matched (P621a), so it is the general statement of the failure and it
has to stand alone. On a graded control that makes it do double duty: it IS the leftover band's
sentence, because the leftover block is exactly the one where no calibration matched.
PAN-POL-002's baseline sentence is its informational band.

**Three shapes, and only one of them has bands.**

- **One query only** — 83 of the 218 controls. That one sentence is the whole of the row, every
  time, so it carries the specific fact itself: there is no band to put it in.
- **Several queries at one severity, or with no calibration at all** — 72 controls. Their
  sentences all print, joined, so each is short and reads as an item among several. The four
  longest cells in a lab build are this shape, the worst at 958 characters.
- **Several severities** — 63 controls, which is Pass A: five cumulative, 58 facets.

1. **The first sentence names this query's own failing condition**, in the firewall's terms, with
   the number that put the finding in this band.
2. **For a cumulative-band control only, then name the other bands and their grades.** Jason,
   2026-11-17: *"First name failing condition, then name the others."*

   **Five controls are cumulative** — PAN-POL-002, POL-003, POL-013, POL-014, GPG-006. One band's
   condition implies another's, so a worse finding matches the lower bands too and the worst match
   decides the grade. Those are points on a scale and the scale is worth naming.

   **The other 58 graded controls are facets.** No query implies another, so several matched
   queries are several different facts about one block and the document prints them all, joined.
   PAN-MGT-006's critical block matches five on the lab — its baseline and four data-plane
   surfaces, http, https, ssh and telnet — and all five belong in the cell. Each sentence is one
   standalone fact that reads as an item among several, with no tail naming other grades: those
   grades differ because the facts differ, and a tail on each of five sentences prints the same
   scale five times.
3. **Each line stands alone.** No "as above", no "the other bands".
4. **The leftover band has to be derived.** A finding matching none of a control's severity queries
   carries the control's default severity, so that block means "everything the bands did not
   catch". PAN-AUTH-018's bands are four-to-five failures (low) and six-to-ten (medium) against a
   standard of three, and its default is high — so its high block means lockout switched off, or
   set above ten. No sentence in the catalogue says that and none can be copied.
5. **Where a grade covers several states, name the states instead of choosing one.** Jason,
   2026-11-17: *"Can we just make that explanation more generic for now. For example, THIS or THIS
   or THIS?"* So PAN-SVC-001's high band reads: *The firewall is not following any NTP server this
   configuration names: either it reported keeping its own time, or that reading was not taken.*
   Choosing one of those asserts a reading of the firewall we do not have.
6. **No backticks and no machinery.** The other three rows refuse both. This row had no rule at
   all and shipped 42 backticks, 25 copies of "Default baseline query." and lines like "failed
   attempts before lockout 6 to 10 — reported medium", which is us narrating our own grading to a
   client.

**Not yet enforced, as of 2026-11-17.** Nothing in `controls_catalog/schemas.py` checks these six:
the register covers the other three fields only, and `short_description` passes through
`validate_catalog_payload` unexamined. The rules land in the validator paired with the rewritten
sentences in one commit, because a rule landing first invalidates the shipped catalogue and blocks
every commit until the lines are rewritten. Until then this section is what to write, not what is
checked.

## Risk

One sentence naming the consequence. 240 characters. It is the first line of the block, so it is
the sentence a stakeholder triages on: it has to land for someone who does not know what a zone
protection profile is. State the exposure, not the setting, and never our analysis of it.

## Remediation

One imperative sentence, opening with the verb. 280 characters. The caveats, the CLI and the
screen path live in the engineer-facing `remediation` field, which the remediation pages print in
full — so a sentence here may drop them and must not contradict them.

---

## The test to apply to any line

Every framework in the appendix sits on the finding elements the GAO Yellow Book fixed, and each
row answers one of them and only one:

| Element | The question | Our row |
|---|---|---|
| Criteria | Says who? | Requirement |
| Condition | What exists? | Evidence |
| Effect | So what? | Risk |
| Recommendation | Now what? | Remediation |
| Cause | Why does it exist? | we have none: a configuration cannot say why somebody opened a rule |

**A sentence that answers a question other than its own row's is in the wrong row.**

## Where this is enforced

- `controls_catalog/schemas.py` — `CLIENT_DETAIL_LIMITS` and the register are the gate for
  Requirement, Risk and Remediation, on every catalogue import and every commit.
- `tests/test_controls_catalog.py` — `SeededCatalogTextTests` asserts the shipped catalogue passes
  its own register, and every pattern narrowed after a false refusal has a test naming the line
  that forced it.
- Nothing enforces the Evidence rules yet.

---

## Appendix: what the frameworks do with the number

Researched 2026-11-17, because the number is the one thing the frameworks disagree about.

- **CIS Benchmarks** put it in the recommendation title and again in the Audit section.
- **DISA STIG** puts it in the rule title in human units and in the device's units in the check
  text: *"after 15 minutes of inactivity"* in the title, 900 in the TCP field in the check.
- **PCI DSS v4** puts it in the Defined Approach Requirement and keeps a numberless Customized
  Approach Objective beside it, for a customized-approach mechanism we have no equivalent of.
- **NIST SP 800-53** and **XCCDF** keep it out of the statement, as an organization-defined
  parameter or a `Value` element a profile can override, because both are catalogues meant to be
  tailored. Ours are fixed in each baseline query.
- **Qualys Policy Audit** defines evidence as the Expected value and the Actual value together.

We take the CIS and DISA position, because our Requirement IS our expected value and the block
prints it directly above what was found. That our thresholds are our own rather than a standard's
is recorded on the board as a thing to know, not as work.
