# Rule Permissiveness Scoring — v1 methodology

> **Status: designed, not built.** The methodology is agreed and the decisions below are
> Jason's; what is implemented is the address sizing it rests on, and the two PAN-COV coverage
> controls. Jason, 2026-09-30: "Don't implement yet."
>
> It lives here rather than in the drafts directory because it is not awaiting review - it was
> reviewed on 2026-09-30 and 10-01 and every answer is recorded below. It is awaiting the
> BUILD, and this is where that build will come looking.

Scores PAN-OS security rules for **permissiveness (breadth)**, not contextual risk. It answers
"how much does this rule permit", not "is permitting that wise here" — the second needs
context the configuration does not hold.

Everything below is decided unless marked **OPEN**. Thresholds are calibrated per client.

## Which control this is

**PAN-POL-002, "Source/Destination Address Breadth Bounded"** — critical, STIG
`PANW-AG-000029`, `not started`. Confirmed against the corpus on 2026-09-30 rather than
assumed: the corpus entry already carries a `severity_scale` with bands, and its note says
"thresholds pending user sign-off".

The corpus measure is NOT the one below. It reads *"largest contiguous address space a single
allow rule exposes on its broadest side"* — a **max** over one side. That is a deviation to
record in `control-changes.json` when this is built, with the reasoning in *Why not the
corpus's measure*.

### PAN-POL-001 overlaps it, and the overlap is total

001 fires on source **AND** destination `any`. The corpus's 002-critical fires on source
**OR** destination `any`. **001 is a strict subset**, so every one of its 44 lab findings
would be reported twice at critical. Both carry the same STIG ref, so the corpus split one
requirement into two controls and we built the narrower half first.

**OPEN:** whether 001 retires into 002, or keeps a distinct assertion. Under the methodology
below, 001's any/any is simply the top band of both address fields.

## Scope

- Fields evaluated: **source address, destination address, service, application**.
- **Zones are excluded in v1.** May become a separate control. (This reverses the
  2026-09-30 message "I want to add zone, service and application"; the methodology as
  written excludes them.)
- Rules evaluated: **action `allow` only**, excluding the two predefined default rules
  (`config_source == default`, the mechanism PAN-POL-001 already uses) and **excluding
  disabled rules**, which permit nothing.
- Two check categories:
  1. **Per-field checks** — severity from the raw count permitted in each field.
  2. **Aggregate check** — severity from combining the per-field tiers.

Tier order: Null < Info < Low < Medium < High < Critical. These map exactly onto the existing
severity vocabulary (`informational`, `low`, `medium`, `high`, `critical`); **Null means no
finding**, which is what a non-matching query produces naturally.

## What is counted

| Field | Count (n) | Upper bound |
|---|---|---|
| Source / destination address | Host count | 2^32 |
| Service | (protocol, port) pairs | 131,070 |
| Application | App count | ~5,357 |

- A side's host count is the **union of every object on it, de-duplicated** — not the sum.
  Two objects covering the same /8 are one /8. Overlapping members must be merged into
  disjoint intervals before counting.
- **Negation is scored against the true meaning of the field.** `negate-source` means the
  effective source is the COMPLEMENT, which is usually close to 2^32. Scoring the listed
  members instead would score a negated rule as its own inverse — negating one host would
  read /32 → Null.
- Service pairs count TCP and UDP separately: `tcp/1-1024` + `udp/1-1024` = 2,048 pairs.
  The bound is 131,070 on the basis of ports **1–65535 per protocol**. *Unverified: whether
  PAN-OS accepts port 0 in a service object. One `action=complete` call settles it, and it
  moves the bound to 131,072.*
- Service and application are evaluated independently.
- ~5,357 App-IDs is **informational only**. It drifts with weekly content updates, so no
  threshold is computed from it; the bands below are absolute.

## Per-field checks

Ranges are inclusive integers.

### Source / destination address

Host count converts to an equivalent prefix length, rounding UP:

**network_bits = 32 − ceil(log2(n))** — the smallest subnet containing n hosts. n = 1 → /32.

| Severity | Network bits | Host count |
|---|---|---|
| Critical | /0–/7 (includes `any`) | > 16,777,216 |
| High | /8–/11 | 1,048,577–16,777,216 |
| Medium | /12–/14 | 131,073–1,048,576 |
| Low | /15–/16 | 32,769–131,072 |
| Info | /17–/18 | 8,193–32,768 |
| Null | /19–/32 | 1–8,192 |

Round-up, worked:
- `10.0.0.0/8` = 16,777,216 hosts → /8 → High.
- RFC1918 (10/8 + 172.16/12 + 192.168/16 = 17,891,328) → /7 → **Critical**. Round-to-nearest
  would give /8 → High.

**RFC1918 scoring Critical is deliberate.** Jason, 2026-09-30: "RFC1918 rules may be poorly
considered." See *Accepted consequences*.

### Service

| Severity | (protocol, port) pairs |
|---|---|
| Critical | `any`, or ≥ 1,024 |
| High | 64–1,023 |
| Medium | 32–63 |
| Low | 16–31 |
| Info | 8–15 |
| Null | 1–7, or `application-default` |

`tcp/1-1024` alone is 1,024 pairs → Critical.

The band widths are irregular on purpose — Info, Low and Medium are one doubling each, High
spans four. Jason, 2026-09-30: "The range is somewhat arbitrary, based on what a security
practitioner might consider Critical, High, Medium, Low and Info." Recorded so it is not
re-derived as a mistake.

### Application

| Severity | App count |
|---|---|
| Critical | `any`, or ≥ 64 |
| High | 24–63 |
| Medium | 16–23 |
| Low | 8–15 |
| Null | 1–7 |

No Info tier. Applications are selected individually while addresses and ports can be ranges,
so the thresholds sit lower than service. Bands are linear at low counts (manual selection)
and coarse at high counts (filters, broad groups, `any`). Null covers 1–7 so an app plus its
dependencies — `ssl`, `web-browsing` — produces no finding.

## Aggregate check

**Aggregate severity = one tier above the second-highest per-field severity.**

- Two fields broad at tier T make the rule one tier worse, whichever two fields they are.
- Capped at Critical.
- If the second-highest per-field severity is Null, there is no aggregate finding.
- No separate thresholds: recalibrating a per-field tier updates the aggregate automatically.

## Rule-level severity

**Highest severity across all per-field and aggregate findings.** A single Critical field makes
the rule Critical — Jason, 2026-10-01: "Yes, a single critical is a rule critical."

## Accepted consequences

Stated so they are decisions rather than surprises.

- **Low + Low = Medium**, so /16 ↔ /16 with one app is Medium overall.
- **Most rules on an internal estate will be Critical.** RFC1918 on either side is Critical by
  itself, and a single Critical field makes the rule Critical — so
  `RFC1918 → one host, application-default, one app` scores Critical. The aggregate check and
  the other three fields stop discriminating once any field reaches Critical. Both halves of
  this are deliberate; the consequence is that rule severity will not rank an internal estate,
  and the per-field findings are where the detail lives.
- **The aggregate is insensitive at the top of its range**: `(High, Medium)` and
  `(Medium, Medium)` both produce High, so a strictly broader rule can score the same.

## Indeterminate sides

A side whose size cannot be established does **not** score Null. Null is the narrowest band,
and letting unknown fall through to it produces a false negative on the one control whose job
is finding broad rules — the assessor sees "narrow" with no reason to doubt it.

Precedent: `MasterKey` records a key nobody asked about as `undetermined`, which fires, because
"we never asked" must not look like "we asked and it was fine."

Four causes, all surfacing today as `num_hosts` NULL:

| cause | kind |
|---|---|
| the device could not fetch its EDL | **client finding** |
| we never collected the EDL | coverage |
| we truncated the EDL at 50,000 members | coverage |
| an application group or filter is unresolved | coverage |

**DECIDED 2026-10-02** — Jason: "surface them like any other finding." No appendix, no
separate tab: an indeterminate side raises a finding through the ordinary pipeline, so it
inherits the existing presentation, search and artifact behaviour rather than needing its own.

**Its subject is the RULE**, not the object that could not be sized. That is what makes it
reach the person reading that rule's row — a notice on the EDL does not. The coverage findings
below have a different subject (the address object) and a different audience, so a rule
referencing an uncollected EDL legitimately produces two findings on two rows: *this rule's
source breadth is indeterminate*, and *this EDL was never collected*. Under "one object, one
row" each appears against its own subject, which is the intended outcome rather than
duplication.

**DECIDED 2026-10-01** — Jason: Medium. Not Critical, since nothing is known to be broad, and
not Null, which would hide it. That is the severity both PAN-COV controls ship at.

## The client / coverage split

The four causes above are two different kinds of thing and must not share a control.

**Client findings** are defects in the customer's firewall. The clear one: the device itself
could not fetch its EDL — `prod_west_edl` on the lab answers `total-valid 0, total-invalid 1`
with cURL error 28. **The firewall is enforcing a rule against a list it cannot download.**
That is a real finding, belongs in the deliverable, and is arguably high on its own. It sits
naturally beside `PAN-POL-017 EDL-Based Blocking Rules Present`.

**Coverage findings** are blind spots in our assessment: we never collected it (13 of 14 lab
EDLs, because collection is driven by normalized rule refs), we truncated it at **our** cap of
50,000, or we cannot resolve an application group. Reporting these through a normal control
would present our limitations as firewall misconfigurations, and they need different severity
language — "we could not read this" is not critical *to the client*.

They are mechanically distinguishable: the device-failure case has a snapshot with
`resolved_content_source_total = 0`; the never-collected case has no snapshot at all.

**DECIDED 2026-10-02** — the coverage domain is **`PAN-COV-###`**. The prefix is unused in
both `controls.json` and `seed.json`, and none of the 27 existing domains fits a finding about
our own visibility.

| id | assertion | state |
|---|---|---|
| `PAN-COV-001` | an EDL referenced by an in-scope rule, that no collection has ever reported on | **BUILT** 2026-10-02, OEA `8e8561e` |
| `PAN-COV-002` | an EDL's content was truncated at the collection ceiling, so its size is a known under-count | **BUILT** 2026-10-02 |
| `PAN-COV-003` | an application group or filter is unresolved, so a rule's application count may be understated | not built — needs application-group modelling, which does not exist, and its own control_type since its subject is a rule |

Built as a tab of their own in the app and the workbook, with prose summaries rather than
columns. `CoverageFinding` still extends `ObjectFindingBase` and keys to an address object: the
first attempt dropped the foreign key for genericity and six convergence invariants rejected
it. The generic half is the presentation; the structure stayed.

**The client-facing one is not a PAN-COV.** The corpus was searched for the ASSERTION rather
than the name, per the checklist, and nothing covers it: `PAN-POL-017` asks whether EDLs are
used at all and `PAN-POL-018` is IP/Geo blocking. The nearest shape is `PAN-LOG-010 Log
Forwarding Health Verified` — a health check on an external dependency — which is a different
domain. So it needs a new id, and **`PAN-POL-023` is the next free number in both files**:

> **PAN-POL-023 — External Dynamic List Resolvable by the Device.** An EDL a rule enforces
> against must be one the firewall can actually fetch. `prod_west_edl` on the lab answers
> `total-valid 0, total-invalid 1` with cURL error 28: the rule is live and the list behind it
> is empty, so the rule matches nothing it was written to match. The device's own counters say
> so, which is what separates this from our coverage gaps — `resolved_content_source_total` is
> 0 against a snapshot that exists, where a never-collected list has no snapshot at all.

## Why not the corpus's measure, or the product

- **The corpus's "broadest side" is a max**, and a max cannot distinguish `any → one host`
  from `any → any`. That collision is exactly what makes PAN-POL-001 a strict subset of
  002-critical.
- **The product of the two sides is out.** Jason, 2026-09-30: "too coarse." Worth knowing when
  revisiting: sum-of-bits is the SAME ORDERING as the product, since
  log2(src × dst) = log2(src) + log2(dst).
- The per-field + aggregate scheme here keeps the two sides separate and visible, which is what
  both of the above lose.

## PAN-POL-004 and PAN-POL-005 are not this control

Jason, 2026-10-01: "PAN-POL-004 is a separate check and answers a different question that isn't
permissivity. Same with 005."

Confirmed by example: a rule with `service tcp-443` is **not** application-default, so it fires
004, and is **narrow**, so it scores Null here. The questions genuinely differ — 004 and 005
ask whether a recommended construct was used, this asks how much is permitted. A rule with
`service any` will produce findings from both; the "one object, one row" presentation rule puts
them on the same row, which is the right outcome.

## Verification of the tables

Checked 2026-09-30, not eyeballed:

- **Every address band boundary** is consistent with `network_bits = 32 − ceil(log2 n)`. Each
  band holds n in (2^(32−b−1), 2^(32−b)] for its prefixes — e.g. /11 holds 1,048,577–2,097,152,
  so the High band /8–/11 is 1,048,577–16,777,216 as written.
- **All seven test cases reproduce.**
- The tier ladder maps onto the existing severity vocabulary with no new values needed.

### Test cases

Service `application-default` unless noted. Per-field order: source, destination, service,
application.

| Rule | Per-field tiers | 2nd highest | Aggregate |
|---|---|---|---|
| /12 → /12, 8 apps | Medium, Medium, Null, Low | Medium | High |
| /12 → /12, 1 app | Medium, Medium, Null, Null | Medium | High |
| /12 → /12, 50 apps, 200 TCP ports | Medium, Medium, High, High | High | Critical |
| /16 → /16, 1 app | Low, Low, Null, Null | Low | Medium |
| /20 → /20, 10 apps | Null, Null, Null, Low | Null | No finding |
| /16 → /24, 5 apps | Low, Null, Null, Null | Null | No finding |
| host → host, app `any`, svc `any` | Null, Null, Critical, Critical | Critical | Critical |

## What exists, and what blocks the build

**Built** (OEI `0bb3683`, 2026-09-30): every address object carries a size. `num_hosts` was
already filled for `ip_netmask` and `builtin_any`; it is now filled for **EDL and FQDN** from
their resolved runtime intervals and for **synthetic negated complements**, which had none. An
object that resolved to nothing keeps `num_hosts` **NULL, not 0**.

**Not built, by instruction:** per-rule counts (the union of a side) and truncation handling in
the scorer.

| field | state |
|---|---|
| source / destination | **buildable** — object sizes exist; the per-side union does not |
| application | buildable, but **wrong without group/filter resolution**. `SecurityRuleApplication` stores a bare member string and nothing resolves it; the lab's merged config contains `application-group` nodes. One member that is a group of 80 apps counts as 1 → Null |
| service | **blocked** — `SecurityRuleService` also stores a bare member name, and **there is no ServiceObject model at all**. Resolving `tcp-443-loc` → (tcp, 443) needs one, plus predefined services and service-groups |

Per-rule counts belong in **normalization**, not the search layer: the search layer compares a
field to a literal and cannot traverse an edge.

### Subjects

Jason, 2026-09-30: create subjects for every test case after building, on **pan-fw-111** — the
only currently reachable device, single-vsys, slow commits. Per the checklist they are left in
place afterwards.

**Built 2026-10-05.** All six address bands now report. The lab's own policy supplies Critical
(174 rule sides broader than a /8) and Indeterminate (3); the four bands in between had no rule
subject and now have one each, written by `OptivEdgeProbe/scratch/lab_breadth_subjects.py`:

| Band | Object | Prefix | Addresses |
|---|---|---|---|
| Informational | `oep-breadth-info` | 10.64.0.0/18 | 16,384 |
| Low | `oep-breadth-low` | 10.65.0.0/16 | 65,536 |
| Medium | `oep-breadth-medium` | 10.68.0.0/14 | 262,144 |
| High | `oep-breadth-high` | 10.96.0.0/11 | 2,097,152 |

Each is the **source** of one enabled local allow rule whose destination is `oep-breadth-sink`
(198.51.100.254/32, RFC 5737). These rules are **not disabled**, unlike the PAN-COV subjects,
because the control excludes disabled rules — a disabled rule permits nothing, so scoring its
breadth would be meaningless. Harmlessness comes from the destination and from `application
ssl` / `service application-default` instead.

**A band is covered when a RULE lands in it, not when an object does.** The object census that
sized this work — 490 of 501 objects Null, 2 High, 9 Critical — said High was covered. It was
not: those two objects are not on the source or destination of any in-scope allow rule, and the
rule-side distribution measured before any subject was written read 174 critical, **0 high**, 0
medium, 0 low, 0 informational, 1,529 narrow, 3 indeterminate. Four bands were missing, not
three, and the earlier wording of this section said both numbers in one paragraph.

**The full case matrix was built the same day**, after the four band subjects: 98 rules on
pan-fw-111, ten or more for each of the nine cases the control distinguishes — the five bands,
the narrow band that must stay silent, indeterminate, worst-side-wins, and the out-of-scope
actions. `OptivEdgeProbe/scratch/lab_breadth_matrix.py` writes them and
`scratch/validate_pol002.py verify` checks each one against an expectation file computed by
that module's own arithmetic rather than read back from the normalizer. 98/98 agree on both the
side counts and the severity.

Three kinds of case needed more than a netmask object, and they are the ones that would
otherwise fail invisibly:

- **Exact band edges.** Every threshold is `gt` against a power of two, so one `gte` moves a
  whole class of rules by one severity. An `ip-range` object takes an arbitrary count, so each
  band has a subject at exactly its floor+1 and exactly its ceiling. One rule is exactly 8,192
  addresses and must report **nothing**; the next is 8,193.
- **Merges that cross a band.** A side naming a /8 and a /16 inside it is 16,777,216 merged and
  16,842,752 unmerged — `high` against `critical`. The band reveals whether the union was
  de-duplicated, where a count only reveals it to someone checking the arithmetic.
- **Negated sides that are not critical.** Negating one host only exercises the critical band. A
  range from `0.0.0.0` to `MAX − n` has a complement of exactly *n*, so a negated side can be
  landed in any band; if negation were reading the members instead of the complement, all four
  would report critical.

Objects for different rules may overlap freely — breadth is computed per rule side, so two
rules each naming a /8 do not interact. Only members on the **same** side merge, which is what
the merge cases above are built on.

One PAN-OS constraint turned up while building it: **`negate-source` cannot be combined with
the keyword `any`.** The `set` is accepted and the COMMIT refuses the whole candidate. It is a
keyword check and not a space check — the same space as a `0.0.0.0/0` object negates and commits
fine, which is the only subject that reaches the normalizer's empty-complement branch.

Service and application subjects wait on the models above.

## Open questions

1. Whether PAN-POL-001 retires into this control.
2. Whether zones return as a separate control.
3. Whether PAN-OS accepts port 0 in a service object (moves the service bound by 2).
4. PAN-POL-023, the client-facing half — an EDL the DEVICE cannot fetch — is allocated and
   unbuilt. It is not a coverage finding and belongs in the policy domain.
