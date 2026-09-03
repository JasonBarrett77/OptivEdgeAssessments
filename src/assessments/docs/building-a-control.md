# Building a control — the checklist

> Read this before starting a control, and again before calling one done.

Every item here is here because it was **missed once**, on a control someone believed was
finished. None of it is general advice; each line has an incident behind it, and the incident
is named so the item can be argued with rather than obeyed.

**Read the bold sentence as the rule and the italics as one instance of it.** The instances
are PAN-OS because that is what has been built; the rules are not. A second vendor, a second
management platform or an unfamiliar subsystem should change the examples and leave the rules
standing. An item is not inapplicable because its example names a tool you are not using —
ask what that tool was doing and find the local equivalent.

**Add to this file whenever a control turns out to need work after it looked done.** That is
the only way it stays worth reading.

**Items that produce a durable fact name where it goes**, as `→ payload contract` and so on.
That list IS the schema: the in-flight scratchpad's fields come from these items rather than
from a separate document, so the two cannot drift. The four destinations:

| destination | holds |
|---|---|
| `OptivEdgeProbe/reference/panos-payload-contract.json` | key sets, wire shapes, implicit values |
| `OptivEdgeProbe/scratch/reproductions.json` | the API calls that give each control a subject |
| `OptivEdgeProbe/scratch/control-changes.json` | deviations from controls.json, and status |
| `OptivEdgeProbe/scratch/controls-status.csv` | every control's state at a glance — generated, never edited |
| the OptivEdgeIntegrations vendor guides + discovery log | facts consumers depend on, and how they were established |

While a batch is in flight, `OptivEdgeProbe/scratch/in-flight.json` holds what has not reached
one of those yet — measurements not yet recorded, which lab device carries which variant,
questions raised and unanswered. It is a scratchpad, never a source of truth: entries graduate
and are then deleted, and empty is its normal state.

---

## 1. Understand the configuration — before modelling anything

> **Measure in parallel, not in series.** A commit is the slow step, and most variants are
> independent of each other, so they can all exist at once and be read in a single pass.
>
> - **Different devices are independent.** An HA pair is two devices off one baseline: put
>   the variant on one and leave the other as the control.
> - **Panorama and local are different layers.** A template or stack value and a device-local
>   value can be written in the same round. Writing both for the SAME key is not a shortcut —
>   that combination is its own measurement, of override behaviour.
> - **Different objects on one device are independent.** One profile passing and another
>   failing, on the same firewall, in one commit.
> - **Passing, failing and implicit can all exist simultaneously.** A control needs a subject
>   that violates it, one that satisfies it, and ideally one that has never been configured.
>   Those are three objects or three devices, not three rounds.
>
> Write down which device or object carries which variant before committing — in
> `OptivEdgeProbe/scratch/in-flight.json` under `lab_variants`, not in your head. The saving
> is real and so is the confusion when a result cannot be attributed.
>
> This also folds phase 5 into phase 1: a failing subject set up to measure a shape is the
> subject the control needs left behind, so it never has to be created twice.


- [ ] **Enumerate the real key set from the device** `→ payload contract`, rather than from a sample, a document
      or memory. Use whatever the platform offers as a schema oracle. *PAN-OS: `action=complete`.
      The payload contract recorded 6 management services; a firewall accepts 10. Two
      normalizers hard-coded 5 interface containers; a PA-5220 offers 6 and a PA-VM offers 5 —
      and `sdwan`, which neither listed, is on both.*
- [ ] **The key set is platform-dependent.** `→ payload contract` Check a second platform before treating it as
      fixed. *`vlan` exists on a PA-5220 and not on a PA-VM.*
- [ ] **Establish the implicit value by measurement, per key.** `→ payload contract` An absent key is not an
      absent setting, and neighbouring keys do not share a default. *`disable-http` was
      recorded implicit `no` and measures `yes`. `server-verification` absent means ENABLED
      while `enable-log-high-dp-load` absent means DISABLED — two keys, opposite defaults, so
      one assumption would have flagged every device for one control and no device for the
      other.*
- [ ] **If writing both values leaves both stored, the default is not discoverable that
      way.** Some keys are omitted when they match the default, which reveals it; others
      persist whatever you write, and then absence only means "never written". Use another
      oracle — the vendor UI on an unconfigured device is usually the fastest, and asking the
      operator to look is faster than inferring. *`server-verification`, `ack-login-banner`
      and `enable-log-high-dp-load` all persist `yes` and `no` alike; the checkbox states
      settled all three in one screenshot.*
- [ ] **Distinguish absent from empty from default.** `→ payload contract` Three states, and a config format that
      has all three will use all three. *PAN-OS: an empty `<units/>` and an empty
      `<aggregate-ethernet/>` both parse to `None`, not `{}`.*
- [ ] **Check what the value looks like when it arrives from a central manager** `→ payload contract`, not only
      when set on the device. The shape usually differs, and not every read exposes the
      difference. *PAN-OS: a template leaf arrives as `{'@ptpl': …, '#text': 'yes'}` and a
      naive reader calls it unset; `action=get` strips `@ptpl` entirely, so only merged config
      carries it.*
- [ ] **Ask which oracle can see it.** `→ discovery log` Some settings appear in no config read at all. *Four
      management services are invisible to `show system services` and to the running config;
      only the compiled ACL sees them.*
- [ ] **A schema oracle says what MAY be set, never what IS set.** Do not quote one as
      evidence of what a real payload looks like — that needs an instance. *PAN-OS:
      `action=complete`. The `vlan` payload shape was asserted from it and only later
      measured, and it happened to be right.*

- [ ] **Search the corpus for the CONCEPT before allocating a new id.** The allocation rule
      guards against id collisions — next free number, check both files — and says nothing
      about a control that already exists under a different domain. Grep `controls.json` for
      the *assertion*, not the name, and check neighbouring domains before deciding a control
      is new. *PAN-MGT-014 was allocated for the certificate half of a split, and duplicated
      PAN-CRT-006 "Management Certificate Issued by Trusted CA" — same intent, same
      man-in-the-middle rationale, same minimum. Splitting a control feels like creating one,
      so the corpus was never searched for the half being split off; it surfaced only when the
      certificates domain came up as the next batch. Re-identified, and nothing about the
      built control changed — it was correct and filed under the wrong number.*

## 2. Model it — in OptivEdgeIntegrations

- [ ] **Decide the object root by asking what a finding names.** *"Telnet is enabled" is not
      reportable; "telnet is enabled on ethernet1/1" is. The surface is the object and the
      service is a value on it. An unused profile has no surface, which is why the profile
      needed a model of its own.*
- [ ] **Scope it by where the config lives, not by how the documentation groups it.** The
      two disagree. *PAN-OS: `vsys/entry/…` → `EnforcementPoint`, everything else →
      `Appliance`. `Zone` is a network-plane concept that scopes like policy because it lives
      under `vsys/entry`.*
- [ ] **Populate every appliance, including both HA peers**, unless there is a bridge model
      recording which appliances a row speaks for. *Interfaces were normalized for the active
      member only, which gave the model appliance-anchored identity with group-like
      population — "this peer has no interfaces" became indistinguishable from "this peer was
      never normalized".*
- [ ] **Provenance uses `ProvenancedMixin` and `FieldProvenance`. There is no second
      mechanism.** Read it with the helpers in `normalization/common.py`. *A bespoke
      `provenance = CharField` was built and removed a day later: it could not hold the type,
      could not be queried, and could not tell a PAN-OS default from a local value.*
- [ ] **Adding fields to an already-provenanced model does NOT inherit its provenance.**
      Every new field must be appended to that normalizer's `field_provenance_data` too, or it
      silently stores values with no source. *Sixteen password-complexity fields went onto
      `DeviceConfigurationProfile` — a model that has used `ProvenancedMixin` since it was
      written — and none of them recorded provenance. Nothing failed: the columns were right,
      the findings were right, and the gap only surfaced while building the tab. The model
      being provenanced is what makes this easy to miss.*
- [ ] **Search for an existing helper before writing one.** *`common.py` already had
      `scalar_value`, `parse_yes_no_field`, `entry_provenance`, `classify_prov_type` and
      `ABSENT`; a private `_provenance()` was written beside them, checking the wrong key
      set.*
- [ ] **Never skip a payload you cannot parse.** Emit a `NormalizationIssue`. *A list that
      looks complete and is not is worse than an error.*
- [ ] **Report an unknown shape rather than dropping it.** Keep the row, warn, say what was
      unrecognised. *An unfamiliar interface container is still walked, because hard-coding
      the container set is what made `sdwan` invisible.*
- [ ] **Wire it into every path that produces the data** — collection and re-normalization
      both — with its **own** error handling. One part of the answer failing must not silently
      remove another. *PAN-OS: `flows.py`, where the two paths share one loop.*

- [ ] **Check a new model against the certificate reference list.** `→ certificate-reference-locations.csv`
      `OptivEdgeProbe/scratch/certificate-reference-locations.csv` holds the 67 places PAN-OS
      lets a certificate be referenced. Set `covered_by` on any row your model's subtree now
      covers, and ADD a row if you find a reference the list is missing. PAN-CRT-001 and
      PAN-CRT-008 are deferred until enough of those locations have models, and this is how
      they stop being deferred — incrementally, as each domain lands. *Do not build a model
      because it is on the list: it is a coverage checklist, not a work queue.*

## 3. Assess it — the control

- [ ] **A finding rests on a COLUMN. Never on a JSON field or a raw payload.** If a control
      needs something that currently lives inside a JSON blob, promote it to a real column in
      normalization and query that. Raw payload fields — `raw_rule`, `raw_profile` — are never
      registered as searchable at all.
      Four reasons, and the first two bite silently: a JSON lookup is unindexed, and it matches
      NOTHING when the vendor renames a key, so the control quietly stops finding anything
      rather than failing. It also writes the shape of a vendor payload into a control
      definition, where no schema protects it and no migration will catch it. And a raw payload
      is not normalized data — assessing it means the control has its own private
      interpretation of the config, which is the thing normalization exists to prevent.
      *This is long-standing practice — `permitted_ip_count` is searchable while
      `permitted_ip_values` is not, `bound_interface_count` while `bound_interface_names` is
      not — and it was broken once, by PAN-CRT-009 querying
      `protocol_algorithms__auth-algo-sha1`. `allows_sha1` is now a column with a clean() guard
      keeping it consistent with the JSON it derives from. Only the one algorithm a control
      asserts was promoted: a column per key would be eleven migrations ahead of a
      requirement.*


- [ ] **Use the id from `controls.json`** `→ control-changes.json`, and record every deviation in
      `scratch/control-changes.json` with what now covers any dropped ground.
- [ ] **Replace the superseded seed control** `→ control-changes.json`, and check whether it splits. *Seed `MGMT-001`
      asserted telnet and http together; `controls.json` has them as two controls.*
- [ ] **Check whether the assertion is broader than the control's title.** `→ control-changes.json` A control named
      for one subject often asserts something true of several. *PAN-MGT-001/002/003 were
      written for the management interface and apply to every administrative surface.*
- [ ] **A `posture` or `architecture-review` control usually cannot be decided from config.**
      Enumerate and let the assessor filter, rather than guessing. *006 asks whether a zone is
      "untrusted", which no zone name states.*
- [ ] **Watch the breadth of what fires.** *006 firing on any enabled service would flag every
      interface with `ping` on. It fires on the five administrative services only.*
- [ ] **Adding a member to an enum? Check every map keyed by that enum.** Nothing enforces
      the pairing, and the failure is silent. *`interface_management_profile` was added to
      `ControlType` and not to `_CONTROL_TYPE_TARGET_MODEL`, so `target_model` was wiped on
      every save and the catalog reported permanent drift against itself. There is now a test
      asserting the maps stay in step.*
- [ ] **A classifier that collapses many values into a verdict must be right at the
      boundary.** Find the value that looks like one class and behaves like another, and check
      both directions — over-correcting is as wrong as the original. *A list containing only
      `0.0.0.0/0` was reported Restricted. The fix then reported `[0.0.0.0/0, jump host]` as
      undetermined everywhere, a false positive on a hardened device, and contradicted a
      measurement already in the corpus.*

## 4. Present it

- [ ] **One object, one row — every control that assesses it reports there.** Where several
      controls share a subject, the tab presents the OBJECT and all of its findings together,
      rather than one row per control or a tab per control. An engineer fixes the object, not
      the control, and needs to see everything wrong with it in one place. *An SSL/TLS service
      profile is assessed by PAN-CRT-005 for its protocol floor and PAN-CRT-009 for its
      algorithms, and they fail independently — `oep-tls-legacy` reports both, while
      `oep-mgmt-tls-hardened` passes the floor and fails the algorithms. Two rows for that
      first profile would imply two problems where there is one object to remediate.*
      This is why the finding models carry `subject_name` and `subject_scope`: the object is
      the key the presentation groups by, and a name alone is not unique on a device.
- [ ] **A new subject gets its OWN TAB, not columns on Device Configuration.** That table is
      being retired precisely because it accumulated a column group per finding type and every
      new control widened it; object- and control-specific tabs replace it as they come up. Put
      the subject and its controls on one tab, and show controls that fail independently side
      by side so the rows where they disagree are visible. *PAN-MGT-010 was first built as a
      three-column group on Device Configuration, which the LoginBannerListView docstring
      already explained not to do. It became the Management TLS tab, which is also what made
      the 010-passes / 014-fails row legible on a single line.*
- [ ] **Show only the provenance you actually have.** Values resolved from an object elsewhere
      in the tree carry no `@ptpl` of their own, so a provenance line under them is an
      invention. *On the Management TLS tab only the BINDING has provenance; the profile's
      protocol range and certificate are read from the profile object and deliberately show
      none.*
- [ ] **Assert the table stays square.** Body cells == header cells; group spans cover every
      column. *Removing two model fields left the headers declaring columns the body no longer
      rendered, shifting everything after them.*
- [ ] **Blank cells are ambiguous.** Say "any source", "Nothing", not nothing at all.
- [ ] **Anything referenced by name is unvalidated until render.** Icons, template includes,
      URL names. *A lucide icon that does not exist reads an SVG off disk and 500s, failing
      ten unrelated view tests at once.* **For icons, list the directory first** — the set is
      not lucide's, it is the ~17 SVGs vendored at
      `OptivEdge/src/optivedge/templates/components/icons/`. *Picked from memory three times
      now — `lock`, `layers`, then `key-round` and `git-branch` in one commit. Reusing an icon
      another tab already uses is fine and normal here; inventing a plausible name is not.*
- [ ] **Empty-state text must name the right action.** *Both tabs said "run a sync"; both
      needed only a renormalize, which contacts no device.*

## 5. Prove it — against hardware, not fixtures

- [ ] **Include a state that MUST come back different.** When a measurement's answer is "no
      change", that reading is indistinguishable from "the thing was never wired up" — the
      instrument being broken and the device being uninteresting look identical. Pair every
      such measurement with a control state whose result is known in advance, in the same run.
      *This was hit twice on one day, 2026-09-02, on unrelated objects. A custom SSL/TLS
      profile sharing a predefined name changed nothing; only a second, uniquely-named profile
      — which did change what negotiated, proving bindings work on that device at all — made
      the null result admissible. Separately, `[0.0.0.0/0, 10.99.99.99]` on a profile came back
      OPEN, but so had the state before it, so the surface had never been watched TRANSITION
      into it; re-running from a freshly closed baseline was what turned "still open" into
      "opened".*
- [ ] **A count is meaningless without the environment that produced it.** Two databases
      with different appliance topology give different totals for the same correct lab, and a
      number quoted across them reads as findings lost. Make the tool print WHICH database and
      what makes it differ, so a total cannot be repeated without its context. *The findings
      census exists in two forms — one against the probe's own database, one against the Lab
      project's. The probe census builds STANDALONE appliance groups, so `ha_required` is
      false and the HA controls can never fire there: a permanent four-finding offset that is
      structural, not quiet. Two sessions spent a round reconciling 35 against 31 before
      noticing they were different databases. Both now print their database and group
      composition on every run.*

      The environment note fixes the TOOL. It does not fix a reader who has already decided
      which rows are theirs, and that is the harder half: a per-control census invites reading
      as fourteen separate answers rather than one description of a database. *Both sessions
      printed `HA-001 / HA-002 / HA-003 → NO FINDINGS` on every run all day and read past them
      every time — one because those controls belonged to the other session, the other having
      actually diagnosed the discrepancy mid-session, called it an environment difference, and
      moved on without recording it. Three zero rows, visible in output we generated ourselves
      four times, describing the exact thing we then spent a round reconciling. The checklist
      says an empty control is either one needing a subject or one that does not work, and
      that the census cannot tell you which — so ask. Neither of us asked, because we were
      reading to confirm rather than to learn. Same posture as the item above.*
- [ ] **A verification tool must not fail in the direction of its own answer.** The census
      exists to answer "did a control go quiet". One `try` wrapped its collection AND every
      normalizer for an appliance, so a single failed read skipped all of them and the tool
      reported zero findings for that host across every control — a failure that is
      indistinguishable from the regression it was built to detect. Ask what a tool prints
      when it breaks, and make that different from what it prints when the finding is real.

      Which steps may gate is decided by **"can this failure be mistaken for an answer?"**,
      not by how bad the failure is. In the census the merged-config read gates and the
      predefined read does not, and that is not a severity ranking: continuing past a failed
      merged-config read silently re-reports an OLD collection as current, with nothing on
      the output saying so, while a failed predefined read only leaves a binding unresolved —
      which normalization already says out loud. A failure that announces itself can be
      allowed to degrade; one that produces a plausible-looking result must stop.
      *Found by a peer session reviewing a fix for the identical coupling one layer down,
      where one unavailable predefined catalog was discarding all three for both PA-5220s.
      Same shape, twice in one day: the gating step should be the only one that gates.*
- [ ] **Validate the instrument before believing it.** `→ payload contract's instrument_note` A
      measuring tool's failure modes mimic device behaviour, and the mimicry is close enough to
      publish. Prove the tool reports a KNOWN result correctly before trusting it on an unknown
      one, and record every trap next to the measurement so the next reader does not re-derive
      it. *`measure_mgmt_tls.sh` produced four separate wrong answers: openssl prints
      `verify error:num=18` on SUCCESSFUL handshakes, so grepping for "error" reported every
      version refused; it silently will not OFFER tls1/tls1_1 without `SECLEVEL=0`, which reads
      as a server refusal; detecting on the session summary's `Protocol :` line loses TLS 1.3
      entirely, so a correctly hardened device looked like it refused everything — the most
      dangerous of the four, because 1.3 is the PASSING outcome; and the obvious fix, the
      `New, TLSv...` line, reports genuine 1.1 and 1.2 handshakes as `TLSv1.0`. A device fact
      was published from the third of these and had to be corrected.*
- [ ] **Make the control fire.** A control that returns zero findings has proven nothing.
      Configure the condition on the lab and watch it fire on the right subject. *001 and 002
      both returned zero against the lab as it stood.* **Set the passing and failing subjects
      in the same commit** — see the note at the top of phase 1 — and prefer subjects the
      discovery phase already created.
- [ ] **LEAVE the condition in place.** `→ reproductions.json` Every implemented control should have at least one
      live finding in the lab, permanently. A control with no subject cannot be demonstrated,
      cannot be checked after a refactor, and its UI has nothing to render. *PAN-MGT-009
      reported nothing for a correct reason — `server-verification` absent means enabled — so
      it was turned off on the passive HA member and deliberately not reverted.*
- [ ] **A column tested against one input has been tested against one input.** If every row
      in the estate gives a column the same value, rendering it correctly proves nothing about
      the other cases — including the case where the column is simply broken. Leave a subject
      that produces a DIFFERENT value for each column a control introduces.
      The instance that produced this rule: **leave at least one finding whose row SHOWS
      PROVENANCE.** `→ reproductions.json` A finding written locally proves the control fires
      and proves nothing about the provenance column, because local renders BLANK by design —
      so a tab can look correct while the whole provenance path is untested end to end. Push at least one subject from a template or
      stack so a source actually renders, and say in `reproductions.json` which subject exists
      for that purpose. *Both the Login Banner and Management TLS tabs shipped with every
      provenance cell blank and no way to tell a working toggle from a broken one: every value
      on them was device-local or absent. Jason caught it in the view, not the tests.*
      Two traps when creating one: a **local value survives a template push of a different
      value** and stays unmarked, so pushing to a device that already sets the field locally
      changes nothing visible; and pushing a value that REMEDIATES the control silences the
      finding you were trying to decorate — push a value that still fails, or an explicit
      negative like `ack-login-banner: no`.
- [ ] **A subject you built is also a measurement — go back and read it.** Creating lab
      config to make a control fire does not feel like taking a measurement, so nobody
      re-opens the vendor guide afterwards. But a subject is an INSTANCE of the shape the
      guide describes, and it frequently answers something the guide still lists as open.
      After building one, re-read that object's guide and check whether its Limits section is
      now stale. *A guide claimed `@ptpl` on a profile entry was unconfirmed because no
      populated profile had been pushed from a template — one had been, weeks earlier, as
      another control's subject, and the markers turned out to sit on four levels including a
      service leaf that arrives as `{"@ptpl":…, "#text":"yes"}` where a local one is the bare
      string `"yes"`. It had been in plain sight in every verification read since, unnoticed
      because those reads were confirming the lab was intact rather than looking to learn.*
- [ ] **Exercise every axis the control spans**, not just the one that was convenient.
      *PAN-OS: both service polarities, both management planes, both HA peers — the two planes
      spell the same setting with opposite sense, so a control tested on one is untested on
      the other.*
- [ ] **Run the real pipeline, not the fixtures.** *Fixtures passed while real config broke
      four separate ways: empty `<units/>`, empty container, subinterface type discrimination,
      and a warning on every unconfigured port.*
- [ ] **Name what is still fixture-only.** `→ the vendor guide's Limits` *`layer2`, `tap`, `virtual-wire`, `ha`,
      `dhcp-client`, `pppoe`, IPv6 addressing and `sdwan` have never been seen on hardware.*
- [ ] **DELETE returns a node to its implicit state**, which is how scaffolding comes out when
      the prior state is unknown. Two things measured, one expected:
      **Measured** — on some paths deleting an ABSENT node succeeds silently rather than
      erroring, so a successful delete is not evidence anything was there. **Measured** — it
      still dirties the candidate config, so a probe that changes nothing semantically needs a
      commit or a `<revert><config/></revert>` afterwards.
      **Measured** — a refused delete DOES error, loudly and specifically:
      `status=error code=10`, `"oep-tls-control cannot be deleted because of references from:
      deviceconfig -> system -> ssl-tls-service-profile"`. It names the referring path, so the
      error tells you what to fix.
      **Falsified** — walking UP the tree does NOT help here, and this item used to tell you to
      try it. That refusal is *referential*, not structural: the parent container is held by the
      same reference, so every level up refuses for the identical reason. What clears it is
      removing the REFERENCE, not finding a bigger hammer. Referential integrity is evaluated
      against the CANDIDATE, so re-pointing the referrer earlier in the same commit makes the
      delete succeed — no extra commit needed. Order scaffolding removal accordingly: create
      and re-bind the replacement first, delete the old object second.
      Whether a *structurally* undeletable leaf exists, and whether walking up helps for that
      case, is still unobserved — do not assume this measurement covers it.
- [ ] **Revert the SCAFFOLDING, keep the SUBJECT.** `→ reproductions.json` Two different kinds of lab change:
      config written to measure a shape or a default is scaffolding and comes out; config that
      is the thing a control detects stays. Say plainly which is which. *Template pushes used
      to read provenance markers were reverted; the unused profiles and the disabled
      update-server verification were not, because PAN-MGT-013 and PAN-MGT-009 need them.*
- [ ] **Run the census** — `OptivEdgeProbe/scratch/lab_findings_census.py` — and check no
      implemented control comes back empty. An empty one is either a control that needs a
      subject or a control that does not work, and the census does not tell you which; that is
      the point of asking before you believe it is done.

## 6. Land it

- [ ] **Regenerate the status CSV** `→ controls-status.csv` —
      `python -m scratch.build_controls_csv`. It is generated from `controls.json` and
      `control-changes.json`, never edited, so it cannot drift; the only way it goes stale is
      not being run. It is how the state of 228 controls is read without opening the JSON.
- [ ] **Empty `scratch/in-flight.json`.** Run `python -m scratch.check_in_flight`: every fact
      it holds should have graduated to its durable home, and its entry deleted. A non-empty
      file is a to-do list, and anything left in it has not landed anywhere that will be read
      again.
- [ ] **Record the reproduction** `→ reproductions.json` — the actual API calls that give
      this control a subject, written from the strings the script used rather than
      reconstructed later. Note `subject_kind`: a control whose subject is an UNTOUCHED default
      has no call, and writing the default explicitly would not reproduce it.
- [ ] **Update `scratch/control-changes.json`.** Move `status` from `decided` to
      `implemented`, record what was built and what verified it, and add any deviation
      decided along the way. The file is only worth having if it still matches what shipped —
      a stale entry is worse than none, because it will be trusted.
- [ ] **Migration** — and check whether an existing environment needs a data migration.
- [ ] **Say what the operator must run**: migrate → renormalize → reseed → regenerate
      findings. Renormalize needs no device connection; a sync does.
- [ ] **Record measurements where the consumer is.** `→ the vendor guide` A vendor fact goes in the
      OptivEdgeIntegrations guides, next to the code that depends on it; the method stays in
      OptivEdgeProbe. A fact that spans subtrees goes at the top level, not under one of them.
      Stage doc changes for review first.
- [ ] **Add a discovery-log entry** `→ discovery log` for anything ambiguous, anything that took more than one
      attempt, and anything that contradicted an expectation.
