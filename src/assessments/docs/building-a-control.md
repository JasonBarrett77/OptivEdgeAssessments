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

## How to use it

The phases are ordered by dependency and the order is real: a model cannot be scoped
before the configuration is understood, and nothing can be proved before it exists. But this
is **not a document to walk from top to bottom**, and roughly half of it never was. Two kinds
of item live here and they are retrieved differently:

- **`- [ ]` steps** apply to every control. They are the ones worth ticking, and the ones a
  control is not finished without.
- **plain bullets are facts** — traps, platform behaviour, codebase constraints. They do not
  get ticked because they cannot be completed. You reach them through the sub-heading, which
  names the SITUATION that sends you looking: *when the control walks a reference*, *when you
  write or delete lab config*, *when you add a member to an enum*.

So: read a phase's steps in order, and read the sub-headings of its facts to see which
situations you are in. A sub-heading you are not in is a sub-heading you can skip — that is
what it is for.

The phases are not equally sequential. **Model it** and **Land it** are close to real
workflows. **Prove it** and **Present it** are mostly situational, and trying to perform them
in order is how their items get read past.

## Where a durable fact goes

**Items that produce a durable fact name where it goes**, as `→ payload contract` and so on.
That list IS the schema: the in-flight scratchpad's fields come from these items rather than
from a separate document, so the two cannot drift. The destinations:

| destination | holds |
|---|---|
| `OptivEdgeProbe/reference/panos-payload-contract.json` | key sets, wire shapes, implicit values |
| `OptivEdgeProbe/scratch/reproductions.json` | the API calls that give each control a subject |
| `OptivEdgeProbe/scratch/control-changes.json` | deviations from controls.json, and status |
| `OptivEdgeProbe/scratch/controls-status.csv` | every control's state at a glance — generated, never edited |
| `OptivEdgeProbe/scratch/certificate-reference-locations.csv` | the 67 places a certificate can be referenced |
| the OptivEdgeIntegrations vendor guides | facts consumers depend on, at the point of use |
| the OptivEdgeIntegrations discovery log | how those facts were established |

A `→` marker always sits immediately after the bold rule and names one row above, so the set
of destinations an item feeds can be read off mechanically. Arrows anywhere else in the prose
are ordinary punctuation.

While a batch is in flight, `OptivEdgeProbe/scratch/in-flight.json` holds what has not reached
one of those yet — measurements not yet recorded, which lab device carries which variant,
questions raised and unanswered. It is a scratchpad, never a source of truth: entries graduate
and are then deleted, and empty is its normal state.

## Where the answers already are

PAN-OS instances of general capabilities. A second vendor has its own, and the shape — a set
of vendor guides holding CONCLUSIONS, an instrument repo holding METHOD — is what transfers.

**Look here before measuring. In this order.**

| when you need | go to |
|---|---|
| what is already known about an object | the OptivEdgeIntegrations vendor guides, `integrations/docs/palo-alto/pan-os/` — 21 of them, and they are the conclusions, kept next to the code that depends on them |
| how a known fact was established, or its raw capture | `OptivEdgeProbe/archive/catalog/findings/` (31, frozen) and `captures/` (51, tracked because findings cite them as evidence) |
| why a fact reads the way it does | `OptivEdgeIntegrations/.../pan-os/discovery-log.md` — newest first, and it records what was ambiguous or took more than one attempt |
| key sets, wire shapes, implicit values | `OptivEdgeProbe/reference/panos-payload-contract.json` |
| a technique for establishing something | `OptivEdgeProbe/archive/catalog/procedures/establish-a-fact.md` — in the archive because it belonged to the retired catalog, not because it expired |

The guides came out of the findings: 11 were migrated on 2026-08-27 and there are 21 now. The
findings stayed behind with the method and the evidence. So **a guide is the first stop and
the archive is the second** — going to the archive first reads the working-out of a conclusion
that has since been written down properly, and possibly superseded.

**Searching the vendor's own documents.** Three indexes, each authoritative for something
different, all queried the same way — `python -m probe.doc_index [--doc help|api|guide] <term>`:

| index | authoritative for |
|---|---|
| `--doc help` — Web Interface Help | what is on a SCREEN and what each field means. Its table of contents mirrors the UI |
| `--doc api` — API Usage Guide | request shapes, what each `action` does, what a code MIGHT mean |
| `--doc guide` — Administrator's Guide | how to DO something, and why |

Read the SECTION path each result prints, not just the sentence — that rule has its own item
in phase 1 and it cost a planned experiment.

**The CLI grammar** is `python -m probe.cli_index <term>` over 70k records. **The schema
oracle** is `probe.investigations.schema_introspection.complete` — phase 1 has seven items on
what it can and cannot settle. `python -m probe.pipeline_check` asserts a change ARRIVED on
every firewall by re-reading config rather than trusting job status.

---


## 0. Identify the control

> **First, because everything after it depends on the answer.** Which control this is decides
> which configuration is worth reading, which object gets modelled and what the query has to
> assert.

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

- [ ] **Use the id from `controls.json`** `→ control-changes.json`, and record every deviation in
      `scratch/control-changes.json` with what now covers any dropped ground.

- [ ] **Replace the superseded seed control** `→ control-changes.json`, and check whether it splits. *Seed `MGMT-001`
      asserted telnet and http together; `controls.json` has them as two controls.*

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


### Start here

- [ ] **Read what is already known BEFORE measuring anything** — the OptivEdgeIntegrations
      guide for the object first, then the payload contract's entry, then the frozen findings
      in `OptivEdgeProbe/archive/catalog/` if you need the method behind one. See *Where the
      answers already are*. The guide is first because it is the CONCLUSION, maintained next to
      the code; the archive is the working-out and may have been superseded by it. The payload
      contract is
      written to be read, and the entries carry the traps as well as the key sets. *The
      `mfa-server-profile` entry has said since 2026-09-08 that `mfa-cert-profile` is required
      and that a profile without it is refused at commit with "Invalid MFA vendor config". A
      later control re-measured exactly that, from scratch, at the cost of two commits and a
      failed one - and the only reason the duplication was noticed at all was going to the file
      to write the result down.*

- [ ] **Read the Web Interface Help SECTION for the object, before anything else and again
      whenever you come back to the domain.** The whole section, not a keyword search:
      `python -m probe.doc_index --doc help "Setup > Management"`, then read the page. One read
      gives the field set, the ranges, the defaults, the semantics, the cross-references and
      the traps — and it is cheap enough that going back to it is never the expensive option.
      **It is not only for implicit values.** Reading it narrowly is how you miss that a field
      you were not asking about is the second binding for the one you were. *The Authentication
      Settings section stated three of four implicit values, gave the reachable ranges, named
      the vendor's own recommended value, and revealed that `deviceconfig/system/
      authentication-profile` exists as a device-wide binding the corpus xpath for PAN-AUTH-019
      does not mention.*



### Enumerating the key set

- [ ] **Enumerate the real key set from the device** `→ payload contract`, rather than from a sample, a document
      or memory. Use whatever the platform offers as a schema oracle. *PAN-OS: `action=complete`.
      The payload contract recorded 6 management services; a firewall accepts 10. Two
      normalizers hard-coded 5 interface containers; a PA-5220 offers 6 and a PA-VM offers 5 —
      and `sdwan`, which neither listed, is on both.*

- [ ] **The key set is platform-dependent — run the schema oracle against EACH target.** `→ payload contract` Check a second
      platform before treating it as
      fixed. *`vlan` exists on a PA-5220 and not on a PA-VM.*


### What an absent key means

- [ ] **Establish what an absent key MEANS, and what the value means, per key.**
      `→ payload contract` These are two questions and they need different oracles. An absent
      key is not an absent setting, neighbouring keys do not share a default, and a value's
      meaning is not always its magnitude. *`disable-http` was recorded implicit `no` and
      measures `yes`. `server-verification` absent means ENABLED while `enable-log-high-dp-load`
      absent means DISABLED — two keys, opposite defaults, so one assumption would have flagged
      every device for one control and no device for the other. And `lockout-time 0` is not a
      short lockout, it is an indefinite one.*

      Oracles, cheapest first. Reach down the list only as far as the question needs.
      **The columns say what each oracle is good for HERE, not what it is limited to** —
      they are answers to this item's question, not a description of the tool. The Help
      is not the defaults tool, `action=complete` is not the reference-map tool, and an
      operational command is not the last resort:

      | oracle | settles | cannot settle |
      |---|---|---|
      | **Web Interface Help** `probe.doc_index --doc help` | range, default, semantics, recommended value — and much it is not asked for: the field inventory of a screen, what an action does, constraints between fields, and a UI-location taxonomy | anything, on its own — it has been wrong and self-contradictory here |
      | **Merged config** | absent vs present vs pushed, and the `@ptpl` source | what absent MEANS |
      | **CLI grammar** `probe.cli_index` | reachable values, and sentinels that read as ordinary numbers | which of them is the default |
      | **Schema oracle** `action=complete` | what MAY be set, its children, its ENUM VALUES, where an object may be referenced — and, by returning nothing, where a node is not valid | what IS set, and which of the values is the default |
      | **Unconfigured UI form** (ask for a screenshot) | what the device itself presents when nothing is written | anything about a device that HAS been configured |
      | **Write / read / delete** | a default, but only when PAN-OS omits keys matching it | most keys — they persist whatever you write |
      | **Operational commands** | the EFFECTIVE value — INCLUDING where no key is configured, so this can answer "what does absent mean" outright; and state that appears in no config at all | what was intended, and which config produced the state |
      | **Behavioural probe** — connect and observe | what is actually enforced | why, and anything needing a human action |
      | **Deliberate misconfiguration + a person** | behaviour that needs a real login, failure or session | anything cheaper would have settled |

      *The bottom half earns its place: `show system masterkey-properties` is the ONLY place a
      master key's state and expiry appear — no config read carries them — so an operational
      command is sometimes not the expensive fallback but the only oracle there is. The compiled
      ACL revealed that a `0.0.0.0/0` permitted-ip entry is DISCARDED rather than honoured, which
      no config read shows. Negotiation measured
      that an unbound management interface accepts TLS 1.1 and 1.2 and serves the factory
      certificate. `show authentication locked-users` plus four failed logins by a person
      settled a lockout question the documentation contradicted itself about. `server-
      verification`, `ack-login-banner` and `enable-log-high-dp-load` all persist `yes` and `no`
      alike, so write/read returned nothing and one screenshot settled all three.*

- [ ] **Distinguish absent from empty from default.** `→ payload contract` Three states, and a config format that
      has all three will use all three. *PAN-OS: an empty `<units/>` and an empty
      `<aggregate-ethernet/>` both parse to `None`, not `{}`.*

- **To learn what an ABSENT key means, write the object WITHOUT it and open THAT in the
      UI.** The device renders its own default for a key that is not in the configuration, which
      is the question a control actually asks. Reach for it when the Help is silent and the
      device stores nothing it was not told, which is when the cheaper oracles have nothing left
      to say. *Three keys settled this way in one round: `ldap/ssl` is implicit YES,
      `saml-idp/validate-idp-certificate` and `want-auth-requests-signed` are implicit YES —
      and `ldap/verify-server-certificate`, four lines away from `ssl` in the same dialog, is
      implicit NO. Two of the three invert the safe-looking assumption; reading them as "absent
      means off" would have fired two controls on every unconfigured SAML profile in an estate.
      Neighbouring checkboxes on ONE screen do not share a default.*

- **What the Add form SHOWS is not what the Add form WRITES, and neither settles what an
      ABSENT key means.** Three different questions, and a screenshot answers only the first.
      *`Require SSL/TLS secured connection` is PRE-CHECKED on the LDAP Server Profile dialog —
      the opposite of the "checkboxes default cleared" reading. But the committed object carries
      `ssl: yes` explicitly, so the form WRITES that box rather than omitting it, while omitting
      three pre-filled numeric defaults on the same form. The UI is not uniform, so a profile
      with no `ssl` key was not created by that form at all — which is a useful fact and not the
      one the control needed. Settling absence took a fourth step: write the key-less object by
      API and have a person open THAT in the UI.*

- [ ] **When the cheaper oracles are exhausted, ASK.** A screenshot of an unconfigured form, or
      a login attempt, is usually faster than inference and is sometimes the ONLY oracle there
      is. Say which object, which screen, and what state it has to be in - an object written
      WITHOUT the key, not a fresh Add form, when absence is the question.

      **The reason it is sometimes the only oracle: a default is not IN the configuration.** A
      config read records what was SET. What the device does when nothing was set is behaviour,
      not data, and it appears in no read - not merged, not running, not effective - UNLESS a
      central manager explicitly wrote the value, and then what you are reading is Panorama's
      choice rather than the vendor's default. The device's own rendering is where the vendor's
      default becomes visible, and on a Panorama-managed estate it may be the only place it
      ever is.

      *The two log flags, measured 2026-09-22 on pan-fw-111. A shared rule was pushed carrying
      NEITHER key, and its absence was confirmed in Panorama's running and candidate configs, in
      the device's pushed-shared-policy and in effective-running - four reads agreeing the key
      is not there, and not one of them saying what that means. The device's own UI rendered
      "Log at Session End" TICKED and "Log at Session Start" unticked: log-end absent is YES,
      log-start absent is NO, two keys on one screen defaulting opposite ways. PAN-POL-009 turns
      on it, and reading log-end as "no" would have reported ten correctly-logging rules as
      unlogged. It was measured because Jason opened the screen; nothing else could have
      answered it.*


### Completion semantics — what `action=complete` can and cannot say

- **`action=complete` answers from the SCHEMA, so it answers for objects that are not
      CONFIGURED.** Complete `entry[@name='x']` for a name nothing uses and the children and
      enum values come back anyway, so an object type absent from every device still describes
      itself — no instance, no lab subject, no write. *`shared/admin-role` was null on all three
      lab devices and PAN-AUTH-023 had no subject anywhere; the role's structure read back in
      one call.* It answers on a **template** path too, from Panorama. *Completing a template's
      own config root returns `['devices', 'mgt-config', 'shared']`, which is how `mgt-config`
      was found to be a SIBLING of `devices` inside a template rather than nested under a device
      entry — a guess that would have failed at the write.*

      **"Not configured" is not "not a valid path", and the two answer differently.** An absent
      instance still returns the schema; an invalid path returns `code=6 Invalid sequence`. The
      next two items are entirely about telling those apart, so do not let this one blur them.

      **And "valid" is always valid ON THE DEVICE YOU ASKED.** `target` decides which schema
      answers, and a wrong one produces `Invalid sequence` that reads as "this path is not
      real". *A firewall has no `template` or `device-group` node, so every Panorama-side path
      completed through `probe.investigations.schema_introspection.complete`'s default target —
      which is a FIREWALL — came back Invalid sequence. The same call with `target=None` returns
      the template's children. It cuts both ways: Panorama's own `shared` does not hold
      `certificate-profile`, so that negative is real on Panorama and wrong about a firewall.*

      **It is not only for objects that are absent.** Its other uses are on live nodes —
      enumerating a configured node's children, and reading a reference field's
      eligibility-filtered value list, which is what confirmed the certificate reference map and
      what surfaced the three predefined admin roles a `custom` binding can point at. The oracle
      table above says what each oracle is good for HERE, not what it is limited to; ranking one
      use of this one above the others would contradict it.

- **To ask whether a node is VALID somewhere, complete a made-up ENTRY under it** —
      `<node>/entry[@name='x']` — never the container. There are THREE outcomes and they are
      three different facts: child keys returned (the node is valid there), no completions
      (valid, nothing to enumerate), and an API error `code=6 Invalid sequence` (the path itself
      is rejected). *`admin-role` returns two child keys under `shared` and INVALID PATH under a
      vsys — that is what a real negative looks like.*

- **A container of `entry` elements returns NO completions whether or not it exists.**
      Completing it proves nothing. *This produced a confidently wrong scoping conclusion:
      `vsys/entry/authentication-profile` returned nothing, was read as "not valid here", and
      recorded as settled across seventeen vsys on three devices. The node is perfectly valid —
      seventeen samples of an invalid method is still an invalid method, and the VOLUME made the
      wrong answer read as a strong one. Authentication profiles, certificates, certificate
      profiles, SSL/TLS service profiles, the local user database, server profiles and log
      settings are all vsys-scopable.*

- **Two sibling nodes can complete identically and store differently.** A value list from
      `action=complete` does not say whether the value is TEXT or an ELEMENT. *`protocol` on a
      radius server profile stores `{"PAP": null}`; `protocol` on the tacplus profile beside it
      stores the string `"PAP"`. Both complete to `['CHAP', 'PAP', ...]`. Writing the radius
      form into tacplus is refused at the write - "tacplus -> <name> -> protocol is invalid" -
      so a neighbour's wire form is not evidence about this one.*

- **An empty completion set on a LEAF means the element takes no text — so complete
      `<leaf>/member` before believing that.** *`devicereader` returned nothing and was written
      as `<devicereader>yes</devicereader>`, refused with "has unexpected text"; `<devicereader/>`
      was accepted, and that was recorded as the answer. It is half the answer. Completing
      `devicereader/member` returns `localhost.localdomain`: the leaf is a MEMBER LIST that is
      also valid bare, and `__telemetryuser` carries the populated form on all three lab devices.
      A model built on the bare shape drops the device names.*

- **Sibling keys under one parent are not one shape. Complete EACH of them.** The parent
      being a single UI dropdown is not evidence the payload is uniform. *`permissions/role-based`
      offers seven children in THREE shapes: `superuser`/`superreader` are yes/no leaves,
      `deviceadmin`/`devicereader` are member lists of device names, and
      `vsysadmin`/`vsysreader` are an entry PER DEVICE carrying a vsys member list. All three
      were live on the lab at once. Completing one sibling and generalising would have reported
      two thirds of the estate's administrators as holding no role at all — which reads as an
      account with no privilege, the safest-looking wrong answer there is.*

- **On a reference field, completions are ELIGIBILITY-FILTERED — the completion list IS the
      dropdown.** They are the values valid *there* on *that device*, not every instance of the
      type. *One authentication-profile field returned four values, another one, and a third
      none, on one device, purely by method eligibility — confirmed against the UI dropdowns
      twice, on two devices, with two different causes.* So an empty result is never disproof
      that the field can reference the type, and this is what makes `complete` a stand-in for a
      screenshot on any reference field.


### Reading the vendor documentation

- [ ] **Read the SECTION a sentence sits in before quoting it.** `probe.doc_index` prints it.
      Whole chapters govern one operating mode, and a rule from
      `Certifications > FIPS-CC Security Functions` is not advice about a field. *"You must
      ensure Failed Attempts and Lockout Time are greater than 0" was quoted here as general
      hardening that contradicted the corpus, and manufactured a doubt that cost a planned
      hardware experiment. It is a FIPS-CC requirement and contradicted nothing.*

- **When a document contradicts ITSELF, understand the contradiction before measuring —
      it usually carries the discriminator.** Two sentences in one document about one field
      cannot be resolved by finding a third, so a measurement is coming; but read both claims
      closely first and find what separates them — scope, operating mode, management plane,
      version, platform. That is what tells you which variable to vary, and what the result is
      allowed to claim afterwards. *The Help says both "the Failed Attempts is ignored and the
      user is never locked out" and "the user is locked out … until another administrator
      manually unlocks the account", in adjacent paragraphs on p.707. The first is prefixed
      "(Panorama managed firewalls only) … when you manage the setting from a TEMPLATE" — so the
      two are not symmetric claims about one behaviour, they are claims about two management
      planes. That prefix decided the experiment (set the keys locally) and it decided the
      write-up: the result settles the locally-set case and leaves the template case UNTESTED
      rather than disproved. Skipping straight to the device would have produced the same
      reading and a conclusion that overclaimed.*


### Reading device output

- [ ] **Ask which oracle can SEE it at all.** `→ discovery log` Some settings appear in no
      config read. *Four management services are invisible to `show system services` and to the
      running config; only the compiled ACL sees them.*

- [ ] **Never read truncated output as absence.** Print full values, or say `... (truncated)`.
      *A probe printed `json.dumps(node)[:300]` and a long `initcfg` public key pushed
      `idle-timeout` and `api/key/lifetime` past the cut; they were recorded as "not set on any
      lab device" when both were configured on pan-fw-111.* **Second instance, 2026-09-09, while
      this rule was being quoted in the same session**: `json.dumps(keys)[:150]` cut `ssl` off
      three LDAP profiles, and "three lab profiles have no ssl key, so they were not created by
      the form" was written into the payload contract before a full read showed all six state
      it. Knowing the rule is not the same as not printing a slice.


### Provenance, and values that arrive from a central manager

- [ ] **Check what the value looks like when it arrives from a central manager** `→ payload contract`, not only
      when set on the device. The shape usually differs, and not every read exposes the
      difference. *PAN-OS: a template leaf arrives as `{'@ptpl': …, '#text': 'yes'}` and a
      naive reader calls it unset; `action=get` strips `@ptpl` entirely, so only merged config
      carries it.*

- **A provenance marker on a CONTAINER says nothing about the entries inside it.**
      `→ payload contract` Read entry provenance from the entry. *`mgt-config/users` reports
      `{"@ptpl": "shared", ...}` on both PA-5220s while not one of their entries carries a marker:
      there is a template literally NAMED `shared` whose users node is EMPTY, and pushing an empty
      container marks the container. Reading the container would have labelled six device-local
      accounts as template-managed, and the template name looking like the shared-scope keyword is
      what makes it convincing.*

- **Whether a central manager delivered something is a question PER VIEW, not per device.**
      `→ payload contract` Read every view that can carry it before calling it absent. *A
      Panorama-shared anti-spyware profile that nothing referenced was looked for in
      fw-core-tpa-b's vsys1 pushed view, not found, and written into the lab script as "not
      pushed at all". The same object was in that device's vsys3 view and on pan-fw-111 - one
      view of four. It surfaced only because normalization, which unions every vsys, put the
      object where the write-up said it could not be.*


## 2. Model it — in OptivEdgeIntegrations


### Choosing the model

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


### Provenance

- [ ] **Storing a value for an ABSENT key is a claim about the vendor, so say which kind it
      is.** `parse_yes_no_field`, `parse_integer_field` and `parse_text_field` take an
      `Implicit`, and it is not optional: `Implicit.measured(value, citation)` where someone
      established what PAN-OS does, `Implicit.assumed(value, why)` where nobody has, and
      `Implicit.not_assumed(why)` where the right answer is to store nothing and leave the field
      null. The citation has to be checkable or it is not a citation — a payload contract node
      and field, a guide and its sentence, a dated measurement; `measured()` refuses a string
      too short to chase and the constructor refuses one carrying neither.
      *An audit of all 33 sites that defaulted a value found three kinds mixed together under
      one bare `default_effective=False`: defaults measured on hardware, defaults a guide
      documents, and defaults nobody had ever checked — including `log-start` and `log-end`,
      which `read-a-security-rule.md` says outright must be measured rather than assumed, and
      which PAN-POL-009 turns on. 14 of the 33 are still assumptions; the inventory test in
      OptivEdgeIntegrations names each one, so adding another is a deliberate act and the list
      doubles as the queue of what to measure next.*

- [ ] **A column normalization COMPUTED goes in the model's `DERIVED_FIELDS`.** A verdict, a
      count, a filtered subset, a value resolved through another object: none of them has a
      payload key, so none can have a provenance row, and undeclared they are indistinguishable
      from a field nobody tracks. The test is whether the payload carries the value in ANY
      form — a member list the device wrote is not derived, however unprovenanced it is.
      *It was a `derived_fields` tuple kept per SHEET in the artifact prototype, a repository
      away from the fields it described; 103 columns across 21 models are declared now. The
      invariant is that a declared field must never have a stored row, and running it against
      the normalized lab found the one real mistake: `community_is_default` IS computed, and its
      row is written on purpose, because the community string's value is never stored and that
      row is the only record of who set the credential.*

- [ ] **Adding fields to an already-provenanced model does NOT inherit its provenance.**
      Every new field must be appended to that normalizer's `field_provenance_data` too, or it
      silently stores values with no source. *Sixteen password-complexity fields went onto
      `DeviceConfigurationProfile` — a model that has used `ProvenancedMixin` since it was
      written — and none of them recorded provenance. Nothing failed: the columns were right,
      the findings were right, and the gap only surfaced while building the tab. The model
      being provenanced is what makes this easy to miss.*

- **Provenance uses `ProvenancedMixin` and `FieldProvenance`. There is no second
      mechanism.** Read it with the helpers in `normalization/common.py`. *A bespoke
      `provenance = CharField` was built and removed a day later: it could not hold the type,
      could not be queried, and could not tell a PAN-OS default from a local value.*


### A new column on an existing model

> The hazard is designed around at the moment the column is CREATED. Meeting it at landing
> means rewriting the migration.

- **A control reading a NEW derived column reports a CLEAN ESTATE until the data is
      re-normalized.** `→ control-changes.json` A migration creates the column; only normalization
      fills it. Between the two, every row holds the field's DEFAULT - and for a boolean that
      default is `False`, which on a "does this device offer something weak" column means
      compliant. So the control does not error and does not render an empty page: it passes every
      device, which is indistinguishable from a hardened estate. *Measured 2026-09-14 on one copy
      of the lab, with only the re-normalize differing: PAN-MCR-001, 002 and 003 fired on 0 of 3
      migrated-and-reseeded, and on 2 of 3 after re-normalizing from the same stored snapshots,
      as `non_preferred_ciphers` went from `[]` to `['aes128-cbc']`. Nothing failed in between.*
      **So a control whose query moves to a new column is not landed when its tests pass.** Say
      the sequence in its record - migrate, RENORMALIZE, reseed, regenerate - and say what
      skipping the re-normalize looks like, because "it reports nothing" will otherwise be read as
      good news.
      **Give the column a default that FIRES.** The hazard is not the gap between migrating and
      normalizing; it is that the natural default sits on the compliant side. `False` on "does
      this device offer something weak" is the safe-looking value and the dangerous one. The
      precedent was already here: `MasterKey` records a key nobody asked about as `undetermined`,
      which fires, because "we never asked" must not look like "we asked and it was fine". A
      derived column carries the same obligation - pair the firing default with a data migration
      marking existing rows not-yet-computed.
      **This bites a column ADDED to rows that already exist, and only that.** A brand-new model
      has no rows until normalization creates them, so there is no window in which a stale row
      reads as compliant - a new model is absent, and absence is visible. Adding a field to a
      populated model is the case to think about.

### Writing the normalizer

- [ ] **Search for an existing helper before writing one.** *`common.py` already had
      `scalar_value`, `parse_yes_no_field`, `parse_integer_field`, `parse_text_field`,
      `entry_provenance`, `classify_prov_type`, `was_absent`, `Implicit` and `ABSENT`; a private
      `_provenance()` was written beside them, checking the wrong key set.*
      **`was_absent` is the one to reach for**, not `raw_key is ABSENT`, which stopped being the
      whole question on 2026-09-21: an absent key arrives as the `Implicit` declaration now. Two
      lines in the security rule normalizer asked the old question and would have silently
      turned both log flags from null into False, with the whole suite passing.

- [ ] **Never skip a payload you cannot parse.** Emit a `NormalizationIssue`. *A list that
      looks complete and is not is worse than an error.*

- [ ] **Report an unknown shape rather than dropping it.** Keep the row, warn, say what was
      unrecognised. *An unfamiliar interface container is still walked, because hard-coding
      the container set is what made `sdwan` invisible.*

- [ ] **Wire it into every path that produces the data** — collection and re-normalization
      both — with its **own** error handling. One part of the answer failing must not silently
      remove another. *PAN-OS: `flows.py`, where the two paths share one loop.*
      **Then grep for a call site outside the tests.** A normalizer nobody calls fails exactly
      like a device with nothing to report, and every downstream surface renders correctly and
      empty. *Three of them — certificate objects, authentication profiles, password profiles —
      shipped with their own controls, tabs and passing tests, and `renormalize_in_scope_configuration`
      called none of them. The only thing that ever ran them was a test and a scratch script, so
      the renormalize button left four model families stale and said nothing. Found while wiring
      the fourth, by looking for the loop to add it to and discovering there wasn't one.*


### Coverage

- [ ] **Check a new model against the certificate reference list.** `→ certificate-reference-locations.csv`
      `OptivEdgeProbe/scratch/certificate-reference-locations.csv` holds the 67 places PAN-OS
      lets a certificate be referenced. Set `covered_by` on any row your model's subtree now
      covers, and ADD a row if you find a reference the list is missing. PAN-CRT-001 and
      PAN-CRT-008 are deferred until enough of those locations have models, and this is how
      they stop being deferred — incrementally, as each domain lands. *Do not build a model
      because it is on the list: it is a coverage checklist, not a work queue.*

      **Confirm the row while you are there — one `action=complete` call.** Every row is a claim
      from the CLI grammar that an xpath *can* hold a certificate. Completing that xpath returns,
      on a typed reference field, `@vxpath` — the full xpath of the referenced definition — which
      proves the edge outright and replaces the name-matching heuristic the table was first built
      with. *That heuristic had measurable false positives: pan-fw-111's certificate is named
      after its host and matched `deviceconfig/system/hostname`.* Record it in `confirmed_by`
      and `confirmed_vxpath`; the how-to is in the generator's docstring.

      **An empty completion result is NOT disproof, and this is the part that will mislead you.**
      Completions are eligibility-filtered — *On a reference field, completions are
      ELIGIBILITY-FILTERED*, in phase 1, has what that means and the measurement behind it.
      Here it has one consequence: never downgrade a row because a completion came back empty,
      and never build a reference map by asking "does completing this return the type" — that
      makes a schema fact into an inventory fact.


## 3. Assess it — the control


### What the control asserts

- [ ] **Assert the PREFERRED value, not the minimum — one check, at the stricter number.**
      `→ control-changes.json` Where the corpus names both, the control fires below the preferred
      and the finding carries the control's own severity. Do NOT build a graded band between the
      minimum and the preferred, and do not assert the minimum and leave the preferred unasserted.
      *Jason, 2026-09-14: "Let's simplify the class by setting the preferred as the only control
      check. There's no alternative... the preferred should replace the minimum. I'll let the
      consultant reduce severity based on risk." Five controls had shipped asserting only the
      minimum while the corpus also named a preferred and a `preferred_gap_severity` —
      PAN-AUTH-008, 009, 010, 011 and 015 — so a device sitting between the two reported nothing.
      The same shape was open in PAN-MCR-001 and 003.* It is the same principle as *Do not lower a
      corpus severity*,
      at the other end: report the stricter reading and leave the relaxation to the only person
      holding the context. **`preferred_gap_severity` is therefore not something to implement** —
      a band it grades cannot exist once the preferred is the threshold.
      **The sentinel and direction rules still apply.** A preferred value that is NUMERICALLY
      LOWER than the minimum (PAN-AUTH-010: minimum 90 days, preferred 60) still needs both ends,
      and a sentinel keeps its own meaning (PAN-AUTH-015: 0 is locked until an administrator
      releases, which is stronger than any duration and must not fire).

- [ ] **Check whether the assertion is broader than the control's title.** `→ control-changes.json` A control named
      for one subject often asserts something true of several. *PAN-MGT-001/002/003 were
      written for the management interface and apply to every administrative surface.*

- [ ] **Check the control's own TITLE against what the query actually asserts.** A reference
      being present is not the property the title names, and the gap is invisible while every
      subject happens to agree. *PAN-AUTH-019, "External Authentication for Administrator
      Accounts", tested only whether an authentication profile was BOUND. It never read the
      profile's METHOD, and three of the four lab accounts passing it were reaching the
      firewall's own local user database through one - `local-database` and `none` are methods
      too. Nothing failed; the control simply answered a different question under its own name,
      and it took Jason reading the description to see it.*

- **Do not lower a corpus severity because you can only measure part of the failure.**
      `→ control-changes.json` Severity travels ONE WAY in practice: an assessor who sees the
      finding can downgrade it with the context you do not have, and nobody re-reads an
      understated finding to raise it. Report what the corpus says and say plainly, in the
      description, which half was measured. *PAN-AUTH-021 is `critical` for "default account WITH
      the default password"; `phash` is a hash, so only the account's existence is visible. It
      shipped at `high` on that reasoning and Jason reversed it the same day — "the consultant
      can then do the work to reduce the severity if it meets minimum control language. We can't
      account for that." The lowering was defensible and still wrong, because it moved a
      judgement out of the hands of the only person holding the facts.*
      **A corpus field can be an artefact of how the corpus was built.** Where
      `minimum_value_descr` and `preferred_value_descr` split one assertion into two, read them
      together rather than treating the split as a finding about the control.

- **A `posture` or `architecture-review` control usually cannot be decided from config.**
      Enumerate and let the assessor filter, rather than guessing. *006 asks whether a zone is
      "untrusted", which no zone name states.*
      **Some cannot be decided at all, and the honest move is not to build them.** Ask what the
      assertion compares. If one side of the comparison is intent — what a role's holder needs,
      what an account is for — the config holds one side and no query completes it. Enumerating
      is right where the assessor can finish the judgement from the rows; where they cannot,
      a control that fires on everything is worse than none. *PAN-AUTH-023 asks for
      "least-privilege custom admin roles". The roles and their assignments are readable; the
      fit between a role and its holder is not. Built literally it would fire on every account
      not holding a custom role — 20 of 21 on the lab, most of them legitimately. Deferred, with
      the decidable neighbour named: whether a defined custom role is assigned to nobody.*
      **Check whether the narrow reading is decidable before assuming it is.** *"Is this role
      over-broad" sounds like a query. A role entry records only the features explicitly SET —
      the lab's role stores three — so breadth needs the implicit value of every webui, restapi
      and xmlapi feature PAN-OS has. Hundreds of enumerations for one control.*

- **A control that cannot be decided from config is FINISHED when it becomes an INTERVIEW
      QUESTION — not deferred, and not outstanding.** `→ control-changes.json` Write the question
      the consultant will ask, record it beside the reason the configuration cannot answer it, and
      count the control complete. *Jason, 2026-09-14, on PAN-AUTH-020: "This is not a config check,
      it needs to be handled via interview. Let's mark 020 as complete." `build_controls_csv` counts
      `interview` as complete for that reason, and the same ruling completed PAN-AAA-003, PAN-AAA-007
      and PAN-AUTH-023 — four controls that had been reading as unfinished work for weeks.*
      **`deferred` and `decided` still mean outstanding.** A control waiting on a model, an oracle
      or a ruling is not finished; one whose answer lives in a person is.
      **A control BUILT before the discovery stays in the catalogue, inactive**, so the question and
      the reason travel with it and it generates no findings by design. One never built needs no seed
      entry at all. *PAN-AUTH-020 is in seed.json with `is_active` false, carrying its interview text
      in the description; PAN-AAA-003, PAN-AAA-007 and PAN-AUTH-023 are in neither the seed nor the
      database.*

- **A corpus `preferred_value` can be an artefact of the field existing, not a control.**
      `→ control-changes.json` Check whether the preferred value is a distinguishable
      configuration state before building a check for it. *PAN-AUTH-020's
      `preferred_value_descr` asks for "a phishing-resistant factor (FIDO2/certificate) rather
      than push or OTP". The device records a vendor type and a server, not a factor modality,
      so nothing in the config distinguishes them. Jason: "Skip the FIDO2/certificate check on
      this one. This is another case of *_values being filled in because they exist in the
      schema."*


### Writing the query

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

- [ ] **Check what the control's field does when the key is ABSENT, before trusting the
      finding count.** Three different absences reach a column as a stored value:
      `pan_os_default` (the vendor's, measured), `assumed_default` (ours), and `not_configured`
      (null, because guessing would be worse). A control resting on the second is resting on
      something nobody checked; one resting on the third has to handle a null.
      *PAN-POL-009 asserts `log-end`, whose default the corpus records as unmeasured. The rule
      normalizer stores NULL for it rather than False — and a change that turned that null into
      False passed the entire suite, because nothing covered it. Read `provenance_for(field)` on
      a real subject and see which of the three you are standing on.*

- [ ] **Watch the breadth of what fires.** *006 firing on any enabled service would flag every
      interface with `ping` on. It fires on the five administrative services only.*

- **Following a reference to read a property of the target belongs in NORMALIZATION.**
      The search layer compares a field to a literal and cannot traverse an edge, so a control
      needing "the method of the profile this account points at" gets a resolved column, not a
      join. *`centrally_authenticated` reads three keys on the account AND the method of a row
      on another model. Same reasoning as `weakens_global_expiration`, which compares two fields
      the search layer could not compare either.*

- **A classifier that collapses many values into a verdict must be right at the
      boundary.** Find the value that looks like one class and behaves like another, and check
      both directions — over-correcting is as wrong as the original. *A list containing only
      `0.0.0.0/0` was reported Restricted. The fix then reported `[0.0.0.0/0, jump host]` as
      undetermined everywhere, a false positive on a hardened device, and contradicted a
      measurement already in the corpus.*

- **A compiler must be able to SERVE every operator it advertises.** `FIELD_OPERATOR_REGISTRY`
      is a promise, and until something rendered it to a person nothing checked it was kept.
      *Two compilers took the text operator set from `scalar_text` without taking its behaviour:
      `is_empty` is the one operator whose valid value is the EMPTY string, and both rejected it
      with "search value must be a non-empty string". Invisible for as long as the only consumer
      was a hand-written control query. The moment the configuration query builder rendered the
      registry into a dropdown, it offered an operator that could only ever error.*

- **`is_empty` over a field read THROUGH a foreign key must include the missing row.** A
      join to nothing is NULL, and `fk__field=""` does not match NULL - so a query asking "is
      this empty" quietly excludes the rows where there is nothing at all, which is usually the
      case the clause was written for. *`ManagementTlsBinding` reads its protocol floor through
      the SslTlsServiceProfile row. PAN-MGT-010's fourth clause - bound, with an empty floor -
      exists to catch a binding that resolves to no profile, and with a plain lookup it matched
      only profiles that exist and are silent. Removing the null branch fails four tests;
      nothing else would have noticed.*


### Severity

- [ ] **Transcribing thresholds is where they get fat-fingered — diff, do not read.** Compute
      what every value in the field's domain reports before and after, and refuse the change
      unless the two are identical. *`OptivEdgeProbe/scratch/convert_severity_scales.py` will
      not write unless the diff is empty. It caught the SAML widening on its first run.*

- **Severity comes from QUERIES. There is one mechanism and this is it.**
      A control has ONE baseline query saying what fires, and `default_severity` on the control
      is the severity a finding reports when only that matched. A non-baseline query carrying
      `adjusted_severity` states a severity for a specific condition; when several match, the
      WORST wins, and it overrides the baseline tier in either direction — including downward,
      which is how an assessor relaxes a finding in the field. Worst-wins is deliberate: a query
      for critical assets must keep its severity on the objects a later, broader query also
      matches, so a relaxing query only takes effect where nothing more severe matches.
      A second mechanism — declarative `severity_scale` bands on the control — existed until
      2026-09-09 and was removed. *It was seed-only, reachable from no form, capped so it could
      never escalate, and produced every severity defect this project had: a null band on a
      firing value reporting at the default, a query threshold disagreeing with its bands, a
      measure field of the wrong type, and the bands silently outranking an operator query. Ten
      controls' bands converted to eight operator queries with a zero behaviour diff — most
      bands turned out to equal the default and needed no query at all.*

- **A non-baseline query MUST carry a severity.** Without one it matches, contributes
      nothing, and leaves the finding at the default — indistinguishable from the query not
      existing. A baseline query must NOT carry one; `ControlQuery.clean()` and the catalog
      schema both refuse it, because the baseline tier's severity lives on the control.

- **A severity query fires ON ITS OWN, so it must carry whatever the baseline was
      carrying.** A band only ever refined the severity of something already firing; a query
      widens the control unless it repeats the baseline's other conditions. *Converting
      PAN-AUTH-018 emitted `attempts 4 to 5 → low` without the baseline's `method != saml-idp`
      exclusion, and SAML profiles that had never fired started reporting. The before/after diff
      caught it; nothing else would have.*

- **The corpus still carries `severity_scale` on 16 UNBUILT controls. Convert it; do not
      look for something that reads it.** One non-baseline query per band whose severity differs
      from the control's default, each repeating whatever else the baseline requires, plus a
      separate `eq` query for every sentinel. Bands equal to the default need no query — the
      baseline already reports it. *Nine of the twenty-five converted this way produced eight
      queries between them, because most bands were the default.* The corpus field note says the
      same thing, so the two cannot drift.

- **A sentinel is not a low value, it is a different meaning — so it needs its own
      query.** `failed-attempts 0` means lockout is OFF and `idle-timeout 0` means sessions
      never expire; both sort as the gentlest value on any numeric comparison and are the worst
      possible settings. A range query cannot express that, so write `eq 0` separately and give
      it the severity the meaning deserves. Check `notes` for an overloaded zero before writing
      any of it. *PAN-AUTH-015 runs the other way: its 0 means locked until an administrator
      intervenes, which is stricter than any duration, so flagging it would report the most
      restrictive setting as a weakness.*

- **A control being `done` does not mean its THRESHOLDS have been tested.** `status: done`
      says the control works; `query_values_tested` in `controls-status.csv` says every
      threshold in its queries has had a real subject. *A control can be done with one of four
      severity thresholds ever having fired. All 40 built controls read `no` today, including
      the ten whose values came from the corpus and were converted without ever being subject-
      tested — the conversion proved the new queries reproduce the old bands, which is a
      different claim from the numbers being right.*


### When the control walks a reference

- **An "unused" control is only as good as its list of hiding places, so do not scan BY
      PATH.** Walk the whole payload for the referring key and keep the enumerated path list as
      a CROSS-CHECK on what the walk finds. A path the enumeration missed makes the control
      report an in-use object as unused — the worst direction for a hygiene control to fail in,
      because the remediation is deletion. *PAN-AUTH-025: the CLI grammar named eight referrer
      paths and only one was populated on the lab, so seven were "absent" — and absent-because-
      unconfigured is indistinguishable from absent-because-the-payload-does-not-carry-it. Two
      were created for their SHAPE rather than their realism, which brought the confirmed-readable
      set to all four structural shapes: a container of entries, a device leaf, a vsys leaf, and
      a leaf nested inside a vsys entry.*
      **And a referring key can hold a MEMBER LIST, under a key you have not seen.** Twice now
      a walk matched only leaves: MFA factors are `multi-factor-auth/factors/member` and a
      sequence's profiles are `authentication-profiles/member`, and both references vanished
      silently — an in-use MFA server profile and every profile used through a sequence reported
      unused. The cross-check that found both was searching the payload for the object NAMES and
      listing every path whose value is one; run it whenever a referrer key set changes.

- **A reference from inside a scope resolves within that scope first.** Attributing it to
      the wrong definition is two errors at once — the real object reports unused and the orphan
      reports in use. *The path builder read `@name` off the parent instead of the entry, so
      entry names never reached the path and the vsys was never found: every vsys-scoped
      reference was attributed to the SHARED profile of that name. Invisible on a lab where all
      nine profiles are shared, and found by reading the rendered paths rather than by a test.*


### When you add a member to an enum

- [ ] **Adding a member to an enum? Check every map keyed by that enum.** Nothing enforces
      the pairing, and the failure is silent. *`interface_management_profile` was added to
      `ControlType` and not to `_CONTROL_TYPE_TARGET_MODEL`, so `target_model` was wiped on
      every save and the catalog reported permanent drift against itself. There is now a test
      asserting the maps stay in step.*


## 4. Present it


> **Make the control fire before building any of this.** *Making the control fire*, in phase 5,
> is cheap and tells you whether there is a row to render at all — a control that returns zero
> findings leaves a tab correct and empty, which looks identical to one that is broken. A
> pointer rather than a move: the subject it needs is hardware work and belongs with the rest
> of phase 5. *PAN-COV-001 and 002 had their tab, their domain and their workbook sheet built
> before anyone checked, and both returned nothing — not because they were broken but because
> the lab held no instance of either condition.*

### Where a finding appears

- [ ] **A new finding model is invisible to the Findings pages.** That page enumerates one
      finding model by name — `RuleFinding` — out of the twenty-three in
      `finding_registry.FINDING_KINDS`. Do not wire yours in; the surface is
      pending replacement. Add it to the list in `AGENTS.md` under *Surfaces pending replacement*
      so the gap stays counted. *Five finding models drifted out without one test failing, taking
      the whole certificates domain out of the client deliverable that then had to be deleted.*

- **One object, one row — every control that assesses it reports there.** Where several
      controls share a subject, the tab presents the OBJECT and all of its findings together,
      rather than one row per control or a tab per control. An engineer fixes the object, not
      the control, and needs to see everything wrong with it in one place. *An SSL/TLS service
      profile is assessed by PAN-CRT-005 for its protocol floor and PAN-CRT-009 for its
      algorithms, and they fail independently — `oep-tls-legacy` reports both, while
      `oep-mgmt-tls-hardened` passes the floor and fails the algorithms. Two rows for that
      first profile would imply two problems where there is one object to remediate.*
      This is why the finding models carry `subject_name` and `subject_scope`: the object is
      the key the presentation groups by, and a name alone is not unique on a device.

- **A new subject gets its OWN TAB, not columns on Device Configuration.** That table is
      being retired precisely because it accumulated a column group per finding type and every
      new control widened it; object- and control-specific tabs replace it as they come up. Put
      the subject and its controls on one tab, and show controls that fail independently side
      by side so the rows where they disagree are visible. *PAN-MGT-010 was first built as a
      three-column group on Device Configuration, which the LoginBannerListView docstring
      already explained not to do. It became the Management TLS tab, which is also what made
      the 010-passes / 014-fails row legible on a single line.*
      **A tab also picks a SECTION, and the rule is in `navigation.py`, not here.** Key on the
      config subtree; key on the QUESTION instead when one spans several subtrees; fall through
      to Device. Adding the tuple entry is the whole job — the bar, the sidebar highlight and
      four tests all derive from it. *The Device section reached eleven tabs before
      Authentication was split out of it, and six of the eleven were the authentication story,
      spread across `deviceconfig`, `mgt-config` and `shared`. Keying strictly on the subtree is
      what scattered them.*


### Building the tab

- [ ] **Subclass `DeviceTabListView`; declare, do not re-implement.** `subject_model`,
      `finding_model`, `finding_subject_field`, orderings, and a `build_row`. **If your finding
      model is shared with another tab, `finding_controls` is mandatory** - empty means every
      control of that model, so the four DeviceConfigurationProfile tabs would show each
      other's findings. *Removing it from Master Key broke no test until a test was written
      for exactly that; the page simply filled with fifty findings from three other tabs.*

- [ ] **Extend `device_tab_base.html` and declare `COLUMNS` on the view.** The page supplies a
      description, its columns and its rows; the nav, toolbar, toggles, empty state and header
      come from the base. *Eight templates re-typed the whole scaffold, and one `<th>` class
      string appeared 38 times.* The two grouped-header pages keep their own headers on
      purpose - see `tables.py` for why.

- [ ] **Use the shared machinery; do not copy a neighbouring module.** A finding model
      subclasses `FindingBase` or `ObjectFindingBase` (declaring only its own FK, `through`,
      index and constraint); a generator supplies a subject sentence and an `ObjectFindingSpec`
      and calls `generate_object_findings`; a new finding model is registered in
      `finding_registry.FINDING_KINDS`. *Five generators were 111 of 122 lines identical, and
      seven finding models carried the same thirty lines each - copying is also what let five
      of them drift out of the report unnoticed.*

- **The table stays square automatically now** - `test_device_tab_tables_are_square` renders
      every tab and checks each body row against its header. *Removing two model fields left the
      headers declaring columns the body no longer rendered, shifting everything after them; it
      was found by reading. Do not re-add a manual check, and do not let the test go vacuous:
      it creates a row on every tab, because an empty database renders no table at all.*


### What the row must show

- [ ] **Show only the provenance you actually have.** Values resolved from an object elsewhere
      in the tree carry no `@ptpl` of their own, so a provenance line under them is an
      invention. *On the Management TLS tab only the BINDING has provenance; the profile's
      protocol range and certificate are read from the profile object and deliberately show
      none.*

- [ ] **Blank cells are ambiguous.** Say "any source", "Nothing", not nothing at all.

- [ ] **Empty-state text must name the right action.** *Both tabs said "run a sync"; both
      needed only a renormalize, which contacts no device.*

- **A column that colours one direction must be re-read when a control fires the other
      way.** Emphasis in a table is an assertion, and it goes stale silently: nothing fails,
      the cell simply argues against the finding beside it. *The MFA column ambered "off" and
      left a factor count plain, which was right while every control wanted MFA on. PAN-AAA-011
      fires on MFA being PRESENT — vendor-API factors are not invoked for administrator login —
      so the most reassuring cell on the row was the finding, and the amber was on the rows with
      nothing to report.*

- **If the scoping clause is DERIVED, the tab must show it.** A control that fires on some
      rows and not others must let the row explain which it is. When the deciding property is
      computed rather than displayed — a reference walk, a resolved binding, a cohort size — the
      table has to carry it as its own column or sub-line, or identical-looking rows report
      differently and the tab reads as broken. *PAN-AAA-010 fires on `all` only for profiles an
      administrator authenticates through. All nine lab profiles show `all`; five report and four
      do not, and nothing in the rendered row said why until `is_administrative` became an
      "administrator-bound" marker under the allow-list cell.*


### Things that only break at render

- **A broken template comment is not an error, it is CONTENT.** `{# ... #}` is single-line
      only; spread over two lines Django stops treating it as a comment and prints it. *A note
      to the next developer became a paragraph of grey text in the middle of the configuration
      rail, twice — once per loop iteration. Every test passed, the page returned 200, and Jason
      caught it by looking at the screen. `test_no_template_comment_spans_a_line` now checks the
      template files; use `{% comment %}` for anything that does not fit on one line.*

- **Anything referenced by name is unvalidated until render.** Icons, template includes,
      URL names. *A lucide icon that does not exist reads an SVG off disk and 500s, failing
      ten unrelated view tests at once.* **For icons, list the directory first** — the set is
      not lucide's, it is the ~17 SVGs vendored at
      `OptivEdge/src/optivedge/templates/components/icons/`. *Picked from memory three times
      now — `lock`, `layers`, then `key-round` and `git-branch` in one commit. Reusing an icon
      another tab already uses is fine and normal here; inventing a plausible name is not.*


## 5. Prove it — against hardware, not fixtures


> **Half of this phase runs during phase 1, and that is not a defect.** Designing an experiment
> that can fail, trusting an instrument, and writing or deleting lab config are how a
> measurement gets taken — so they happen while the configuration is being understood, not
> after the control exists. The phase-1 note about measuring in parallel says the same thing
> from the other side: a failing subject set up to measure a shape is the subject the control
> needs left behind, so it is never created twice.
>
> What genuinely belongs here, after the control exists, is **Making the control fire** and
> **What to leave behind**. Read those two when the control is built; read the rest when you
> are still measuring.

### Designing an experiment that can fail

- [ ] **A setting present in the config is not a setting in FORCE. Prove the mechanism is live
      in the same run, with an attempt that MUST go through it.** Otherwise an observation is
      consistent with two different worlds — the mechanism declining to act, and the mechanism
      not being active at all — and they are indistinguishable. *A device-wide authentication
      binding was pushed at a dead server, and a login with a stored password succeeded. That was
      written up as "the binding does not displace a stored password"; it equally supported "the
      binding was inert". Jason asked whether the difference had been tested directly. It had
      not. Adding an account with NO credential — which cannot authenticate any other way, so
      the binding must be consulted for it — produced the timeout entry naming the profile two
      seconds before the other account authenticated locally. Same binding, same run, one state
      that had to come back different.* `@ptpl` in the merged config proves it was pushed, not
      that it is doing anything.

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

- [ ] **How long a failure took is evidence, and it is usually free to record.** Two mechanisms
      that produce the same outcome often cannot produce the same LATENCY. *Whether a bound
      authentication profile falls back to a stored password could not be settled by the outcome
      - a refusal is a refusal. It is settled by the clock: a local check answers in 0.2-0.4s and
      an attempt that waits out a dead RADIUS server takes 5.3-6.9s. The refusal took 6.89s, so
      the device waited out the timeout and declined rather than spending another 0.2s on the
      password it had just been proved to hold. Both measure scripts now record elapsed time on
      every attempt.*

- [ ] **A failed login, a refused connection, a timeout — ask the DEVICE why before reading the
      outcome.** A negative outcome has many causes and they are indistinguishable from the
      client side; the device usually logged which one. *PAN-AUTH-019 turned on whether a bound
      authentication profile displaces a stored password. The login failed, which alone proves
      only that the login failed — the account might have been wrong, the role might not permit
      the web interface, the password might have been mistyped. The system log, subtype `auth`,
      said "Reason: Authentication request is timed out. auth profile 'oep-auth-deadend' ...
      server address '192.0.2.1'", which names the path taken AND shows only one attempt. The
      same log reads "Invalid username/password" elsewhere, so the reasons are distinguishable
      and the line is its own negative control — though only once *A log reason can be TRUE and
      still not discriminate* has been satisfied.* **`type=log` must go DIRECT to the device** — Panorama accepts `target=` on a
      log query, ignores it, and answers from its own database. **An event whose cause is a
      TIMEOUT is logged when the timeout expires, after the API call has already returned**, so
      a log query fired immediately shows every other case and not the one under test.

- **The control has to be the SAME SUBJECT with one variable moved, not a neighbouring
      subject that behaves.** Other objects behaving sensibly prove the instrument works; they
      say nothing about what THIS one would have done. Vary the thing under test on the thing
      under test, and the OUTCOME then carries the result without any inference from logs.
      *Whether a bound authentication profile displaces a stored password took three attempts.
      The first was a person's typed login, whose password turned out to carry a trailing
      character. The second fixed the password and used two OTHER accounts as controls — one
      authenticating, one refused on a deliberate typo — and concluded from an absent second log
      entry that nothing fell back. Jason: "If I pasted the correct password, it might have tried
      local authentication after radius timed out." He was right, and no amount of evidence about
      other accounts answers it. What settled it was unbinding the profile from THAT account,
      authenticating, binding it back, and failing with the same password a minute later. The
      conclusion never changed across all three; the evidence was inadmissible twice.*

- **A log reason can be TRUE and still not discriminate the thing you are testing.** Ask
      whether the failure you are worried about and the failure you are testing for produce
      DIFFERENT lines. *"Authentication request is timed out. auth profile 'oep-auth-deadend'"
      was read as proof the profile took precedence. It is not: a wrong password produces the
      identical line, because the request goes to RADIUS either way. What made it readable was a
      second attempt in the same run — wrong password, no profile bound — logging "Invalid
      username/password" with no profile clause. Only once a local check is known to be logged,
      and logged DIFFERENTLY, does an absent second entry mean "no fallback was attempted"
      rather than "nothing was logged".*


### Instruments and credentials

- [ ] **A person typing a credential is an uncontrolled input. Have the INSTRUMENT
      authenticate instead.** Where an authentication attempt can be made programmatically —
      PAN-OS: `type=keygen` — the password is exactly what you set, and the run is repeatable.
      Ask a person only for what no API can do. *A precedence result rested on one failed login
      typed by a person. Jason then found his console copy appended a trailing period to the
      password, so what had been sent was unknown; the result was withdrawn. Retaken over
      keygen — the instrument setting the passwords itself and retiring them afterwards — it
      ran in one command, produced its own controls, and reproduced twice.*

- [ ] **An instrument that tidies up after itself will tidy up state someone else is standing
      on.** Anything handed to a person - a credential, a lab subject, a pushed binding - is now
      shared state, and a later run of your own tool is the most likely thing to destroy it.
      Verify the handoff still works immediately before handing it over, and say so. *Two
      accounts were armed with a password for a human web-login test. The measurement script was
      then run again for an unrelated timing question, and its cleanup step retired both
      credentials twenty minutes before the person tried them. The device answered "Invalid
      username/password", which read as the POSITIVE CONTROL FAILING - the most alarming possible
      result - and was the tool tidying up underneath. The script now has an `arm` mode that sets
      the passwords and stops.*

- [ ] **A credential created for an experiment must not outlive it.** Replace it with a hash of
      nothing once the measurement is taken, and keep the account if it is a subject. *A
      profile-bound account's password is unusable only while the profile is bound, and profiles
      get removed.*

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


### Trusting a verification tool

- [ ] **Run the census** — `OptivEdgeProbe/scratch/lab_findings_census.py` — and check no
      implemented control comes back empty. An empty one is either a control that needs a
      subject or a control that does not work, and the census does not tell you which; that is
      the point of asking before you believe it is done.

- **A count is meaningless without the environment that produced it.** Two databases
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
      reading to confirm rather than to learn. Same posture as *A count is meaningless without the
      environment that produced it*.*

- **A verification tool must not fail in the direction of its own answer.** The census
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


### When you write or delete lab config

- **A refused call is classified by MEASUREMENT, not by the vendor's error-code table.**
  `classify-an-api-failure.md` in the OptivEdgeIntegrations guides holds the measured
  behaviour; reach for it before reading anything into a code. *The vendor publishes a table,
  and five of its meanings were checked against a live device: four disagreed. An unknown
  command returns `17` where the table says `1`, a malformed xpath returns `7` — with
  `status="success"` — where it says `6`, and deleting a nonexistent node returns `7` where it
  says `13`. The table is a reliable guide to the code SPACE and an unreliable one to any
  device's behaviour, so use it to know a code exists and measurement to know what it means.*
  Two consequences that catch people: on reads the outcome is `code`, not `status`, and `19`
  means data was returned; and one code spans unrelated causes, so the code narrows the search
  and the message text discriminates.

- [ ] **An abandoned experiment can leave the candidate config INVALID, which blocks every
      later commit on that device — including someone else's.** A failed commit does not roll
      the candidate back. Before moving on, delete what you wrote and commit clean, and say so.
      *Three failed commits on fw-core-tpa-b left an MFA server profile the device would not
      accept; anything else committed there would have failed with an error naming an object
      nobody else had touched. This is the third instance — a certificate-profile missing 'CA'
      and an SSL/TLS profile missing `certificate` did the same.*

- [ ] **A template change is undone on EVERY device the stack serves, not the one you tested
      on.** A push scoped to one serial arms one device; any later push of that stack — yours,
      the operator's, another session's — carries the live template to the rest. So the revert
      pushes to every member and re-reads each, rather than trusting the device it armed. *The
      device-wide RADIUS test was armed and reverted on fw-core-tpa-b only. The next day
      fw-core-tpa-a was found still carrying both device-wide leaves at the live RADIUS server —
      a push made while the template was live had reached it, and nothing had looked.*

- **A `set` on a member list APPENDS. It does not replace.** Re-pointing a reference means
      deleting the old member, not writing the new one. *Re-pointing an MFA factor at a second
      server profile left BOTH members, so the delete of the first was refused for a reference
      that was believed already gone — and the refusal message named the referrer correctly, so
      the tool was right and the mental model was wrong. `delete .../member[text()='<name>']`
      removes one member.* *DELETE returns a node to its implicit state* says re-pointing the referrer earlier in the same
      commit clears a refusal; this is what "re-pointing" has to actually do.

- **A commit that names one invalid object is not evidence the others are good.**
      Validation reports the first failure and stops. *Two MFA server profiles were built to
      compare vendors; the commit named only the first. Deleting it made the commit name the
      second — which had been read as "the Duo one passed".*

- **DELETE returns a node to its implicit state**, which is how scaffolding comes out when
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

- **On a central manager, "pending changes" can mean UNPUSHED, not staged.** A pre-write
      guard that reads it as "somebody is mid-edit" waits for a state that never arrives.
      *Measured 2026-09-14: Panorama answers `check pending-changes` with `yes` and
      `location: device-group` while a commit replies "There are no changes to commit". Its own
      candidate was clean; what was outstanding was device-group policy committed but not pushed
      to the firewalls. A day of caution was spent refusing to commit staged work that did not
      exist.* On a FIREWALL the flag means what everyone assumes. So read `location` — and
      remember that clearing it means PUSHING, which reaches devices and carries whatever anyone
      else has committed into those device groups, so it is never the tidy-up it looks like.

- **A commit refusal usually names a missing PREREQUISITE, not an unavailable feature —
      and an empty completion set on a reference field often just means nobody has built the
      thing it points at yet.** Read the refusal as a shopping list and build up the chain.
      *PAN-AUTH-020 had no passing subject: `mfa-enable` needs a factor, a factor needs an
      `mfa-server-profile`, and that would not commit — "Invalid MFA vendor config" — with every
      key `action=complete` offered under `mfa-config` populated. `mfa-cert-profile` completed to
      NOTHING, which was read as "no eligible certificate profile on this device" and written up
      as a gap that could not be closed. The device had six certificates and zero certificate
      profiles: creating one made the same MFA profile commit first try. The completion was
      empty because the OBJECT TYPE was absent, not because the reference was unsatisfiable, and
      an empty completion set is never disproof — *On a reference field, completions are
      ELIGIBILITY-FILTERED*, in phase 1, says exactly that.*

- **A support object built only to satisfy validation may be inoperative, and should be.**
      *Jason, 2026-09-08: "We can build fake server and authentication profiles that are
      inoperative just for config validation." The MFA server profile points at a Duo tenant
      that does not exist and the RADIUS profile at 192.0.2.1. Both controls read configuration
      and neither authenticates, so a working back end would prove nothing extra and would be a
      real credential in a lab.*

### Making the control fire

- [ ] **Make the control fire.** A control that returns zero findings has proven nothing.
      Configure the condition on the lab and watch it fire on the right subject. *001 and 002
      both returned zero against the lab as it stood.* **Set the passing and failing subjects
      in the same commit** — see *Measure in parallel, not in series* at the top of phase 1 — and prefer subjects the
      discovery phase already created.

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

- [ ] **Exercise every axis the control spans**, not just the one that was convenient.
      *PAN-OS: both service polarities, both management planes, both HA peers — the two planes
      spell the same setting with opposite sense, so a control tested on one is untested on
      the other.*

- [ ] **Run the real pipeline, not the fixtures.** *Fixtures passed while real config broke
      four separate ways: empty `<units/>`, empty container, subinterface type discrimination,
      and a warning on every unconfigured port.*


### What to leave behind

- [ ] **LEAVE the condition in place.** `→ reproductions.json` Every implemented control should have at least one
      live finding in the lab, permanently. A control with no subject cannot be demonstrated,
      cannot be checked after a refactor, and its UI has nothing to render. *PAN-MGT-009
      reported nothing for a correct reason — `server-verification` absent means enabled — so
      it was turned off on the passive HA member and deliberately not reverted.*

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

- [ ] **Name what is still fixture-only.** `→ the vendor guide's Limits` *`layer2`, `tap`, `virtual-wire`, `ha`,
      `dhcp-client`, `pppoe`, IPv6 addressing and `sdwan` have never been seen on hardware.*

- [ ] **Revert the SCAFFOLDING, keep the SUBJECT.** `→ reproductions.json` Two different kinds of lab change:
      config written to measure a shape or a default is scaffolding and comes out; config that
      is the thing a control detects stays. Say plainly which is which. *Template pushes used
      to read provenance markers were reverted; the unused profiles and the disabled
      update-server verification were not, because PAN-MGT-013 and PAN-MGT-009 need them.*


## 6. Land it


### Re-read what you assumed

> Not new checks - earlier ones re-run against what actually shipped. By now phase 0 and phase 1
> are a long way behind, and the most recent thing you did reads as the most authoritative.

- [ ] **Re-read the control's description against its FINAL query.** *Check the control's own
      TITLE against what the query actually asserts* runs in phase 3, before severity queries
      and clause refinements land. The gap it names is invisible while every subject happens to
      agree, and the one instance of it was caught by a person reading the description.
- [ ] **Re-read the payload contract entry you started from.** `→ payload contract` Phase 0
      sends you to it and nothing sends you back. A build routinely establishes something the
      entry should now carry, and the discovery log records NEW facts rather than corrections
      to the entry you relied on.
- [ ] **Re-check which `Implicit` the control's fields rest on**, with `provenance_for(field)`
      on the subject you now have, which is the real one rather than the one you reasoned about.
      14 of the 33 defaulted sites are still `assumed`, so a control can rest on one without
      anyone having decided that it should.


### Record it

- [ ] **Read the rules before editing a lookup table, and validate it after.** The payload
      contract and the CLI index are believed by everything downstream, and nothing fails when
      one of them is wrong. They have DIFFERENT rules and both are in `reference/README.md`:
      the boxed block governs `cli-commands.jsonl` and every claim in it must be traceable to
      something that happened; the payload contract is governed by its own `scope` block —
      deliberately partial, entries earn their place by being CONSUMED, and a missing node
      means nobody needed it rather than that there is a gap. Run
      `python -m probe.validate_cli_index` after touching the index. *The boxed rules exist
      because knowledge in that file decayed three times in a single day — a guess hardened
      into a fact once nobody remembered it was a guess, a claim lost its provenance, and a gap
      looked like an oversight.* The hooks re-run the validator, but they are a REMINDER rather
      than a gate: they do nothing in a clone that has not run
      `git config core.hooksPath .githooks`, and `--no-verify` skips them.

- [ ] **Record the reproduction** `→ reproductions.json` — the actual API calls that give
      this control a subject, written from the strings the script used rather than
      reconstructed later. Note `subject_kind`: a control whose subject is an UNTOUCHED default
      has no call, and writing the default explicitly would not reproduce it.

- [ ] **Update `scratch/control-changes.json`.** Move `status` from `decided` to
      `implemented`, record what was built and what verified it, and add any deviation
      decided along the way. The file is only worth having if it still matches what shipped —
      a stale entry is worse than none, because it will be trusted.

- [ ] **Empty `scratch/in-flight.json`.** Run `python -m scratch.check_in_flight`: every fact
      it holds should have graduated to its durable home, and its entry deleted. A non-empty
      file is a to-do list, and anything left in it has not landed anywhere that will be read
      again.

- [ ] **Regenerate the status CSV** `→ controls-status.csv` —
      `python -m scratch.build_controls_csv`. It is generated from `controls.json` and
      `control-changes.json`, never edited, so it cannot drift; the only way it goes stale is
      not being run. It is how the state of 228 controls is read without opening the JSON.


### Ship it

- [ ] **Migration** — and check whether an existing environment needs a data migration.

- [ ] **Say what the operator must run**: migrate → renormalize → reseed → regenerate
      findings. Renormalize needs no device connection; a sync does.

### Documentation

- [ ] **Record measurements where the consumer is.** `→ the vendor guide` A vendor fact goes in the
      OptivEdgeIntegrations guides, next to the code that depends on it; the method stays in
      OptivEdgeProbe. A fact that spans subtrees goes at the top level, not under one of them.
      Stage doc changes for review first.

- [ ] **Add a discovery-log entry** `→ discovery log` for anything ambiguous, anything that took more than one
      attempt, and anything that contradicted an expectation.

- [ ] **Audit a staged document against the TRANSCRIPT, not against memory.** Feedback arrives
      across many turns and some of it lands nowhere; recall cannot tell an item you applied from
      one you meant to. The session transcript is on disk — extract every user turn and check the
      document against each one. *Jason compared the draft file timestamps to his own feedback and
      asked whether it had been captured. Reading the transcript found three items from a day
      earlier that had never reached the drafts at all: that the support objects were inoperative
      by design, that a device-wide binding has to be pushed and reverted from Panorama because it
      locks everyone out, and that the control reads CONFIGURATION rather than the behaviour the
      measurements describe. None of them were disputed — they were simply never written down.*

- **A staged document you edited and did not RE-READ may not say what you think.** Patching
      the same file across a dozen turns accumulates duplication and reorders it out of
      coherence, and a find-and-replace that MATCHES NOTHING fails silently — `str.replace`
      returns the string unchanged and no test covers a draft. Assert every replacement landed,
      and read the whole file before handing it over. *A draft was patched all day and reported
      as updated. Jason checked the file timestamps against his own feedback and found it: one
      edit had silently no-opped because the file held an em-dash where the pattern had a
      hyphen, two later rulings had never been applied at all, and a section had been inserted
      twice. Same class as the duplicated checklist line he found earlier — both survived
      because nobody re-read the file after writing it.*
      **Assert the COUNT, not the presence.** `assert old in s` passes when the anchor appears
      twice, and `str.replace` then edits both. *Two list views share their referrer lines
      verbatim, so a comment and two keys meant for the authentication-profile row also landed
      in the server-profile one, and the tab died on `'ServerProfile' object has no attribute
      'is_administrative'`. The test suite caught it, which is luck rather than method: the
      second site had no test, it would have been a 500 on a page.*
      **And for a SLICE between two anchors, assert what the span CONTAINS.** Both anchors being
      present and unique says nothing about what lies between them. *Removing one results spec
      by cutting from its first line to the next spec's first line also removed the five specs
      that sat in between - the anchors were right and the span was not. The suite caught it at
      once; asserting the span held exactly one spec would have stopped it before the write.*
