# Building a control — the checklist

> Read this before starting a control, and again before calling one done.

Every item here is here because it was **missed once**, on a control someone believed was
finished. None of it is general advice; each line has an incident behind it, and the incident
is named so the item can be argued with rather than obeyed.

**Add to this file whenever a control turns out to need work after it looked done.** That is
the only way it stays worth reading.

---

## 1. Understand the configuration — before modelling anything

- [ ] **Enumerate the real key set from the device**, with `action=complete`, rather than
      from a sample or from memory. *The payload contract recorded 6 management services; a
      firewall accepts 10. Two normalizers hard-coded 5 interface containers; a PA-5220
      offers 6 and a PA-VM offers 5 — and `sdwan`, which neither listed, is on both.*
- [ ] **The key set is platform-dependent.** Check a second platform before treating it as
      fixed. *`vlan` exists on a PA-5220 and not on a PA-VM.*
- [ ] **Establish the implicit value by measurement.** An absent key is not an absent
      setting. *`disable-http` was recorded implicit `no`; it measures `yes`. Two devices with
      different configurations reporting the same effective state is what makes it a default
      rather than one device's coincidence.*
- [ ] **Distinguish absent from empty from default.** They are three states and PAN-OS uses
      all three. *An empty `<units/>` and an empty `<aggregate-ethernet/>` both parse to
      `None`, not `{}`.*
- [ ] **Check what the value looks like when pushed from a template**, not only when set
      locally. *A template leaf arrives as `{'@ptpl': …, '#text': 'yes'}`; a naive reader
      reports it as unset. `action=get` strips `@ptpl` — only merged config carries it.*
- [ ] **Ask which oracle can see it.** Some settings appear in no config read at all. *Four
      management services are invisible to `show system services` and to the running config;
      only the compiled ACL sees them.*
- [ ] **`action=complete` reports the SCHEMA, not an instance.** It says what may be set. Do
      not quote it as evidence of what a real config looks like. *The `vlan` payload shape
      was asserted from `complete` and only later measured.*

## 2. Model it — in OptivEdgeIntegrations

- [ ] **Decide the object root by asking what a finding names.** *"Telnet is enabled" is not
      reportable; "telnet is enabled on ethernet1/1" is. The surface is the object and the
      service is a value on it. An unused profile has no surface, which is why the profile
      needed a model of its own.*
- [ ] **Scope it by the config subtree, not the documentation plane.** `vsys/entry/…` →
      `EnforcementPoint`; everything else → `Appliance`. *`Zone` is a network-plane concept
      that scopes like policy because it lives under `vsys/entry`.*
- [ ] **Populate every appliance, including both HA peers**, unless there is a bridge model
      recording which appliances a row speaks for. *Interfaces were normalized for the active
      member only, which gave the model appliance-anchored identity with group-like
      population — "this peer has no interfaces" became indistinguishable from "this peer was
      never normalized".*
- [ ] **Provenance uses `ProvenancedMixin` and `FieldProvenance`. There is no second
      mechanism.** Read it with the helpers in `normalization/common.py`. *A bespoke
      `provenance = CharField` was built and removed a day later: it could not hold the type,
      could not be queried, and could not tell a PAN-OS default from a local value.*
- [ ] **Search for an existing helper before writing one.** *`common.py` already had
      `scalar_value`, `parse_yes_no_field`, `entry_provenance`, `classify_prov_type` and
      `ABSENT`; a private `_provenance()` was written beside them, checking the wrong key
      set.*
- [ ] **Never skip a payload you cannot parse.** Emit a `NormalizationIssue`. *A list that
      looks complete and is not is worse than an error.*
- [ ] **Report an unknown shape rather than dropping it.** Keep the row, warn, say what was
      unrecognised. *An unfamiliar interface container is still walked, because hard-coding
      the container set is what made `sdwan` invisible.*
- [ ] **Wire it into `flows.py`** — both the collect path and renormalize — with its **own**
      try/except. *One plane of the answer failing must not silently remove another.*

## 3. Assess it — the control

- [ ] **Use the id from `controls.json`**, and record every deviation in
      `scratch/control-changes.json` with what now covers any dropped ground.
- [ ] **Replace the superseded seed control**, and check whether it splits. *Seed `MGMT-001`
      asserted telnet and http together; `controls.json` has them as two controls.*
- [ ] **Check whether the assertion should span planes.** *001/002/003 were written for the
      management interface and apply to every administrative surface.*
- [ ] **A `posture` or `architecture-review` control usually cannot be decided from config.**
      Enumerate and let the assessor filter, rather than guessing. *006 asks whether a zone is
      "untrusted", which no zone name states.*
- [ ] **Watch the breadth of what fires.** *006 firing on any enabled service would flag every
      interface with `ping` on. It fires on the five administrative services only.*
- [ ] **Check every `ControlType` has a `_CONTROL_TYPE_TARGET_MODEL` entry.** *A new type
      without one has `target_model` silently wiped on save, which reads as permanent catalog
      drift.*
- [ ] **A classifier that reports "restricted" must be right about what restricts.** *A list
      containing only `0.0.0.0/0` was reported Restricted. Then the fix reported
      `[0.0.0.0/0, jump host]` as undetermined on every plane, which is a false positive on a
      hardened device.*

## 4. Present it

- [ ] **Assert the table stays square.** Body cells == header cells; group spans cover every
      column. *Removing two model fields left the headers declaring columns the body no longer
      rendered, shifting everything after them.*
- [ ] **Blank cells are ambiguous.** Say "any source", "Nothing", not nothing at all.
- [ ] **Check the icon exists.** *The lucide tag reads an SVG off disk and 500s on a miss.*
- [ ] **Empty-state text must name the right action.** *Both tabs said "run a sync"; both
      needed only a renormalize, which contacts no device.*

## 5. Prove it — against hardware, not fixtures

- [ ] **Make the control fire.** A control that returns zero findings has proven nothing.
      Configure the condition on the lab, watch it fire on the right subject, revert. *001 and
      002 both returned zero against the lab as it stood.*
- [ ] **Exercise both polarities / both planes / both peers**, whichever the control spans.
- [ ] **Run the real pipeline, not the fixtures.** *Fixtures passed while real config broke
      four separate ways: empty `<units/>`, empty container, subinterface type discrimination,
      and a warning on every unconfigured port.*
- [ ] **Name what is still fixture-only.** *`layer2`, `tap`, `virtual-wire`, `ha`,
      `dhcp-client`, `pppoe`, IPv6 addressing and `sdwan` have never been seen on hardware.*
- [ ] **Revert lab changes**, or say plainly which were left and why.

## 6. Land it

- [ ] **Migration** — and check whether an existing environment needs a data migration.
- [ ] **Say what the operator must run**: migrate → renormalize → reseed → regenerate
      findings. Renormalize needs no device connection; a sync does.
- [ ] **Record measurements where the consumer is.** A PAN-OS fact goes in the
      OptivEdgeIntegrations guides; the method stays in OptivEdgeProbe. Stage doc changes for
      review first.
- [ ] **Add a discovery-log entry** for anything ambiguous, anything that took more than one
      attempt, and anything that contradicted an expectation.
