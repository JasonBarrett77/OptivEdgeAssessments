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

---

## 1. Understand the configuration — before modelling anything

- [ ] **Enumerate the real key set from the device**, rather than from a sample, a document
      or memory. Use whatever the platform offers as a schema oracle. *PAN-OS: `action=complete`.
      The payload contract recorded 6 management services; a firewall accepts 10. Two
      normalizers hard-coded 5 interface containers; a PA-5220 offers 6 and a PA-VM offers 5 —
      and `sdwan`, which neither listed, is on both.*
- [ ] **The key set is platform-dependent.** Check a second platform before treating it as
      fixed. *`vlan` exists on a PA-5220 and not on a PA-VM.*
- [ ] **Establish the implicit value by measurement.** An absent key is not an absent
      setting. *`disable-http` was recorded implicit `no`; it measures `yes`. Two devices with
      different configurations reporting the same effective state is what makes it a default
      rather than one device's coincidence.*
- [ ] **Distinguish absent from empty from default.** Three states, and a config format that
      has all three will use all three. *PAN-OS: an empty `<units/>` and an empty
      `<aggregate-ethernet/>` both parse to `None`, not `{}`.*
- [ ] **Check what the value looks like when it arrives from a central manager**, not only
      when set on the device. The shape usually differs, and not every read exposes the
      difference. *PAN-OS: a template leaf arrives as `{'@ptpl': …, '#text': 'yes'}` and a
      naive reader calls it unset; `action=get` strips `@ptpl` entirely, so only merged config
      carries it.*
- [ ] **Ask which oracle can see it.** Some settings appear in no config read at all. *Four
      management services are invisible to `show system services` and to the running config;
      only the compiled ACL sees them.*
- [ ] **A schema oracle says what MAY be set, never what IS set.** Do not quote one as
      evidence of what a real payload looks like — that needs an instance. *PAN-OS:
      `action=complete`. The `vlan` payload shape was asserted from it and only later
      measured, and it happened to be right.*

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

## 3. Assess it — the control

- [ ] **Use the id from `controls.json`**, and record every deviation in
      `scratch/control-changes.json` with what now covers any dropped ground.
- [ ] **Replace the superseded seed control**, and check whether it splits. *Seed `MGMT-001`
      asserted telnet and http together; `controls.json` has them as two controls.*
- [ ] **Check whether the assertion is broader than the control's title.** A control named
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

- [ ] **Assert the table stays square.** Body cells == header cells; group spans cover every
      column. *Removing two model fields left the headers declaring columns the body no longer
      rendered, shifting everything after them.*
- [ ] **Blank cells are ambiguous.** Say "any source", "Nothing", not nothing at all.
- [ ] **Anything referenced by name is unvalidated until render.** Icons, template includes,
      URL names. *A lucide icon that does not exist reads an SVG off disk and 500s, failing
      ten unrelated view tests at once.*
- [ ] **Empty-state text must name the right action.** *Both tabs said "run a sync"; both
      needed only a renormalize, which contacts no device.*

## 5. Prove it — against hardware, not fixtures

- [ ] **Make the control fire.** A control that returns zero findings has proven nothing.
      Configure the condition on the lab, watch it fire on the right subject, revert. *001 and
      002 both returned zero against the lab as it stood.*
- [ ] **Exercise every axis the control spans**, not just the one that was convenient.
      *PAN-OS: both service polarities, both management planes, both HA peers — the two planes
      spell the same setting with opposite sense, so a control tested on one is untested on
      the other.*
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
- [ ] **Record measurements where the consumer is.** A vendor fact goes in the
      OptivEdgeIntegrations guides, next to the code that depends on it; the method stays in
      OptivEdgeProbe. A fact that spans subtrees goes at the top level, not under one of them.
      Stage doc changes for review first.
- [ ] **Add a discovery-log entry** for anything ambiguous, anything that took more than one
      attempt, and anything that contradicted an expectation.
