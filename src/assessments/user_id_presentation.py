"""How the User-ID tabs read: the cells whose wording is a judgment.

Written by the stage 9 run of OptivEdgeProbe's `user-id` domain, 2026-11-02, for PAN-UID-001 to
-006 over four models - two created for this domain (the per-vsys collector settings node and the
per-vsys discovery bound) and two inherited, `integrations.Zone` and
`integrations.ManagementInterface`, whose tabs other domains built first.

EVERY HEADING AND EVERY WORD BELOW IS A PROPOSAL. Report content is Jason's and he takes the
heading pass once across many domains rather than per domain (P399), so these are written to be
argued with, and the ones that are not merely cosmetic say why in their own comment.

THIS DOMAIN GETS THREE DIFFERENT ANSWERS TO "SHOULD THIS COLUMN HAVE A `ValueReader`?" and the
three are worth reading together, because the question looks like a wording question and is not:
a reader's real effect is that `tested_fields` returns `stored=False` for the field, so
`build_rows` hands `remediation_accessor` a field it then never reads a `FieldProvenance` row for.

  1. `Zone.enable_user_identification` - A READER IS COMPULSORY, not an improvement. Without one
     the Security Zones tab CANNOT BE BUILT AT ALL for a PAN-UID-001 row. `build_findings_table`'s
     `provenance_of` closure falls back to `field in _model.DERIVED_FIELDS` whenever no stored
     provenance row exists, `DERIVED_FIELDS` is declared only on `ProvenancedMixin`, and
     `integrations.Zone` is a bare `SyncTrackedModel` - so the attribute does not exist and the
     lookup raises `AttributeError`. The three Device-ID columns on that tab already carry readers
     for exactly this reason; `enable_user_identification` is the FOURTH field to reach the tab and
     the first one no reader covered. The cost of the reader is nil, because a zone has no
     `FieldProvenance` row for a reader to discard. Recorded as a defect rather than fixed: the
     model is another repository's and the closure is shared machinery.

  2. `UserIdDiscoveryBound.list_shape` - A READER IS FREE AND IS USED. The field is in that
     model's `DERIVED_FIELDS`, so there is no provenance row to lose, and the shared
     `display_value` cannot say the one thing this column most needs to say. See `list_shape`
     below.

  3. `UserIdCollectorSettings`' six configuration columns - A READER IS REFUSED, and this is the
     deliberate half. That model's `DERIVED_FIELDS` is `("is_missing",)` alone: every one of the
     six is read from a payload key and carries a real `FieldProvenance` row - `pan_os_default`
     for the four measured implicits and `not_configured` for the two that are not assumed. That
     row is the ONLY thing in the report that tells an absent key from a key present and empty,
     which on `wmi_account` is the difference between "nobody configured a principal" and
     "somebody blanked one". A reader would discard it to buy nicer wording, so there is no reader
     on that tab and the shared renderer prints the values. The Provenance column carries the
     distinction instead.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import FieldProvenance

from assessments.artifacts.sheets import findings as findings_sheet
from assessments import device_id_presentation as device_id

#: The label `build_rows` compares a reader's `provenance` against before it will consult the
#: object's own remediation walk. Named rather than repeated: a reader that wants the walk must
#: match this string exactly, and a reader that must NOT walk (case 1 above) must not.
DERIVED = FieldProvenance.ProvenanceType.DERIVED.label

#: What `list_shape` reads when it holds the empty string. NOT a verdict, and the model's own
#: docstring is explicit that the blank is a fifth state which "must never be rendered as a
#: verdict": it is what a row holds between the migration that adds the column and the pass that
#: fills it. It FIRES, because the assertion is written as the passing condition and `` is not
#: `include_present` - so a reader meets this cell on a row that is reporting a finding, and the
#: finding is "we could not establish the bound", not "the bound is absent".
SHAPE_NOT_COMPUTED = "Not computed for this vsys"

#: What `userid_listener_state_established` reads when it is false. THE HEADING CANNOT CARRY THIS
#: AND THE CELL MUST, which is why this is a reader and not a `setting_labels` entry alone. False
#: is the FIRING side and it does not mean the listener is off - it means nothing has measured
#: what an absent key means on this surface. `OEI.USERID_LISTENER_MEASURED_PLANES` is
#: {mgt, dataplane}, so the column is false on EVERY aux plane of EVERY appliance, always, and no
#: customer action can clear it. A bare "No" under any heading a reader could scan quickly reads
#: as "the listener is not established", i.e. as the reassuring answer, which is the exact
#: inversion this stage exists to catch.
LISTENER_NOT_MEASURED = "Not measured on this plane"
LISTENER_MEASURED = "Measured"


def user_identification_enabled(zone) -> str:
    """Whether the zone gathers user identity for traffic classified into it.

    A stored non-null boolean defaulting to false. POSITIVE direction and no inversion: true means
    User-ID is ON for the zone and TRUE is the firing side, so this is a plain Yes/No and the
    wording is not the reason the reader exists. See case 1 in the module docstring: without this
    reader the tab raises `AttributeError` on every PAN-UID-001 row.
    """
    return "Yes" if zone.enable_user_identification else "No"


ZONE_USER_ID_READER = findings_sheet.ValueReader(
    read=user_identification_enabled,
    # NOT the `DERIVED` label, deliberately: matching it is what makes `build_rows` call the
    # remediation walk, and the walk is what raises on a `Zone`. The prose below stands in its
    # place and is the same sentence the other three columns on that tab print, because it is the
    # same truth about the same model.
    provenance=device_id.ZONE_PROVENANCE)


def list_shape(bound) -> str:
    """This vsys's whole discovery list as one verdict, in the model's own words.

    THE BLANK IS WHY THIS READER EXISTS. `display_value` has exactly three answers - a value,
    `(none)` for NULL and `(empty)` for the empty string - and `list_shape` is a non-nullable
    CharField whose empty value means NOT COMPUTED. `(empty)` in a verdict column reads as "the
    list is empty", which is a real and different state of this subject (`no_entries`), so the
    shared renderer would print one state's wording for another's. That is the stage's own
    recorded failure shape, and here it would be worse than a blank cell: it would agree with a
    plausible wrong reading.

    The four computed states print the model's `SHAPE_CHOICES` labels rather than wording of our
    own, because those labels were written beside the normalizer that assigns them and the
    evaluation ORDER is part of their meaning.
    """
    if not bound.list_shape:
        return SHAPE_NOT_COMPUTED
    return bound.get_list_shape_display()


DISCOVERY_SHAPE_READER = findings_sheet.ValueReader(
    read=list_shape,
    # The `DERIVED` label, so `build_rows` still asks the object where the value came from. Free
    # here: the field is in `UserIdDiscoveryBound.DERIVED_FIELDS`, so there is no stored row for
    # `stored=False` to cost us, and the model's docstring says why there never will be - a
    # verdict row holds nothing read directly off the collection it is a verdict over.
    provenance=DERIVED)


def listener_state(surface) -> str:
    """Whether this surface's listener state rests on a measurement or on an unmeasured inference.

    Not a Yes/No, and the reason is in `LISTENER_NOT_MEASURED` above: false here is the firing
    side and means "nobody has measured what an absent key means on this plane", which a bare No
    states as though it were a fact about the listener.

    THE WORDING IS DELIBERATELY ABOUT THE INSTRUMENT AND NOT ABOUT THE DEVICE. Stage 8 raised this
    as a `needs_human` precisely because no customer action can change it: an estate of
    PA-5200-series appliances carries two of these per appliance for as long as the payload
    contract's `applies_to` names `/deviceconfig/system/service` alone. A cell that reads like a
    device fault would send an engineer to a surface there is nothing to fix on.
    """
    return LISTENER_MEASURED if surface.userid_listener_state_established else LISTENER_NOT_MEASURED


LISTENER_STATE_READER = findings_sheet.ValueReader(
    read=listener_state,
    # The `DERIVED` label: the field is in `ManagementInterface.DERIVED_FIELDS`, so the walk is
    # free and the object still answers where the configuration came from. On the aux-2 row that
    # answer is Panorama's template stack, which is the one thing the reused finding generator's
    # sentence cannot say - see the stage 9 artifact's note on `uid6-26`.
    provenance=DERIVED)


def include_networks(bound) -> str:
    """The in-force include entries' configured CIDRs, one per line, as written.

    NOT RESOLVED AND NOT JUDGED, and the cell says so by printing nothing it was not given: these
    are the ranges a finding prints for an engineer to qualify against which of them hold the
    organization's own staff. A member may be any CIDR the device accepted.

    THE EMPTY CASE IS NOT A BLANK, for the reason the model's own docstring gives: an empty list
    on an unrecomputed row "would render as `no ranges configured`, which is wrong on a bounded
    appliance". So the two causes are separated - a computed row with no in-force include entry
    says that, and an uncomputed row defers to the verdict column beside it.
    """
    members = "\n".join(str(net) for net in (bound.include_networks or []) if str(net).strip())
    if members:
        return members
    if not bound.list_shape:
        return SHAPE_NOT_COMPUTED
    return "No in-force include entry"
