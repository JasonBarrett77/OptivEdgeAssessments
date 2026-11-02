"""How the three Device-ID tabs read: the cells whose wording is a judgement.

Written by the stage 9 run of OptivEdgeProbe's `device-id-iot` domain, 2026-11-02, for
PAN-IOT-001 to -004 over three models and three grains - the appliance's device-identification
service state, the security zone, and a verdict over an enforcement point's whole rule set.

EVERY HEADING AND EVERY WORD BELOW IS A PROPOSAL. Report content is Jason's and he takes the
heading pass once across many domains rather than per domain (P399), so these are written to be
argued with, and the ones that are not merely cosmetic say why in their own comment.

THREE OF THEM ARE THE WHOLE REASON THIS MODULE EXISTS, because the shared `display_value` has
three answers - a value, `(none)` for NULL and `(empty)` for the empty string - and on these
columns all three are wrong in the direction that reassures:

  - AN EMPTY DEVICE-ID ADDRESS LIST IS THE VENDOR'S `any`, NOT A BLANK. Stage 4 measured the
    grid on two platforms: with no `device-acl` node the INCLUDED NETWORKS cell renders `any`
    and EXCLUDED renders `none`, so an absent or empty include list means identification
    applies to EVERY address in the zone - the most permissive reading AND the compliant one
    for PAN-IOT-002. `(empty)` or a blank cell here is the first of this stage's three recorded
    presentation failures, verbatim: "a blank cell where the honest value was *any source*".
    So the cells read the vendor's own two words.

  - A NULL CONTENT AGE IS "NOT COMPUTABLE", NOT `(none)`. `device_dictionary_age_days` is NULL
    on exactly the appliances that report no release date, which PAN-IOT-003's applicability
    clause then narrows OUT of the graded comparison. `(none)` in a column of day counts reads
    as a value somebody failed to fill in, and the row's finding is about something else. The
    em dash says the comparison was not made; the marked companion column says why.

  - THE VERDICT COLUMN'S `True` IS THE FINDING. `has_no_rule_matching_on_device` defaults True
    and True fires, so a heading in the field's own polarity is the only safe one: a reader must
    not be able to mistake the firing cell for a pass. "Device dimension absent from the rule
    set: Yes" cannot be misread. Left as `display_value`'s own Yes/No deliberately - the words
    are right, it is the HEADING that had to carry the direction.

WHAT IS DELIBERATELY NOT HERE. `edge_service_address` gets NO reader, and that refusal is the
one thing in this module that costs a reader something. It is the only PAYLOAD KEY among the
four tested fields of its tab - every other one is in `DeviceIdentificationState.DERIVED_FIELDS`
- and `build_rows` hands a reader field `stored=False` to `remediation_accessor`, which then
never consults that field's own `FieldProvenance` row and walks to the object's entry instead.
Whether the key was ABSENT, explicitly blank, or template-supplied is half of what PAN-IOT-001
is about, so the cell reads `(empty)` and the Provenance column beside it keeps the answer. The
`ipsec-crypto` run made the same refusal on two columns for the same reason.
"""
from __future__ import annotations

from .artifacts.layout import NONE

#: The vendor's own word for an unnarrowed Device-ID include list, from the grid stage 4 read on
#: two platforms. NOT our paraphrase: the firewall prints this.
ANY_ADDRESS = "Any"
#: And its exclude-list counterpart, from the same grid.
NOTHING_EXCLUDED = "None"


def _members(values) -> str:
    """One member per line, in the order the configuration stored them.

    A JSON list column, so there is no `None` state to tell from an empty one: stage 5 measured
    `empty_is_distinct: false` at the device as well as in the column - deleting the only member
    leaves the `device-acl` container present and EMPTY, and PAN-OS does not store an empty
    member list. Absent and empty are one state, which is why the caller supplies the word.
    """
    return "\n".join(str(value) for value in values if str(value).strip())


def device_include_members(zone) -> str:
    """The addresses identification is limited TO, or the vendor's `Any`.

    `Any` rather than a blank is the whole point of this cell: an empty list is the COMPLIANT
    state of PAN-IOT-002's second half and the most permissive one on the device, and a reader
    who has already seen the switch turned on looks for a narrow list, not for an empty one.
    """
    return _members(zone.device_include_acl or []) or ANY_ADDRESS


def device_exclude_members(zone) -> str:
    """The addresses held back from identification, or the vendor's `None`."""
    return _members(zone.device_exclude_acl or []) or NOTHING_EXCLUDED


def identification_enabled(zone) -> str:
    """Whether the zone identifies devices at all.

    A stored non-null boolean defaulting to false, and false is the firing side - so this is a
    plain Yes/No and the reader exists only to keep the Provenance walk off `Zone`, which
    declares no `DERIVED_FIELDS`. See `ZONE_READERS` for that.
    """
    return "Yes" if zone.enable_device_identification else "No"


def identification_narrowed(zone) -> str:
    """Whether either Device-ID list has a member.

    Computed at normalization because the two lists are JSON columns, a JSON column is reachable
    from no query in this language, there is no count operator, and no clause can hold an OR
    across two columns - so "either list has at least one member" is computed there or it cannot
    be asked at all.
    """
    return "Yes" if zone.device_identification_is_narrowed else "No"


def device_lists_read(zone) -> str:
    """Whether this row's Device-ID lists were computed by a normalizer that knew about them.

    False means the row predates the two columns, or its merged read never arrived - NOT that
    the lists are empty. It is the column that answers PAN-IOT-002's unknown, and the one the
    mark lands on when nothing else can.
    """
    return "Yes" if zone.device_acl_lists_computed else "No"


#: What the Provenance column says on every row of the Security Zones tab, and it is the honest
#: answer rather than a workaround dressed up as one.
#:
#: `integrations.Zone` DOES NOT TRACK PROVENANCE AT ALL. It is a `SyncTrackedModel` and not a
#: `ProvenancedMixin`, it declares no `DERIVED_FIELDS`, and nothing writes a `FieldProvenance`
#: row for a zone - so there is no per-field answer to give and no template name to print. Every
#: other findings tab in this repository is over a provenanced model and reads a real answer here.
#:
#: WHY THAT MATTERS TO A READER AND IS NOT BOOKKEEPING. Stage 6 built a zone that exists ONLY in
#: a Panorama template, with every element decorated `@ptpl`/`@src`, and the row this report draws
#: for it is INDISTINGUISHABLE from a firewall-local zone: the finding names a local zone and the
#: remediation it implies is one the firewall will refuse, because the setting is pushed and has
#: to be changed on Panorama. The Provenance cell is the one place that could have said so and it
#: cannot. So it says what is true - that this is not recorded for a zone - which at least stops a
#: reader concluding the zone is local because the column was blank.
ZONE_PROVENANCE = ("Not recorded for a zone:\n"
                   "this model tracks no per-field\n"
                   "provenance, so the report cannot\n"
                   "say whether the value is local\n"
                   "or pushed from a template")


def zone_provenance(_zone, _provenance_of=None, _fields=None) -> str:
    """ONE answer for the whole row, on `vsys_rule_posture`'s precedent for a computed subject.

    It ignores `provenance_of`, and that is deliberate rather than lazy: calling it on a `Zone`
    raises `AttributeError`, because the shared closure falls back to `field in
    model.DERIVED_FIELDS` whenever no stored row exists and `Zone` declares no such attribute.
    Recorded in this run's artifact as a defect rather than fixed here - the model is another
    repository's and the closure is shared machinery.
    """
    return ZONE_PROVENANCE


def content_age_days(state) -> str:
    """How old the installed classification data is, or the em dash for "not computable".

    THE EM DASH IS THE POINT and `layout.NONE` is U+2014. NULL here is not a missing reading in
    the ordinary sense: it is an appliance whose `show system info` reply carries no
    `device-dictionary-release-date` key at all - measured on both PA-5220s, which are the two
    appliances holding content 167 releases behind their siblings - so there is no date to count
    from and PAN-IOT-003's applicability clause narrows the row OUT of the graded comparison
    rather than letting a NULL pass every threshold.

    Safe on this field because the model declares it in `DERIVED_FIELDS`, where a reader costs
    no `FieldProvenance` row. Measured, not assumed.
    """
    value = state.device_dictionary_age_days
    return NONE if value is None else str(value)


def release_date(state) -> str:
    """The release date of the installed content, as the appliance worded it.

    Carried as written and never parsed into a cell: the stored string is a local timestamp with
    a timezone ABBREVIATION rather than an offset, so it is not comparable across appliances and
    not stable on one. The model's own comment says to grade on the age beside it and never on
    this. Shown so a reviewer can check the age against the thing it was computed from.
    """
    return state.device_dictionary_release_date or NONE


def dictionary_version(state) -> str:
    """The installed device-dictionary content version, e.g. `249-772`.

    No clause names this column. It is here so a reviewer can check a staleness finding against
    the number the vendor's own Dynamic Updates screen shows, and so the 167-release gap between
    this lab's two platform families is visible on the row rather than only in an artifact.
    """
    return state.device_dictionary_version or NONE


def icd_build(state) -> str:
    """`show iot icd version`'s build string - THE INSTRUMENT THIS REPORT DOES NOT GRADE.

    Shown beside the graded one on purpose, and the comment is the finding: the two instruments
    rank this estate in OPPOSITE orders. Build dates are 2026-02-06 on the two PA-5220s against
    2024-07-22 on pan-fw-111, while the content versions are 82-406 on those PA-5220s against
    249-772 on pan-fw-111 - a gap of 167 releases. Grading on the build date would call the two
    most stale appliances in the lab the freshest in it. A reader who sees only the build date
    would draw exactly that conclusion, which is why both are on the row.
    """
    return state.icd_build_version or NONE


def icd_built_at(state) -> str:
    """When that build was made. Ungraded, for the reason on `icd_build`."""
    return state.icd_built_at or NONE


def rules_matching_count(verdict) -> str:
    """How many rules name a device object that resolves.

    PRINTED AS THE NUMBER rather than through `display_value`, following the `rule-posture`
    precedent for a count column: zero is the reportable end here, and a word like "Nothing"
    on a column named for a count reads as "not counted" instead of "none found".

    IT CAN READ 1 ON A FIRING ROW, which is a state no cell can explain and is recorded in this
    run's artifact rather than papered over: the verdict column negates the count of rules that
    ALLOW and name a device, while this counts every rule that names one. A rule that names a
    device object and denies therefore leaves the verdict firing beside a non-zero count here.
    No row in this lab is in that state and the combination is reachable on a real estate.
    """
    return str(verdict.rules_matching_on_device_count)


def device_objects_visible(verdict) -> str:
    """How many device objects this enforcement point could resolve a rule member against.

    ZERO AND NON-ZERO ARE TWO DIFFERENT REMEDIATIONS and that is the whole reason this column is
    on the row: zero means no rule COULD name a device even if somebody wrote one, so the work
    is to define the objects; non-zero means the objects exist and the policy does not use them.
    The model's own comment makes the same distinction. Four namespaces are counted - the vsys's
    own container, firewall-local shared, the Panorama device-group scope and Panorama shared.
    """
    return str(verdict.device_object_count)
