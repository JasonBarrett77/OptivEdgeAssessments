"""Finding generation for the custom URL category hygiene control. PAN-URL-006.

THE SENTENCE IS THE DELIVERABLE AND ITS QUALIFICATION IS PART OF IT. Stage 3 bounds this control
in terms: it is "deliverable ONLY as a list of candidates for review, never as a removal
instruction", because "every error this reading makes is in the direction of calling a live object
unreferenced, and the original's own remediation is a deletion, so a finding that does not carry
the qualification is worse than no finding". So `_subject` names how many reference surfaces were
actually searched, every time, and never prints `unreferenced` without that denominator.

The measurement behind that: the vendor documents four rulebases that can match on a URL category
- Security, QoS, Decryption and Authentication - and this project's normalizer collects two.
Stage 2's referrer enumeration, asked with the uncapped flag, found 39 referrer fields pooling 69
scopes where a capped ask gives 8.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_custom_url_category_control_queries
from assessments.models import (
    Control,
    CustomUrlCategoryFinding,
    CustomUrlCategoryFindingControlQuery,
)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import CustomUrlCategory


def category_owner(obj) -> str:
    """The appliance group for shared scope, `group / vsys` for vsys scope.

    The same shape as `security_profile_findings.profile_owner`, and for the same reason: a
    category belongs to an enforcement point at vsys scope and to an appliance group at shared
    scope, so one of the two foreign keys is always null.
    """
    return obj.appliance_group.name if obj.appliance_group_id else str(obj.enforcement_point)


def _reach_qualification(obj) -> str:
    """How far the reference walk actually looked, in the words a reader needs.

    NEVER OMITTED AND NEVER EMPTY. `reference_surfaces_searched` is a JSONField holding the
    surfaces the walk read; an empty list means the walk did not run at all, which is a
    DIFFERENT claim from "nothing references this" and has to read differently on the row. A
    finding that said `unreferenced` without this would be asserting a denominator it never
    established.
    """
    surfaces = obj.reference_surfaces_searched or []
    if not surfaces:
        return ("no reference surface was searched for it, so nothing here establishes that it "
                "is unused")
    return (f"searched across {len(surfaces)} reference "
            f"surface{'s' if len(surfaces) != 1 else ''} ({', '.join(str(s) for s in surfaces)})")


def _membership(obj) -> str:
    """What the category actually reaches, and whether that was measured.

    `match_entry_count` is `null=True` and a null means the `list` key was ABSENT - nothing is
    assumed - which is not the same as an empty list. `match_entry_count_computed` is false on
    exactly the rows whose count is a migration default rather than a reading, so a null and an
    uncomputed zero must not both print as "0 entries".
    """
    if not obj.match_entry_count_computed or obj.match_entry_count is None:
        return "its membership was not read"
    count = obj.match_entry_count
    return f"it holds {count} entr{'y' if count == 1 else 'ies'}"


def _subject(obj) -> str:
    kind = obj.category_type or "untyped"
    what = (f"Custom URL category {obj.name} of type {kind} at "
            f"{obj.namespace_type} scope on {category_owner(obj)}")

    # THE GRADING'S OWN REASONING, in the sentence rather than only in the severity. A
    # `Category Match` target reaches sites by category membership, so its reach grows whenever
    # the database reclassifies a site into the combination - which is why stage 3 ranks it above
    # a `URL List`, whose reach is exactly what somebody typed. Measured and worth stating: a
    # Category Match targets the INTERSECTION of the categories it names, not their union.
    if obj.category_type == "Category Match":
        reach = ("it reaches sites by category membership rather than by name, so its reach "
                 "grows as the URL database reclassifies sites")
    elif obj.category_type == "URL List":
        reach = "it reaches only the entries it holds"
    else:
        # NOT A DEVICE STATE. The type key is mandatory at commit validation - measured, three
        # commits on two platforms - so an empty type is a row written before the recompute or
        # one whose entry came from a view carrying no type leaf. It must not read as a third
        # kind of category.
        reach = ("its stored type was not read, so how far it reaches is not established "
                 "by this finding")

    if obj.is_used:
        # Reached only by a calibration or a future query; the baseline asserts `is_used eq
        # false`. Stated rather than left to the fallback, because a reassuring sentence on a
        # firing finding is the defect this repository has twice had to fix.
        return (f"{what} is referenced by {obj.referrer_count} "
                f"surface{'s' if obj.referrer_count != 1 else ''} and {reach}; "
                f"{_membership(obj)}, {_reach_qualification(obj)}")

    return (f"{what} is referenced by nothing this assessment read and {reach}; "
            f"{_membership(obj)}, {_reach_qualification(obj)}. "
            "Review it rather than deleting it: a category in use by a rulebase this assessment "
            "did not read would read exactly the same way")


def build_custom_url_category_finding_summary(obj, matched_queries) -> str:
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="custom URL category",
    control_type=Control.ControlType.CUSTOM_URL_CATEGORY,
    finding_model=CustomUrlCategoryFinding,
    link_model=CustomUrlCategoryFindingControlQuery,
    subject_fk="custom_url_category",
    link_fk="custom_url_category_finding",
    queryset=lambda: CustomUrlCategory.objects.select_related(
        "enforcement_point__appliance_group", "appliance_group"),
    evaluate=evaluate_custom_url_category_control_queries,
    summary=build_custom_url_category_finding_summary,
    subject_name=lambda obj: obj.name,
    # Names repeat across scopes: the same category name can exist at a vsys, at the firewall's
    # own shared scope, in a Panorama device group and in the pushed view, and the remediation
    # differs by scope - so the finding carries where the definition lives, not only its name.
    subject_scope=lambda obj: f"{obj.namespace_type}:{category_owner(obj)}"[:128],
)

CustomUrlCategoryFindingRunResult = ObjectFindingRunResult


def generate_custom_url_category_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_custom_url_category_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
