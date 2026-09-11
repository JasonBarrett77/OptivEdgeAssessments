"""Finding generation for administrator account controls. PAN-AUTH-019, 021, 022.

The subject sentence states the ACCOUNT'S POSTURE, not the verdict: which role it holds, and
what it authenticates with. All three controls fire on the same object and an engineer reading
two findings on one row needs to see the account, once, in terms they can act on.
"""

from __future__ import annotations

from assessments.control_queries import evaluate_admin_user_control_queries
from assessments.models import (
    AdminUserFinding, AdminUserFindingControlQuery, Control)
from assessments.object_findings import (
    ObjectFindingRunResult,
    ObjectFindingSpec,
    generate_object_findings,
    matched_query_sentence,
    regenerate_object_findings,
)
from optivedge_integrations.integrations.models import AdminUser


def _credentials(obj) -> str:
    """What this account authenticates against, and what it still holds on the device.

    BOTH clauses, because PAN-AUTH-019 has two halves and a summary naming one of them sends an
    engineer to fix the wrong thing. "Authenticates through corp-tacacs" reads as compliant;
    "authenticates through corp-tacacs and still holds a local password" names the work.
    """
    if obj.effective_authentication_profile:
        where = f"authenticates through {obj.effective_authentication_profile}"
        if not obj.authentication_is_external:
            where += ", which is not an external identity service"
    else:
        where = "authenticates against the local database"
    held = [label for present, label in (
        (obj.has_password, "a local password"),
        (obj.has_public_key, "an SSH public key"),
    ) if present]
    # No credential and no profile is real - `oep-authtest` was created that way before its
    # profile was bound - and saying so beats rendering an empty clause.
    return where + (" and still holds " + " and ".join(held) if held
                    else " and holds no credential on the device")


def _subject(obj) -> str:
    return (f"Administrator {obj.name} on {obj.appliance} holds "
            f"{obj.get_role_type_display().lower()}, {_credentials(obj)}")


def build_admin_user_finding_summary(obj, matched_queries) -> str:
    """The one sentence this object type contributes to its findings."""
    return matched_query_sentence(_subject(obj), matched_queries)


SPEC = ObjectFindingSpec(
    label="administrator",
    control_type=Control.ControlType.ADMIN_USER,
    finding_model=AdminUserFinding,
    link_model=AdminUserFindingControlQuery,
    subject_fk="admin_user",
    link_fk="admin_user_finding",
    queryset=lambda: AdminUser.objects.select_related("appliance"),
    evaluate=evaluate_admin_user_control_queries,
    summary=build_admin_user_finding_summary,
    subject_name=lambda obj: obj.name,
)

AdminUserFindingRunResult = ObjectFindingRunResult


def generate_admin_user_findings(assessment_run) -> tuple[int, int, int, int]:
    """Fill an EXISTING run. Returns (controls, findings, links, skipped)."""
    return generate_object_findings(SPEC, assessment_run)


def regenerate_admin_user_findings() -> ObjectFindingRunResult:
    return regenerate_object_findings(SPEC)
