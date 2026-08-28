"""Is this management surface restricted, unrestricted, or undetermined?

Three states, not two. `undetermined` exists because a permitted-source entry that does not
parse - an IPv6 literal on an IPv4-only pipeline, or a typo - can support neither verdict.
Reporting it as restricted would be a false clean result, which is the failure mode the
whole management-plane investigation exists to avoid.

Measured 2026-08-27: an absent or empty permitted-source list means ANY source that can
route to the interface, verified by connecting to a data-plane interface with a profile
bound and no list. An empty list is not storable - PAN-OS drops the container - so absent
and empty are one state.
"""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import ManagementInterface, PermittedSource

SUPPORTED_OPERATORS = {"eq"}

UNRESTRICTED = "unrestricted"
RESTRICTED = "restricted"
UNDETERMINED = "undetermined"
EXPOSURE_STATES = (UNRESTRICTED, RESTRICTED, UNDETERMINED)


def classify(values: list[tuple[str, int | None]]) -> str:
    """(value, family) pairs for one surface -> one of EXPOSURE_STATES.

    Anything that is not an IPv4 literal makes the surface UNDETERMINED, and that includes
    a perfectly valid IPv6 entry. Two reasons, and the second is the one with teeth:

    - the pipeline is IPv4-only, so a v6 entry carries no interval to reason about; and
    - **UNMEASURED**: whether a v6-only list restricts IPv4 at all. The compiled ACL keeps
      `peers` and `v6peers` apart, and an empty `peers` is what unrestricted IS - so a
      v6-only list may leave IPv4 wide open. Calling that `restricted` would be exactly
      the false clean result this control exists to prevent.

    Resolve it by putting a v6-only list on a lab interface and connecting over IPv4.
    """
    if not values:
        return UNRESTRICTED
    if any(family != 4 for _, family in values):
        return UNDETERMINED
    return RESTRICTED


def exposure_by_interface() -> dict[int, str]:
    sources: dict[int, list[tuple[str, int | None]]] = {}
    for pk in ManagementInterface.objects.values_list("pk", flat=True):
        sources[pk] = []
    for value, family, owner in PermittedSource.objects.values_list(
            "value", "family", "management_interface_id"):
        sources.setdefault(owner, []).append((value, family))
    return {pk: classify(rows) for pk, rows in sources.items()}


def compile_exposure_clause(clause):
    op, value = clause["op"], clause["value"]
    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for exposure: {op}.")
    if value not in EXPOSURE_STATES:
        raise SearchSyntaxError(
            f"exposure must be one of {', '.join(EXPOSURE_STATES)}; got {value!r}.")
    matching = [pk for pk, state in exposure_by_interface().items() if state == value]
    return ManagementInterface.objects.filter(pk__in=matching).values("pk")


compile_exposure_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS
