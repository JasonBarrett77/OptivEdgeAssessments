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

import ipaddress

from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import ManagementInterface, PermittedSource

SUPPORTED_OPERATORS = {"eq"}

UNRESTRICTED = "unrestricted"
RESTRICTED = "restricted"
UNDETERMINED = "undetermined"
EXPOSURE_STATES = (UNRESTRICTED, RESTRICTED, UNDETERMINED)


def classify(values: list[tuple[str, int | None]], *,
             wildcard_is_stripped: bool = True) -> str:
    """(value, family) pairs for one surface -> one of EXPOSURE_STATES.

    A non-empty list restricts, whatever family its entries are. Measured 2026-08-28 on a
    data-plane interface, by connecting over IPv4 after each commit:

        no list                       443 OPEN     unrestricted
        one non-matching IPv4 entry   443 closed   restricted
        IPv6 entry only               443 closed   restricted - IPv4 is denied outright
        IPv6 + a matching IPv4 range  443 OPEN     families evaluated independently

    So a v6-only list does NOT leave IPv4 open. An earlier draft classified it
    `undetermined` on the theory that the compiled ACL keeps `peers` and `v6peers` apart
    and an empty `peers` is what unrestricted IS - but an empty `peers` only means
    unrestricted when the whole list is empty. That was a reasonable guess and it was
    wrong, which is why it was marked unmeasured rather than shipped as fact.

    UNDETERMINED now means only what it should: an entry nothing can evaluate, or one whose
    effect is not established.

    An all-addresses entry - `0.0.0.0/0`, `::/0` - needs the plane, because the answer
    differs and one half of it is measured.

    ALONE it is UNRESTRICTED on any plane, and that needs no measurement: if PAN-OS honours
    it the surface permits everything, and if PAN-OS strips it the list is empty, which also
    permits everything. A real firewall permitted only 0.0.0.0/0 on its management interface
    and was reported Restricted - the false clean result this classifier exists to prevent.

    ALONGSIDE other entries the planes differ:

    - On a **deviceconfig plane** PAN-OS strips the wildcard when compiling the ACL, so
      `[0.0.0.0/0, 10.99.99.99]` permits 10.99.99.99 and nobody else. Measured; see
      `docs/palo-alto/pan-os/management/read-device-configuration.md`. Calling that
      unrestricted would be a false positive on a hardened device, which that guide says
      explicitly.
    - On a **data-plane profile** the same stripping is **unmeasured**, so neither answer can
      be claimed and the honest result is UNDETERMINED. PAN-MGT-003 matches UNDETERMINED as
      well as UNRESTRICTED, so the surface is reported rather than quietly assumed safe.
    """
    if not values:
        return UNRESTRICTED
    if any(family is None for _, family in values):
        return UNDETERMINED
    if all(_permits_any_address(value) for value, _ in values):
        return UNRESTRICTED
    if any(_permits_any_address(value) for value, _ in values):
        # The wildcard is stripped on a deviceconfig plane, leaving the specific entries as
        # the real restriction. Whether a profile behaves the same has never been measured.
        return RESTRICTED if wildcard_is_stripped else UNDETERMINED
    return RESTRICTED


def _permits_any_address(value: str) -> bool:
    """Does this entry cover every address of its family? A /0 prefix does."""
    try:
        return ipaddress.ip_network((value or "").strip(), strict=False).prefixlen == 0
    except ValueError:
        return False


def exposure_by_interface() -> dict[int, str]:
    sources: dict[int, list[tuple[str, int | None]]] = {}
    #: Wildcard stripping is measured on the deviceconfig planes and unmeasured on a
    #: profile, so the plane decides how a mixed list is read.
    stripped: dict[int, bool] = {}
    for pk, plane in ManagementInterface.objects.values_list("pk", "plane"):
        sources[pk] = []
        stripped[pk] = plane != ManagementInterface.PLANE_DATAPLANE
    for value, family, owner in PermittedSource.objects.values_list(
            "value", "family", "management_interface_id"):
        sources.setdefault(owner, []).append((value, family))
    return {
        pk: classify(rows, wildcard_is_stripped=stripped.get(pk, True))
        for pk, rows in sources.items()
    }


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
