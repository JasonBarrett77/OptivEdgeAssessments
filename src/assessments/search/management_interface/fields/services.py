"""Which services a management surface exposes.

The polarity difference between the two management planes is already resolved upstream:
`ManagementService.enabled` is the effective answer whether it came from a deviceconfig
plane's `disable-telnet: yes` or a profile's absent `telnet` key. Nothing here needs to
know which plane a surface belongs to.

`administrative` is this layer's judgement and deliberately does not live in
OptivEdgeIntegrations. Whether a service constitutes administrative access is an assessment
question, not a collection one - the collector's job ends at recording that `ping` is on.
"""

from __future__ import annotations

from assessments.search.exceptions import SearchSyntaxError
from optivedge_integrations.integrations.models import SERVICE_NAMES, ManagementInterface

SUPPORTED_OPERATORS = {"eq"}

#: Services that accept an administrative session or management protocol exchange. Enabling
#: one of these makes an interface an administration surface; the other six PAN-OS services
#: do not.
#:
#: The exclusions are the point. ping, response-pages, http-ocsp and the three User-ID
#: listeners are reachability aids and service functions - enabling ping on an interface for
#: troubleshooting is routine, and a control that fired on it would bury the interfaces that
#: actually matter in noise. That would defeat PAN-MGT-006, whose whole value is being a
#: list short enough for a consultant to triage by hand.
ADMINISTRATIVE_SERVICES = ("http", "https", "ssh", "telnet", "snmp")

#: Matches a surface with ANY administrative service on. Kept as a named value rather than
#: expanded into a five-way OR in each control's stored query, so that changing what counts
#: as administrative is one edit here and not a rewrite of every control that asks.
ANY_ADMINISTRATIVE = "administrative"

SERVICE_VALUES = (ANY_ADMINISTRATIVE,) + tuple(SERVICE_NAMES)


def compile_service_enabled_clause(clause):
    op, value = clause["op"], clause["value"]
    if op not in SUPPORTED_OPERATORS:
        raise SearchSyntaxError(f"Unsupported operator for service_enabled: {op}.")
    if value not in SERVICE_VALUES:
        raise SearchSyntaxError(
            f"service_enabled must be one of {', '.join(SERVICE_VALUES)}; got {value!r}.")
    names = ADMINISTRATIVE_SERVICES if value == ANY_ADMINISTRATIVE else (value,)
    return (ManagementInterface.objects
            .filter(services__name__in=names, services__enabled=True)
            .values("pk").distinct())


compile_service_enabled_clause.SUPPORTED_OPERATORS = SUPPORTED_OPERATORS


#: Administrative services a shipped control asserts must be OFF - PAN-MGT-001 (telnet) and
#: PAN-MGT-002 (http). Presentation highlights these when on. Kept beside the definitions
#: above so the highlight and the controls cannot drift apart; extend it only when a control
#: exists to justify it, since colouring a service red is an assertion about it.
INSECURE_SERVICES = ("http", "telnet")
