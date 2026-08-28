"""How a management surface is named in a report.

OptivEdgeIntegrations stores `plane` and `interface_name`; it does not decide what to call
them. Naming is a consumer's choice - a report may want "MGT" or "Management interface" or
the vendor's own label - and putting it in the collection layer would mean editing that repo
to change a word in a finding.
"""

from __future__ import annotations

from optivedge_integrations.integrations.models import ManagementInterface

#: The vendor's own labels, which is what an assessor reading a PAN-OS UI expects to see.
PLANE_LABELS = {
    ManagementInterface.PLANE_MGT: "MGT",
    ManagementInterface.PLANE_AUX1: "Aux-1",
    ManagementInterface.PLANE_AUX2: "Aux-2",
}


def surface_label(surface) -> str:
    """The reportable name of one management surface.

    A data-plane surface is named by its interface, because that is the door an assessor
    has to go and look at; the management planes are named by the vendor's label.
    """
    if surface.plane == ManagementInterface.PLANE_DATAPLANE:
        return surface.interface_name or "(unnamed interface)"
    return PLANE_LABELS.get(surface.plane, surface.plane)
