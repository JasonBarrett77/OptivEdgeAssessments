"""Engineer-detail xlsx, prototype: the Minimum Password Complexity controls, PAN-AUTH-001 to 013.

The first findings sheet built (Jason, 2026-09-15): "pick a single group of controls whose findings
can be represented together on a single spreadsheet ... the control that failed, the provenance for
the failing value, and other relevant meta data ... every finding must be presented." The layout it
established now lives in `findings_sheet.py`, and this module is what is particular to the group.

WHY THIS GROUP FITS THAT SHAPE. Every one of the thirteen controls targets
`PasswordComplexityPolicy` - one row per appliance - and each tests exactly ONE field of it. The
group also carries every case the layout has to survive: a template-pushed value, a local value, a
key absent from the config, a severity adjusted by a query, and an HA pair whose peers DISAGREE.
"""
from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from ..layout import SheetInfo

SPEC = findings_sheet.DeviceSettingSheet(
    control_types=(Control.ControlType.PASSWORD_COMPLEXITY,),
    #: "Firewall-wide" rather than "every password": a password profile bound to an account
    #: overrides the expiry settings for that account (see PasswordComplexityPolicy's docstring).
    # `PasswordComplexityPolicy`: "EVERY DEFAULT IS THE INSECURE ONE ... absent is expanded to
    # it rather than left null", measured 2026-09-03.
    description=("The firewall-wide rules for local administrator passwords - length, character "
                 "mix, reuse, expiry and access after expiry - and whether the firewall enforces "
                 "them."),
)


def write_sheet(build) -> SheetInfo:
    return findings_sheet.write_sheet(build, SPEC)
