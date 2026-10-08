"""Engineer-detail xlsx, prototype: the remaining findings tabs, one per control type.

Jason, 2026-09-18: "Create the rest of the Findings tab. Follow the same column pattern as the
existing tabs." Fifteen domains were left: four device-wide settings and eleven named objects.

ONE MODULE, NOT FIFTEEN. Each is a `DeviceSettingSheet` differing only in its control type, its
domain sentence and which columns name the subject - so they are a TABLE here rather than fifteen
files repeating the same four lines. The four earlier tabs keep their own modules because each
carries an argument worth reading next to it (the sentinel zeros, the derived SSH verdicts, the
clean SNMP controls).

THREE SUBJECT SHAPES, which is what the pattern actually varies by:
- DEVICE-WIDE: the appliance is the subject. Login banner, master key, update server, logging.
  Jason, 2026-09-18: do NOT fold these into Device Services - each is its own question.
- NAMED ON AN APPLIANCE: a name, and for the scoped ones the scope it lives in (`shared`, or the
  vsys). A name is not unique across scopes - `TLSv1.3_Default` exists as both predefined and
  shared - so the scope column is part of the identity, not decoration.
- SCOPED TO A VSYS: security profiles belong to an enforcement point, like security rules, so they
  name the firewalls that run it rather than one appliance.

The settings columns, the marked value, the provenance and the metadata are the shared machinery's
- see `findings_sheet`.
"""
from __future__ import annotations

from assessments.models import Control

from . import findings as findings_sheet
from ..layout import NONE, SheetInfo, appliance_names, ha_role

T = Control.ControlType


def scope_of(obj) -> str:
    """Where a scoped object lives: its vsys, or the scope name where it is not vsys-scoped."""
    scope = getattr(obj, "scope", "") or ""
    vsys = getattr(obj, "vsys_name", "") or ""
    if scope == "vsys":
        return vsys or scope
    return scope or NONE


#: The appliance and its HA role - every device-wide sheet, and the anchor of every named one.
APPLIANCE = (
    ("Appliance", 16, False, lambda s, _p: s.appliance.hostname or NONE),
    ("HA role", 10, False, lambda s, _p: ha_role(s.appliance)),
)

#: A named object on an appliance. Scope and kind are added only where the model has them. Each
#: declares the FIELD it presents, so a control testing that field marks this cell rather than
#: adding a second column of the same name - which is not merely untidy: a table with a duplicate
#: header is rejected by Excel, and xlsxwriter drops it with a warning, leaving a sheet of stray
#: cells where the table should be (seen 2026-09-18 on AAA Server Profile and Security Profile).
NAME = (("Object", None, False, lambda s, _p: s.name or NONE, "name"),)

#: Coverage findings name an address object, which hangs off an enforcement point or an
#: appliance group rather than an appliance - so APPLIANCE, which reads `s.appliance`, does not
#: apply. "Where" carries whichever owner it has.
COVERAGE_SUBJECT = (
    ("Object", None, False, lambda s, _p: s.name or NONE, "name"),
    ("Type", 18, False, lambda s, _p: s.get_address_type_display()),
    ("Where", 24, False, lambda s, _p: str(s.enforcement_point or s.appliance_group or NONE)),
)
SCOPE = (("Scope", 12, False, lambda s, _p: scope_of(s), "scope"),)
KIND = (("Kind", 22, False, lambda s, _p: s.get_kind_display(), "kind"),)

def scope_owner(obj):
    """The appliance group or appliance a scoped object belongs to.

    A vsys-scoped object hangs off an enforcement point; a SHARED-scope one hangs off the group
    directly and has no enforcement point at all. Both are real states - a security profile can be
    defined once for every vsys on a pair - so both are read rather than assumed.
    """
    point = getattr(obj, "enforcement_point", None)
    if point is not None:
        return point.appliance_group or point.appliance
    return getattr(obj, "appliance_group", None) or getattr(obj, "appliance", None)


#: A vsys-scoped object, named the way the policy tabs name one: who runs it, then where.
VSYS_SCOPED = (
    ("Firewalls", 16, True, lambda s, _p: appliance_names(scope_owner(s))),
    ("Vsys", 12, False,
     lambda s, _p: (s.enforcement_point.vsys_name
                    if getattr(s, "enforcement_point", None) is not None else "shared")),
)


#: Three fields controls test that are NOT columns on their model, each read from where the value
#: actually lives. Without these the sheet would refuse to build - which is the guard doing its
#: job: a control testing something the sheet cannot show must not fire onto it silently.
SERVICES_ENABLED = findings_sheet.ValueReader(
    read=lambda surface: "\n".join(
        sorted(service.name for service in surface.services.all() if service.enabled)) or "(none)",
    members=lambda surface: surface.services.all(),
)
#: `exposure` is a VERDICT the query layer computes over the permitted-source list - restricted,
#: unrestricted, or undetermined where an entry cannot be classified. The list is stored and is
#: what an engineer acts on, so the cell shows the list; the verdict is what the control asserts
#: and is in Fires when on the Controls tab.
PERMITTED_SOURCES = findings_sheet.ValueReader(
    read=lambda surface: "\n".join(
        source.value for source in surface.permitted_sources.all()) or "(any source)",
    members=lambda surface: surface.permitted_sources.all(),
)
#: `binding_count` is the query layer's name for `bound_interface_count`, which the model stores
#: and declares derived - so the answer comes from the model rather than from a sentence here.
BINDING_COUNT = findings_sheet.ValueReader(
    read=lambda profile: str(profile.bound_interface_count),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)




#: Whether any security rule points at this object, on either side - what keeps the coverage
#: controls proportionate, since an EDL nobody references is EXPECTED to be unsized. A reader
#: rather than a model property because the answer lives on the ref rows, and the spec prefetches
#: both so the sheet does not pay a query per row for it.
REFERENCED_BY_POLICY = findings_sheet.ValueReader(
    read=lambda obj: "Yes" if (obj.securityrulesourceaddressref_set.all()
                               or obj.securityruledestinationaddressref_set.all()) else "No",
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


#: Which WildFire Inline ML models an antivirus profile does not run. A model the config never
#: mentions is OFF and is listed here, because the absence of a setting is not the absence of a
#: problem - a profile with no ML node runs no inline ML at all.
#:
#: NOT BLOCKING rather than OFF: `mlav-policy-action` has three values and `enable(alert-only)`
#: runs the model without stopping the file, so it belongs in this list as much as `disable`
#: does. Naming the column "off" would have made an alert-only model invisible here.
#: A per-application override defeats the decoder action for one application, so a profile
#: hardened on every decoder can still allow malware over whatever is listed here. "none" is
#: the normal answer - an override is an operator-added exception - and it is spelled out
#: rather than left blank so the cell distinguishes "no overrides" from "not looked at".
APP_OVERRIDE_COVERAGE = findings_sheet.ValueReader(
    read=lambda profile: (", ".join(profile.non_blocking_application_overrides)
                          if profile.non_blocking_application_overrides else "none"),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)

ML_COVERAGE = findings_sheet.ValueReader(
    read=lambda profile: (", ".join(profile.non_blocking_ml_models)
                          if profile.non_blocking_ml_models
                          else ("all enabled" if profile.ml_models.all() else "—")),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


#: Which protocol decoders an antivirus profile does NOT stop malware on. Blank for every
#: other kind, which has no decoders. The resolved action, not the configured one - the
#: configuration says `default` on every decoder of every unedited profile, so a column showing
#: what the config holds would show the same word on a profile that blocks and one that does not.
DECODER_COVERAGE = findings_sheet.ValueReader(
    read=lambda profile: (", ".join(profile.non_blocking_decoders) + " (alert only)"
                          if profile.non_blocking_decoders
                          else ("all block" if profile.decoders.all() else "—")),
    provenance=findings_sheet.FieldProvenance.ProvenanceType.DERIVED.label,
)


def spec(control_type, description, *, title="", subject=APPLIANCE, **options):
    return findings_sheet.DeviceSettingSheet(
        control_types=(control_type,), title=title, description=description,
        subject_columns=subject, **options)


#: The domain each tab covers, and which columns name its subject. Nothing here says what a
#: missing provenance row means or which columns are computed: Integrations records the first and
#: declares the second on the model, as of 2026-09-21.
SPECS = (
    # Its own tab, deliberately separate from the object findings. Jason, 2026-10-02: "I don't
    # want them to disturb the highly structured, object related findings." It sits with the
    # Objects tabs because its subject is an address object and the workbook orders tabs by
    # category.
    spec(T.COVERAGE,
         "What this assessment could not establish, and why. These are gaps in the measurement "
         "rather than faults on the device: an external dynamic list whose content was never "
         "collected, or one collected only in part. A rule referencing an object of unknown "
         "size cannot be scored for breadth, and an unscored rule must not read as a narrow "
         "one - which is what these exist to prevent.",
         title="Coverage", subject=COVERAGE_SUBJECT,
         # An address object hangs off an enforcement point or an appliance group, never a
         # single appliance - the same reason COVERAGE_SUBJECT reads "Where" instead of an
         # Appliance column. Both defaults here are appliance-scoped and neither applies, which
         # is what broke this tab and the coverage findings page: `appliance_of` reads
         # `s.appliance` and the select_related walks `appliance__appliance_group`.
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance_group",
                                 "enforcement_point__appliance", "appliance_group"),
         value_readers={"referenced_by_policy": REFERENCED_BY_POLICY},
         # The reverse accessors on AddressObject, which are NOT the names a rule uses for the
         # same tables - a rule has `source_address_refs`, an address object has
         # `securityrulesourceaddressref_set`. Prefetching so the Referenced column does not
         # cost a query per row.
         subject_prefetch=("securityrulesourceaddressref_set",
                           "securityruledestinationaddressref_set")),
    spec(T.LOGIN_BANNER,
         "The banner shown before an administrator logs in, and whether they must acknowledge it."),
    spec(T.MASTER_KEY,
         "The key that encrypts the firewall's own stored secrets, and whether it is still the "
         "factory default."),
    spec(T.UPDATE_SERVER,
         "How the firewall talks to Palo Alto's update servers, and whether it verifies their "
         "identity."),
    spec(T.LOGGING_SETTINGS,
         "What the firewall does about logging when the data plane is under load."),
    spec(T.NTP_SETTINGS,
         "Where each firewall gets its time, and whether those exchanges are authenticated. "
         "Whether a configured server is reachable or synchronized is not assessed - that is "
         "live device state, not configuration.",
         title="NTP",),
    spec(T.SNMP_SETTINGS,
         "Whether each firewall exposes SNMP, which version, and whether its community string is "
         "a default one.",
         title="SNMP",),
    spec(T.SYSTEM_IDENTITY,
         "How each firewall is named, what time zone its logs are written in, and whether its "
         "management address is static.",
         title="System Identity",),
    spec(T.MANAGEMENT_INTERFACE,
         "Every surface an administrator can reach the firewall on - the management port, the aux "
         "ports and any data-plane interface offering administrative services - and what each "
         "offers.",
         subject=APPLIANCE + (
             ("Surface", 22, False,
              lambda s, _p: f"{s.get_plane_display()} {s.interface_name}".strip(), "plane"),
             ("Services enabled", 22, True, lambda s, _p: SERVICES_ENABLED.read(s),
              "service_enabled"),
             # Headed by what the cell HOLDS. The control tests `exposure`, a verdict over this
             # list; the list is what an engineer edits.
             ("Permitted sources", 24, True, lambda s, _p: PERMITTED_SOURCES.read(s), "exposure"),
         ),
         value_readers={"service_enabled": SERVICES_ENABLED, "exposure": PERMITTED_SOURCES},
         subject_prefetch=("services", "permitted_sources")),
    spec(T.INTERFACE_MANAGEMENT_PROFILE,
         "The profiles that decide which services a data-plane interface offers, and which "
         "interfaces carry them.",
         subject=APPLIANCE + NAME + (
             ("Bound interfaces", 18, True,
              lambda s, _p: "\n".join(s.bound_interface_names or []) or "(none)", "binding_count"),
         ),
         value_readers={"binding_count": BINDING_COUNT}),
    spec(T.SSL_TLS_SERVICE_PROFILE,
         "The TLS profiles the firewall presents to browsers and clients: their protocol floor "
         "and the certificate each uses.",
         title="SSL-TLS Service Profile", subject=APPLIANCE + SCOPE + NAME),
    spec(T.CERTIFICATE_PROFILE,
         "The profiles that decide how a presented certificate is validated - which CAs are "
         "trusted, and whether revocation is checked.",
         subject=APPLIANCE + SCOPE + NAME),
    spec(T.CERTIFICATE,
         "The certificates held on the firewall: who issued each, how strong its key is, and what "
         "signed it.",
         subject=APPLIANCE + SCOPE + NAME,),
    spec(T.AUTHENTICATION_PROFILE,
         "How administrators and users are authenticated: the identity service behind each "
         "profile, its lockout settings and who it admits.",
         subject=APPLIANCE + SCOPE + NAME,),
    spec(T.AUTHENTICATION_SEQUENCE,
         "The ordered fallbacks tried when one authentication profile does not answer.",
         subject=APPLIANCE + SCOPE + NAME,),
    spec(T.PASSWORD_PROFILE,
         "Per-account password rules, which override the firewall-wide policy for the accounts "
         "they are bound to.",
         subject=APPLIANCE + NAME,),
    spec(T.SECURITY_PROFILE,
         "The anti-spyware, vulnerability and antivirus profiles, and what each one blocks.",
         subject=VSYS_SCOPED + KIND + NAME + (
             # Antivirus has no severity verdict and the severity columns read n/a for it, so
             # without this an antivirus finding would land on a tab that says nothing about
             # why it fired.
             ("Decoders not blocking", 24, True,
              lambda profile, _p: DECODER_COVERAGE.read(profile), "has_non_blocking_decoder"),
             ("Inline ML not blocking", 26, True,
              lambda profile, _p: ML_COVERAGE.read(profile), "has_non_blocking_ml_model"),
             ("App overrides not blocking", 30, True,
              lambda profile, _p: APP_OVERRIDE_COVERAGE.read(profile),
              "has_non_blocking_application_override"),),
         value_readers={"has_non_blocking_decoder": DECODER_COVERAGE,
                        "has_non_blocking_ml_model": ML_COVERAGE,
                        "has_non_blocking_application_override": APP_OVERRIDE_COVERAGE},
         appliance_of=lambda obj: None,
         subject_select_related=("enforcement_point__appliance_group",
                                 "enforcement_point__appliance", "appliance_group"),
         subject_prefetch=("enforcement_point__appliance_group__appliances", "decoders", "ml_models",
                           "application_overrides")),
    spec(T.ADMIN_USER,
         "The administrator accounts on each firewall: what each may do, and what it authenticates "
         "with.",
         subject=APPLIANCE + NAME,),
    spec(T.SERVER_PROFILE,
         "The identity services the firewall authenticates against - LDAP, RADIUS, TACACS+, "
         "Kerberos and SAML - and how it connects to each.",
         subject=APPLIANCE + SCOPE + KIND + NAME),
)


SPEC_BY_TYPE = {sheet_spec.control_types[0]: sheet_spec for sheet_spec in SPECS}


def writer(control_type):
    """The `write_sheet(build)` for one domain, so `build_workbook` can place its tab in the
    run's own order rather than taking these fifteen as a block."""
    sheet_spec = SPEC_BY_TYPE[control_type]

    def write_sheet(build) -> SheetInfo:
        return findings_sheet.write_sheet(build, sheet_spec)

    write_sheet.__name__ = f"write_{sheet_spec.sheet_title.lower().replace(' ', '_')}"
    return write_sheet
