"""Forms for assessment-facing CRUD surfaces."""

from django import forms

from assessments.models import Control, ControlQuery
from assessments.search.compiler import parse_search_payload
from assessments.search.exceptions import SearchSyntaxError


FORM_CONTROL_CLASS = (
    "border border-slate-200 bg-white px-3 text-sm text-slate-800 "
    "placeholder:text-slate-400 focus:border-blue-300 focus:outline-none "
    "focus:ring-2 focus:ring-blue-500/20"
)


class ControlForm(forms.ModelForm):
    class Meta:
        model = Control
        fields = [
            "control_id",
            "name",
            "control_type",
            "description",
            "rationale",
            "audit",
            "remediation",
            "default_severity",
            "implementation_version",
            "is_active",
        ]
        widgets = {
            "control_id": forms.TextInput(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS} font-mono",
                }
            ),
            "name": forms.TextInput(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS}",
                }
            ),
            "control_type": forms.Select(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS}",
                }
            ),
            "description": forms.Textarea(
                attrs={
                    "class": f"min-h-24 py-2 {FORM_CONTROL_CLASS}",
                }
            ),
            "rationale": forms.Textarea(
                attrs={
                    "class": f"min-h-24 py-2 {FORM_CONTROL_CLASS}",
                }
            ),
            "audit": forms.Textarea(
                attrs={
                    "class": f"min-h-28 py-2 {FORM_CONTROL_CLASS}",
                }
            ),
            "remediation": forms.Textarea(
                attrs={
                    "class": f"min-h-28 py-2 {FORM_CONTROL_CLASS}",
                }
            ),
            "default_severity": forms.Select(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS}",
                }
            ),
            "implementation_version": forms.TextInput(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS}",
                }
            ),
        }


class ControlQueryForm(forms.ModelForm):
    class Meta:
        model = ControlQuery
        fields = [
            "control",
            "name",
            "short_description",
            "is_baseline",
            "adjusted_severity",
            "is_active",
            "canonical_query",
        ]
        widgets = {
            "control": forms.Select(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS}",
                }
            ),
            "name": forms.TextInput(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS}",
                }
            ),
            "short_description": forms.TextInput(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS}",
                }
            ),
            "adjusted_severity": forms.Select(
                attrs={
                    "class": f"h-8 {FORM_CONTROL_CLASS}",
                }
            ),
            "canonical_query": forms.Textarea(
                attrs={
                    "class": "min-h-72 w-full border border-slate-300 bg-white px-3 py-2 "
                    "font-mono text-[12px] text-slate-900 focus-visible:outline-hidden "
                    "focus-visible:ring-2 focus-visible:ring-blue-500/20",
                    "rows": 18,
                }
            ),
        }

    def __init__(self, *args, control=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.control = control
        self.fields["short_description"].label = "Description"
        self.fields["adjusted_severity"].required = False

    def clean_canonical_query(self):
        value = self.cleaned_data["canonical_query"]
        try:
            if isinstance(value, dict):
                payload = value
            else:
                payload = parse_search_payload(value)
        except SearchSyntaxError as exc:
            raise forms.ValidationError(str(exc)) from exc

        if payload is None:
            raise forms.ValidationError("Canonical query JSON is required.")
        return payload

    def clean(self):
        cleaned_data = super().clean()
        if cleaned_data.get("is_baseline"):
            cleaned_data["adjusted_severity"] = None
        return cleaned_data
