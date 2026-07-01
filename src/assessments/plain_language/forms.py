"""Forms for plain-language assessment workflows."""

from __future__ import annotations

from django import forms

from assessments.forms import FORM_CONTROL_CLASS


class PlainLanguageSecurityRuleQueryForm(forms.Form):
    request_text = forms.CharField(
        label="Describe the security rule query",
        widget=forms.Textarea(
            attrs={
                "class": f"min-h-40 w-full py-3 {FORM_CONTROL_CLASS}",
                "placeholder": (
                    "Examples:\n"
                    "- Show rules from transit to internet where source matches 10.0.0.0/8\n"
                    "- Find rules whose destination address name contains sanctioned-saas\n"
                    "- Show disabled rules in perimeter vsys"
                ),
            }
        ),
        help_text=(
            "Describe the rule query in plain language. The app will translate it into "
            "canonical structured query JSON and open it in the existing security-rule builder."
        ),
    )

