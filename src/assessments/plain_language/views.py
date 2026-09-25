"""Views for plain-language assessment workflows."""

from __future__ import annotations

from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic.edit import FormView

from assessments.configuration_results import query_results_url
from assessments.models import ConfigurationSearchState
from assessments.plain_language.forms import PlainLanguageSecurityRuleQueryForm
from assessments.plain_language.security_rules.exceptions import (
    PlainLanguageSecurityRuleQueryError,
)
from assessments.plain_language.security_rules.translator import (
    translate_plain_language_security_rule_query,
)


#: Where a translated prompt lands. The security rules page had it until 2026-09-25; the
#: explorer's Policies > Security is the same query over the same model, and it is the page
#: that survives.
RULE_MODEL = "integrations.SecurityRule"


def builder_url(search_state_token: str = "") -> str:
    url = f"{query_results_url({'model': RULE_MODEL})}?edit_search=1"
    if search_state_token:
        return f"{url}&search_state={search_state_token}"
    return url


class PlainLanguageSecurityRuleQueryView(FormView):
    template_name = "assessments/plain_language/security_rule_query_form.html"
    form_class = PlainLanguageSecurityRuleQueryForm

    def get_initial(self):
        initial = super().get_initial()
        search_state_token = self.request.GET.get("search_state", "").strip()
        if not search_state_token:
            return initial

        search_state = get_object_or_404(ConfigurationSearchState, token=search_state_token)
        if search_state.query_text:
            initial["request_text"] = search_state.query_text
        return initial

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["builder_url"] = builder_url(
            self.request.GET.get("search_state", "").strip())
        return context

    def form_valid(self, form):
        request_text = form.cleaned_data["request_text"]
        try:
            translation = translate_plain_language_security_rule_query(request_text)
        except PlainLanguageSecurityRuleQueryError as exc:
            form.add_error(None, str(exc))
            return self.form_invalid(form)

        # `query_text` is what makes the round trip work: the explorer offers "Edit prompt"
        # when the applied state carries one, which is the only way back to this page with the
        # words that produced the query.
        search_state = ConfigurationSearchState.objects.create(
            model_label=RULE_MODEL,
            query_text=request_text,
            canonical_query=translation.canonical_query,
        )
        return HttpResponseRedirect(builder_url(str(search_state.token)))
