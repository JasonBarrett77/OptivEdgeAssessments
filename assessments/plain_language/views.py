"""Views for plain-language assessment workflows."""

from __future__ import annotations

from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic.edit import FormView

from assessments.models import SecurityRuleSearchState
from assessments.plain_language.forms import PlainLanguageSecurityRuleQueryForm
from assessments.plain_language.security_rules.exceptions import (
    PlainLanguageSecurityRuleQueryError,
)
from assessments.plain_language.security_rules.translator import (
    translate_plain_language_security_rule_query,
)


class PlainLanguageSecurityRuleQueryView(FormView):
    template_name = "assessments/plain_language/security_rule_query_form.html"
    form_class = PlainLanguageSecurityRuleQueryForm

    def get_initial(self):
        initial = super().get_initial()
        search_state_token = self.request.GET.get("search_state", "").strip()
        if not search_state_token:
            return initial

        search_state = get_object_or_404(SecurityRuleSearchState, token=search_state_token)
        if search_state.query_text:
            initial["request_text"] = search_state.query_text
        return initial

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        search_state_token = self.request.GET.get("search_state", "").strip()
        if search_state_token:
            context["builder_url"] = (
                f"{reverse('assessment_security_rule_list')}?edit_search=1&search_state={search_state_token}"
            )
        else:
            context["builder_url"] = f"{reverse('assessment_security_rule_list')}?edit_search=1"
        return context

    def form_valid(self, form):
        request_text = form.cleaned_data["request_text"]
        try:
            translation = translate_plain_language_security_rule_query(request_text)
        except PlainLanguageSecurityRuleQueryError as exc:
            form.add_error(None, str(exc))
            return self.form_invalid(form)

        search_state = SecurityRuleSearchState.objects.create(
            query_text=request_text,
            canonical_query=translation.canonical_query,
        )
        return HttpResponseRedirect(
            f"{reverse('assessment_security_rule_list')}?edit_search=1&search_state={search_state.token}"
        )
