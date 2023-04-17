from django import forms
from .models import Organization, Agent

class CreateOrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ['name']

class CreateAgentForm(forms.ModelForm):
    class Meta:
        model = Agent
        fields = ['name']