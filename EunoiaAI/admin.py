from django.contrib import admin
from .models import UserProfile, Organization, Agent

admin.site.register(UserProfile)
admin.site.register(Organization)
admin.site.register(Agent)
