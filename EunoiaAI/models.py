from uuid import uuid4
from django.db import models
from django.contrib.auth.models import User

class Organization(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, related_name='owned_organizations')
    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True)
    api_key = models.CharField(max_length=255)
    api_secret = models.CharField(max_length=255)
    subscription_type = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)

    def __str__(self):
        return self.user.username

class Agent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    agentKey = models.CharField(max_length=255, blank=True, null=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    namespace = models.CharField(max_length=50, unique=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    primer_prompt = models.TextField(blank=True, null=True)
    company_name = models.CharField(max_length=255, blank=True, null=True)
    agent_display_name = models.CharField(max_length=255, blank=True, null=True)

    def __str__(self):
        return self.name
    
class APIKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    key = models.CharField(max_length=100, unique=True)
    status = models.CharField(max_length=10, default="active")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.key