from django.db import models
from django.contrib.auth.models import User
from uuid import uuid4

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
    name = models.CharField(max_length=255)
    namespace = models.CharField(max_length=255, unique=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name