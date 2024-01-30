# identime_app/models.py
from django.db import models
from django.contrib.auth.models import User
import uuid


class UserProfile(models.Model):
    # Link to the User model with additional user information
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    preferred_name = models.CharField(max_length=100)


class EmailVerificationToken(models.Model):
    # Represents an email verification token for a user
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)


class WebAuthnCredential(models.Model):
    # Stores WebAuthn credentials for user authentication
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    credential_id = models.BinaryField(unique=True)
    public_key = models.BinaryField()
    sign_count = models.IntegerField()
