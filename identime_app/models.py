# models.py

from django.db import models
from django.contrib.auth.models import User


class WebAuthnCredential(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    credential_id = models.BinaryField(unique=True)
    public_key = models.BinaryField()
    sign_count = models.IntegerField()
    # Add any other necessary fields

