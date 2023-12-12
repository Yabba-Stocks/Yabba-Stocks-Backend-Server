from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils import timezone

from .user_manager import CustomUserManager


# User describes the database model for each user.
class User(AbstractBaseUser, PermissionsMixin):
    password = models.CharField(max_length=255, null=True)
    email = models.CharField(max_length=80, unique=True)
    is_verified = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    date_joined = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email


class OTP(models.Model):
    otp = models.CharField(max_length=6, null=True)
    user_id = models.IntegerField()
    expires_at = models.DateTimeField(auto_now_add=True)
