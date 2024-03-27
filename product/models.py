import uuid
from django.db import models

from accounts.models import User


class BaseModel(models.Model):
    """Define abstract base model."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted = models.BooleanField(default=False)

    class Meta:
        abstract = True


class Product(BaseModel):
    user = models.ForeignKey(to=User, on_delete=models.CASCADE)
    preview = models.CharField(max_length=155, null=True)
    title = models.CharField(max_length=250, null=True)
    preview = models.CharField(max_length=255, null=True)
    price = models.FloatField(null=True)
    story = models.TextField(null=True)
    cover_image = models.CharField(max_length=255, null=True)
    video_or_sound = models.CharField(max_length=255, null=True)
