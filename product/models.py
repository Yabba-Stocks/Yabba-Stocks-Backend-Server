from django.db import models

from accounts.models import User


class Product(models.Model):
    user = models.ForeignKey(to=User, on_delete=models.CASCADE)
    preview = models.CharField(max_length=155, null=True)
    title = models.CharField(max_length=250, null=True)
    price = models.FloatField(null=True)
    story = models.TextField(null=True)
    cover_image = models.CharField(max_length=155, null=True)
    video_or_sound = models.CharField(max_length=155, null=True)
