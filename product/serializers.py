# Third party imports.
from rest_framework import serializers

from .models import Product


class ProductSerializers(serializers.Serializer):
    """Serailizers for yabbatocks products."""

    class Meta:
        model = Product
        fields = [
            "id",
            "preview",
            "title",
            "price",
            "story",
            "cover_image",
            "videp_or_sound"
        ]
