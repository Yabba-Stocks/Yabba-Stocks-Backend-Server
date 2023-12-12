# Third party imports.
from rest_framework import serializers

# In project imports.
from .models import User


class RegisterSerializer(serializers.ModelSerializer):
    """Serailizers for our User first time registration"""

    confirm_password = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "password",
            "confirm_password",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def validate(self, attrs):
        email = attrs.get("email", "")

        if email:
            email_exists = User.objects.filter(email=email).exists()
            if email_exists:
                raise serializers.ValidationError("Email has already been used")
        else:
            raise serializers.ValidationError("email: email field can not be empty")

        return super().validate(attrs)

    def create(self, validated_data):
        user = User.objects.create(
            email=validated_data["email"],
        )

        user.set_password(validated_data["password"])
        user.save()

        return user

class VerifyOTPSerializer(serializers.Serializer):
    otp = serializers.CharField()


class ResendOTPSerializer(serializers.Serializer):
    """Serailizers for resending OTP to our users."""

    email = serializers.CharField()
    id = serializers.IntegerField()

    class Meta:
        model = User
        fields = ["id", "email"]


class ForgotPasswordSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ["email"]


class ResetPasswordSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(max_length=50, min_length=6)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2 = serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ("otp", "password", "password2")
