from decouple import config

# Third party imports.
from rest_framework import generics
from django.contrib.auth import authenticate
from django.contrib.auth.hashers import make_password
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken


from .serializers import (
    RegisterSerializer,
    VerifyOTPSerializer,
    ResetPasswordSerializer,
    ResendOTPSerializer,
    ForgotPasswordSerializer,
)

from .models import User
from .otp import otp_manager
from .utils import send_email
from .tokens import create_jwt_pair_for_user
from permissions import IsVerifiedUser


class Register(generics.GenericAPIView):
    """
    Register handles the POST request of registering a user,
    It takes in email, password and password2 as payload
    and returns a validation email upon success.
    """

    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        if serializer.is_valid(raise_exception=True):
            if user["password"] != user["confirm_password"]:
                return Response(
                    data={"error": "Passwords do not match!"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            serializer.save()
            # Create and send OTP.
            otp = otp_manager.create_otp(user_id=str(serializer.data["id"]))
            msg = (
                "Welcome to YabbaStocks! To verify your account, enter this {}.".format(
                    otp
                )
            )
            subject = "YabbaStocks - Verify your email"
            sender = config("EMAIL_HOST_USER")
            password = config("EMAIL_HOST_PASSWORD")
            recipient = serializer.data["email"]

            send_email(
                subject=subject,
                body=msg,
                sender=sender,
                recipients=[recipient],
                password=password,
            )
            try:
                user_data = serializer.data
                response = {
                    "status": "success",
                    "message": "User Created Successfully. Check your email for an OTP",
                    "data": user_data,
                }
                return Response(data=response, status=status.HTTP_201_CREATED)
            except Exception as err:
                return Response(
                    {
                        "status": "fail",
                        "message": err,
                    },
                    status=status.HTTP_409_CONFLICT,
                )
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerifyOTP(generics.GenericAPIView):
    """
    EmailVerifyOTP handles the POST request of verifying a
    register user with valid email.
    """

    permission_classes = (AllowAny,)
    serializer_class = VerifyOTPSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        if serializer.is_valid(raise_exception=True):
            received_otp = serializer.data["otp"]

            # Validate otp.
            user_id = otp_manager.validate_user_otp(received_otp)

            if not user_id:
                return Response(
                    data={"error": "Invalid or expired OTP"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = User.objects.get(id=user_id)
            # Send welcome message to user.
            msg = "Welcome to YabbaStocks... Trade your digital assets safely. Thank you for choosing our platform!"
            recipient = user.email

            subject = "YabbaStocks - Welcome to YabbaStocks"
            sender = config("EMAIL_HOST_USER")
            password = config("EMAIL_HOST_PASSWORD")

            send_email(
                subject=subject,
                body=msg,
                sender=sender,
                recipients=[recipient],
                password=password,
            )
            if user:
                user.is_verified = True
                user.is_active = True
                user.save()

                return Response(
                    {"Success": "Account is verified"}, status=status.HTTP_200_OK
                )
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordVerifyOTP(generics.GenericAPIView):
    """
    PasswordVerifyOTP handles the POST request of verifying a
    register user with valid email address.
    """

    permission_classes = (AllowAny,)
    serializer_class = VerifyOTPSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        if serializer.is_valid(raise_exception=True):
            received_otp = serializer.data["otp"]

            # Validate otp.
            user_id = otp_manager.validate_user_otp(received_otp)

            if not user_id:
                return Response(
                    data={"error": "Invalid or expired OTP"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            user = User.objects.get(id=user_id)
            # Send password reset message to user.
            msg = "User is verified... You can now reset your password!."
            recipient = user.email

            subject = "YabbaStocks - Reset your password"
            sender = config("EMAIL_HOST_USER")
            password = config("EMAIL_HOST_PASSWORD")

            send_email(
                subject=subject,
                body=msg,
                sender=sender,
                recipients=[recipient],
                password=password,
            )
            if user:
                return Response(
                    {"Success": "Account is verified"}, status=status.HTTP_200_OK
                )
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ResendOTP(generics.GenericAPIView):
    """
    ResendOTP handles the POST request of resending an
    OTP to a user.
    """

    permission_classes = (AllowAny,)
    serializer_class = ResendOTPSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        if serializer.is_valid(raise_exception=True):
            # Generate otp.
            otp = otp_manager.create_otp(user_id=str(serializer.data["id"]))
            msg = (
                "Welcome aboard! To protect your account, please enter this {}.".format(
                    otp
                )
            )

            subject = "YabbaStocks - Welcome to YabbaStocks"
            sender = config("EMAIL_HOST_USER")
            password = config("EMAIL_HOST_PASSWORD")
            recipient = serializer.data["email"]

            send_email(
                subject=subject,
                body=msg,
                sender=sender,
                recipients=[recipient],
                password=password,
            )
            response = {
                "status": "success",
                "message": "Otp resent Successfully. Check your email for validation",
            }
            return Response(data=response, status=status.HTTP_200_OK)
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResendOTP(generics.GenericAPIView):
    """
    PasswordResendOTP handles the POST request of resending an
    OTP to a user after forgotpassword.
    """

    permission_classes = (AllowAny,)
    serializer_class = ResendOTPSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        if serializer.is_valid(raise_exception=True):
            # Generate otp.
            otp = otp_manager.create_otp(user_id=str(serializer.data["id"]))
            msg = "To reset your password, please enter this One Time Password {}.".format(
                otp
            )

            subject = "YabbaStocks - Reset your password"
            sender = config("EMAIL_HOST_USER")
            password = config("EMAIL_HOST_PASSWORD")
            recipient = serializer.data["email"]

            send_email(
                subject=subject,
                body=msg,
                sender=sender,
                recipients=[recipient],
                password=password,
            )
            response = {
                "status": "success",
                "message": "Otp resent Successfully. Check your email for validation",
            }
            return Response(data=response, status=status.HTTP_200_OK)
        else:
            return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    """
    LoginAPIView handles the POST request of logging in
    a verified user with valid login credentials.
    """

    permission_classes = [IsVerifiedUser]

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        user = authenticate(email=email, password=password)
        if user:
            # Create JWT tokens
            tokens = create_jwt_pair_for_user(user)

            response = {"message": "Login successful", "tokens": tokens}
            return Response(data=response, status=status.HTTP_200_OK)
        else:
            return Response(
                data={"error": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class ForgotPassword(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            email = user_data["email"]
            try:
                user = User.objects.get(email=email)
            except user.DoesNotExist:
                return Response(
                    data={"detail": "A user with this email does not exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            user_id = user.id
            # Create and send OTP.
            otp = otp_manager.create_otp(user_id=str(user_id))
            msg = "Enter this {} to verify your account and reset your password".format(
                otp
            )

            subject = "YabbaStocks - Rest your password"
            sender = config("EMAIL_HOST_USER")
            password = config("EMAIL_HOST_PASSWORD")

            send_email(
                subject=subject,
                body=msg,
                sender=sender,
                recipients=[email],
                password=password,
            )
            response = {
                "status": "success",
                "message": "Check your email for an OTP",
            }
            return Response(data=response, status=status.HTTP_201_CREATED)


class ResetPassword(generics.CreateAPIView):
    serializer_class = ResetPasswordSerializer

    def create(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user_data = serializer.validated_data

        otp = user_data["otp"]
        user_id = otp_manager.validate_user_otp(otp=otp)

        if not user_id:
            return Response(
                data={"error": "Invalid or expired OTP"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response(
                data={"error": "User not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if user_data["password"] != user_data["password2"]:
            return Response(
                data={"error": "Passwords do not match!"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        password = user_data["password"]
        user.password = make_password(password)

        # Retrieve existing tokens and blacklist them.
        user_token = request.data.get("refresh_token")
        if user_token:
            token = RefreshToken(user_token)
            token.blacklist()

        user.save()

        response = {"status": "Success!", "message": "Password reset successfully"}
        return Response(data=response, status=status.HTTP_200_OK)
