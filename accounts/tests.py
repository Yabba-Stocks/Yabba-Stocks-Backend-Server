from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient
from django.urls import reverse
from rest_framework import status

from .otp import otp_manager


class UserModelTest(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email='test@example.com',
            password='testpassword'
        )

    def test_create_user(self):
        self.assertEqual(self.user.email, 'test@example.com')
        self.assertTrue(self.user.check_password('testpassword'))

# Test Register endpoint.
class RegisterAPITest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.register_url = reverse('register')

    def test_register_user(self):
        data = {
            "email": "test@example.com",
            "password": "testpassword",
            "confirm_password": "testpassword",
        }
        response = self.client.post(self.register_url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(get_user_model().objects.count(), 1)
        self.assertEqual(get_user_model().objects.get().email, 'test@example.com')
        self.assertTrue('data' in response.data)

    def test_register_user_with_existing_email(self):
        get_user_model().objects.create_user(
            email='existing@example.com', password='existingpassword'
        )

        data = {
            "email": "existing@example.com",
            "password": "newpassword",
            "confirm_password": "newpassword",
        }

        response = self.client.post(self.register_url, data, format='json')

        # Print the response content for debugging purposes
        print(response.content)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        
        # Update the assertion based on the actual error message in response.data
        self.assertTrue('user with this email already exists' in str(response.data))


# Test EmailVerify Endpoint.
class EmailVerifyOTPTest(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.verify_otp_url = reverse('verify_otp')

        # Create a user and generate an OTP for testing
        self.user = get_user_model().objects.create_user(
            email='test@example.com',
            password='testpassword'
        )
        self.otp = otp_manager.create_otp(user_id=str(self.user.id))

    def test_email_verify_otp_valid_data(self):
        data = {
            "otp": self.otp,
        }

        response = self.client.post(self.verify_otp_url, data, format='json')

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue('Account is verified' in response.data.get('Account is verified', ''))

        # Verify that the user is marked as verified and active
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_verified)
        self.assertTrue(self.user.is_active)

    def test_email_verify_otp_invalid_data(self):
        # Use an incorrect OTP to simulate an invalid request
        data = {
            "otp": "invalidotp",
        }

        response = self.client.post(self.verify_otp_url, data, format='json')
        print(response.content)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('Invalid or expired OTP' in response.data.get('error', ''))

    def test_email_verify_otp_missing_otp(self):
        # Omitting the OTP field to simulate a missing OTP in the request
        data = {}

        response = self.client.post(self.verify_otp_url, data, format='json')
        print(response.content)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue('otp' in response.data.get('non_field_errors', []))
