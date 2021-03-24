from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class BaseTest(TestCase):
    def setUp(self):
        self.register_url = reverse('register')
        self.login_url = reverse('login')
        self.password_reset = reverse('password-reset-complete')
        self.user = {
            'email': 'testemail@gmail.com',
            'username': 'username',
            'password': 'password',
        }
        self.user_invalid_email = {

            'email': 'test.com',
            'username': 'username',
            'password': 'password',

        }
        self.login = {
            'email': 'testemail@gmail.com',
            'password': 'password'
        }
        return super().setUp()


class RegisterTest(BaseTest):

    def test_can_register_user(self):
        response = self.client.post(self.register_url, self.user)
        self.assertEqual(response.status_code, 201)

    def test_cant_register_user_with_invalid_email(self):
        response = self.client.post(self.register_url, self.user_invalid_email)
        self.assertEqual(response.status_code, 400)

    def test_cant_register_user_with_taken_email(self):
        self.client.post(self.register_url, self.user)
        response = self.client.post(self.register_url, self.user)
        self.assertEqual(response.status_code, 400)


class LoginTest(BaseTest):

    def test_login_success(self):
        self.client.post(self.register_url, self.user)
        user = User.objects.get(email=self.user['email'])
        user.is_active = True
        user.is_verified = True
        user.save()
        response = self.client.post(self.login_url, self.login)
        self.assertEqual(response.status_code, 200)

    def test_cantlogin_with_no_username(self):
        response = self.client.post(self.login_url, {'password': 'password', 'username': ''})
        self.assertEqual(response.status_code, 400)

    def test_cantlogin_with_no_password(self):
        response = self.client.post(self.login_url, {'username': 'username', 'password': ''})
        self.assertEqual(response.status_code, 400)


class PasswordResetTest(BaseTest):
    def test_password_reset(self):
        self.client.post(self.register_url, self.user)
        user = User.objects.get(email=self.user['email'])
        user.is_active = True
        user.is_verified = True
        user.save()
        response = self.client.patch()
