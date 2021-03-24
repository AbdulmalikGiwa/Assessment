from django.contrib.auth import authenticate
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from rest_framework.serializers import *
from rest_framework import serializers
from rest_framework_simplejwt.exceptions import AuthenticationFailed, TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User


class RegisterSerializer(ModelSerializer):
    password = serializers.CharField(max_length=50, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    # Modify create method to use custom create_user
    def create(self, validated_data):
        email = validated_data.pop('email')
        username = validated_data.pop('username')
        password = validated_data.pop('password')
        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.save()
        return user


class EmailVerificationSerializer(ModelSerializer):
    token = serializers.CharField()

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=255, min_length=3, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3, read_only=True)
    tokens = serializers.CharField(max_length=255, min_length=3, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attr):
        email = attr.get('email')
        password = attr.get('password')
        # print(email)
        # print(password)

        user = authenticate(email=email, password=password)

        # print(user)

        if not user:
            raise AuthenticationFailed('Invalid Login Parameters')
        if not user.is_active:
            raise AuthenticationFailed('Account has been disabled, please contact us for more info')
        if not user.is_verified:
            raise AuthenticationFailed('User is not verified')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.get_tokens()
        }


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length=2)

    class Meta:
        fields = ['email']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True, required=False)
    uidb64 = serializers.CharField(min_length=1, write_only=True, required=False)

    class Meta:
        fields = ['password', 'token', 'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            token = attrs.get('token')
            uidb64 = attrs.get('uidb64')

            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uid)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid 3', 401)

            user.set_password(password)
            user.save()

            return user

        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid 4', 401)


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': 'Token is expired or invalid'
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()

        except TokenError:
            self.fail('bad_token')
