from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin, BaseUserManager
from rest_framework.views import *
from rest_framework_simplejwt.tokens import RefreshToken


# Create your models here.


class UserManager(BaseUserManager):
    def create_user(self, username, email, password=None):
        if username is None:
            raise TypeError("Username cannot be empty")
        if email is None:
            raise TypeError("Email cannot be empty")
        user = self.model(username=username, email=self.normalize_email(email))
        # user.set_password = password
        # user.save()
        return user

    def create_superuser(self, username, email, password=None):
        if password is None:
            raise TypeError("Password cannot be empty")

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()
        return user


AUTH_PROVIDERS = {'Facebook': 'Facebook', 'Google': 'Google',
                  'Twitter': 'Twitter', 'Email': 'Email'}


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(max_length=10, default=AUTH_PROVIDERS.get('Email'))

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    def get_tokens(self):
        authtokens = RefreshToken.for_user(self)
        return {
            'refresh': str(authtokens),
            'access': str(authtokens.access_token)
        }
