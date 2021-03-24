from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.utils.encoding import smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode
from rest_framework.exceptions import APIException
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView
from .serializers import *
from .models import *
from .utils import *
from decouple import config
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import jwt

# Create your views here.
description_string = "Email Verification Token \n This endpoint takes a post request of the token returned" \
                     "upon registration of a new user, although a link is returned on registration," \
                     "a GET to that link will also verify so you can just click on that "


# RegisterView to register new users
class RegisterView(GenericAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data

        user_for_token = User.objects.get(email=serializer.data['email'])
        token = RefreshToken.for_user(user_for_token).access_token
        user_data['token'] = str(token)

        current_site = get_current_site(request).domain
        relativeLink = reverse('verify-email')
        url = 'http://' + current_site + relativeLink + "?token=" + str(token)

        user_data['verification_link'] = url

        return Response(user_data, status=status.HTTP_201_CREATED)


# VerifyEmail class verifies user email and changes "is_verified" field to True
# It decodes token returned upon registration
class VerifyEmail(APIView):
    serializer_class = EmailVerificationSerializer
    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    # This decorator modifies the swagger endpoint to match te view
    @swagger_auto_schema(request_body=openapi.Schema(type=openapi.TYPE_OBJECT,
                                                     required=['token'],
                                                     properties={
                                                         'token': openapi.Schema(type=openapi.TYPE_STRING)
                                                     },
                                                     ),
                         operation_description=description_string)
    def post(self, request):
        token = request.data['token']
        try:
            decode_token = jwt.decode(token, options={"verify_signature": False})
            user = User.objects.get(id=decode_token['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({"message": "Email Verification Successful"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message": "The following error occurred: {}".format(e)},
                            status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.query_params.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY)
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        return Response(serializer.data, status=status.HTTP_200_OK, content_type='json')


class RequestPasswordReset(GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        email = request.data.get('email')

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)
            current_site = get_current_site(
                request=request).domain
            relativeLink = reverse('password-reset-complete')

            url = 'http://' + current_site + relativeLink + "?uidb64=" + uidb64 + "&token=" + token

            return Response({"reset_link": url}, status=status.HTTP_200_OK)

        else:
            return Response({"message": "Password Reset Failed"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SetNewPasswordAPIView(GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        try:
            token = request.query_params.get('token')
            uidb64 = request.query_params.get('uidb64')
            password = request.data.get('password')
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=uid)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid 2', 401)

            user.set_password(password)
            user.save()
        except KeyError:
            pass

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(GenericAPIView):
    serializer_class = LogoutSerializer

    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)
