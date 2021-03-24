import os

from django.core.mail import EmailMessage
from django.http import HttpResponsePermanentRedirect


class Util:
    @staticmethod
    def send_email(data):
        email = EmailMessage(subject=data['email_subject'],
                             body=data['email_body'],
                             to=data['recipient'])
        email.send()


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [os.environ.get('APP_SCHEME'), 'http', 'https']
