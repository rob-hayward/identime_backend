# identime_app/urls.py

from django.urls import path
from .views import RegistrationChallengeView, RegistrationResponseView, AuthenticationChallengeView, \
    AuthenticationResponseView

urlpatterns = [
    path('webauthn/register/challenge/', RegistrationChallengeView.as_view(), name='webauthn-register-challenge'),
    path('webauthn/register/response/', RegistrationResponseView.as_view(), name='webauthn-register-response'),
    path('webauthn/login/challenge/', AuthenticationChallengeView.as_view(), name='webauthn-login-challenge'),
    path('webauthn/login/response/', AuthenticationResponseView.as_view(), name='webauthn-login-response'),
]
