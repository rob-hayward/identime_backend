# identime_app/urls.py

from django.urls import path
from .views import RegistrationChallengeView, RegistrationResponseView, AuthenticationChallengeView, \
    AuthenticationResponseView, LogoutView, send_verification_email, verify_email

urlpatterns = [
    path('webauthn/register/challenge/', RegistrationChallengeView.as_view(), name='webauthn-register-challenge'),
    path('webauthn/register/response/', RegistrationResponseView.as_view(), name='webauthn-register-response'),
    path('webauthn/login/challenge/', AuthenticationChallengeView.as_view(), name='webauthn-login-challenge'),
    path('webauthn/login/response/', AuthenticationResponseView.as_view(), name='webauthn-login-response'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('send-verification-email/', send_verification_email, name='send_verification_email'),
    path('verify-email/<uuid:token>/', verify_email, name='verify_email'),
]
