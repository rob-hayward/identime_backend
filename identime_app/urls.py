# identime_app/urls.py

from django.urls import path
from .views import RegistrationChallengeView, RegistrationResponseView

urlpatterns = [
    path('webauthn/register/challenge/', RegistrationChallengeView.as_view(), name='webauthn-register-challenge'),
    path('webauthn/register/response/', RegistrationResponseView.as_view(), name='webauthn-register-response'),
    # Add other URLs as needed
]
