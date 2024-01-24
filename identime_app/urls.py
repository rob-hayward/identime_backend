# identime_app/urls.py

from django.urls import path
from .views import RegistrationChallengeView, RegistrationResponseView, AuthenticationChallengeView, \
    AuthenticationResponseView, LogoutView, simple_register, simple_login, simple_logout

urlpatterns = [
    path('webauthn/register/challenge/', RegistrationChallengeView.as_view(), name='webauthn-register-challenge'),
    path('webauthn/register/response/', RegistrationResponseView.as_view(), name='webauthn-register-response'),
    path('webauthn/login/challenge/', AuthenticationChallengeView.as_view(), name='webauthn-login-challenge'),
    path('webauthn/login/response/', AuthenticationResponseView.as_view(), name='webauthn-login-response'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('simple/register/', simple_register, name='simple-register'),
    path('simple/login/', simple_login, name='simple-login'),
    path('simple/logout/', simple_logout, name='simple-logout'),
]
