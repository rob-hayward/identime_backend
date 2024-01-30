# identime_app/views.py

import base64
import json
from django.http import JsonResponse
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.parsers import JSONParser
from django.core.mail import send_mail

# WebAuthn related imports
from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    options_to_json,
    verify_registration_response,
    verify_authentication_response,
    base64url_to_bytes,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

# Local app imports
from .serializers import AuthenticationResponseSerializer
from .models import WebAuthnCredential, UserProfile, EmailVerificationToken


def send_verification_email(request):
    data = JSONParser().parse(request)
    email = data.get('email')
    preferred_name = data.get('preferredName')

    user, created = User.objects.get_or_create(email=email, defaults={'username': email})
    if created:
        user.set_password(User.objects.make_random_password())
        user.save()

    user_profile, profile_created = UserProfile.objects.get_or_create(
        user=user, defaults={'preferred_name': preferred_name})
    if not profile_created:
        user_profile.preferred_name = preferred_name
        user_profile.save()

    token = EmailVerificationToken.objects.create(user=user)
    verification_link = f"http://localhost:3000/verify-email/{token.token}"
    email_subject = "Email Verification"
    email_body = f"Hi {preferred_name},\nPlease verify your email by clicking on this link: {verification_link}"

    send_mail(email_subject, email_body, 'from@example.com', [email], fail_silently=False)
    return JsonResponse({'status': 'success', 'detail': 'Verification email sent'})


def verify_email(request, token):
    try:
        verification_record = EmailVerificationToken.objects.get(token=token)
        user = verification_record.user
        user.is_active = True
        user.save()

        user_profile = UserProfile.objects.get(user=user)

        return JsonResponse({'status': 'success', 'email': user.email, 'preferredName': user_profile.preferred_name})
    except EmailVerificationToken.DoesNotExist:
        return JsonResponse({'error': 'Invalid or expired token.'}, status=400)
    except UserProfile.DoesNotExist:
        return JsonResponse({'error': 'User profile not found.'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


class RegistrationChallengeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # Parsing the request data.
        data = JSONParser().parse(request)
        username = data.get('username')

        # Error handling if username is not provided.
        if not username:
            return JsonResponse({'detail': 'Username is required'}, status=400)

        # Generating registration options using webauthn library.
        registration_options = generate_registration_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            rp_name=settings.WEBAUTHN_RP_NAME,
            user_id=username,
            user_name=username,
            user_display_name=username,
        )

        # Storing the challenge and username in the session.
        challenge_base64 = base64.b64encode(registration_options.challenge).decode('utf-8')
        request.session['webauthn_challenge'] = challenge_base64
        request.session['webauthn_username'] = username
        request.session.save()

        # Returning registration options as JSON response.
        registration_options_dict = json.loads(options_to_json(registration_options))
        return JsonResponse(registration_options_dict)


class RegistrationResponseView(APIView):
    # Allow access to this view without authentication
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # Retrieving the response data sent by the client
        response_data = request.data

        # Extracting the challenge and username from the session
        challenge_base64 = request.session.pop('webauthn_challenge', None)
        username = request.session.pop('webauthn_username', None)

        # Decoding the challenge if available
        challenge = base64.b64decode(challenge_base64) if challenge_base64 else None

        # Handling the case where username is not found in the session
        if not username:
            return JsonResponse({'detail': 'Username not found'}, status=400)

        try:
            # Verifying the registration response using the WebAuthn library
            registration_verification = verify_registration_response(
                credential=response_data,
                expected_challenge=challenge,
                expected_origin=settings.WEBAUTHN_ORIGIN,
                expected_rp_id=settings.WEBAUTHN_RP_ID,
                # Include other necessary parameters here
            )

            # Handling the case where the user already has WebAuthn credentials
            user = User.objects.filter(username=username).first()
            if user and WebAuthnCredential.objects.filter(user=user).exists():
                return JsonResponse({'detail': 'User already registered with WebAuthn'}, status=400)

            # Creating a new user if it does not exist
            if not user:
                user = User.objects.create(username=username)
                user.set_password(User.objects.make_random_password())
                user.save()

            # Creating WebAuthn credentials for the user
            WebAuthnCredential.objects.create(
                user=user,
                credential_id=registration_verification.credential_id,
                public_key=registration_verification.credential_public_key,
                sign_count=0
            )

            # Logging the user in
            login(request, user)
            return JsonResponse({"status": "success"})

        # Handling exceptions and returning an error response
        except Exception as e:
            return JsonResponse({"status": "error", "detail": str(e)}, status=400)


class AuthenticationChallengeView(APIView):
    # Allow any user to access this view
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # Parsing the JSON data from the request
        data = JSONParser().parse(request)
        username = data.get('username')

        # Validating the presence of a username
        if not username:
            return JsonResponse({'detail': 'Username is required'}, status=400)

        try:
            # Fetching the user and their stored WebAuthn credentials
            user = User.objects.get(username=username)
            stored_credentials = WebAuthnCredential.objects.filter(user=user)

            # Preparing credentials for the authentication challenge
            if stored_credentials.exists():
                allowed_credentials = [
                    PublicKeyCredentialDescriptor(
                        id=base64.urlsafe_b64encode(cred.credential_id).decode(),
                        type='public-key'
                    ) for cred in stored_credentials
                ]
            else:
                # Handling case where no credentials are found
                return JsonResponse({'detail': 'No credentials found'}, status=404)

        except User.DoesNotExist:
            # Handling case where user does not exist
            return JsonResponse({'detail': 'User not found'}, status=404)

        # Generating authentication options for the challenge
        authentication_options = generate_authentication_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            allow_credentials=allowed_credentials,
            # Add other required parameters here
        )

        # Storing the challenge in the session
        challenge_base64 = base64.urlsafe_b64encode(authentication_options.challenge).decode().rstrip("=")
        request.session['webauthn_challenge'] = challenge_base64

        # Converting options to JSON and sending it as a response
        options_dict = json.loads(options_to_json(authentication_options))
        return JsonResponse(options_dict)


class AuthenticationResponseView(APIView):
    # Allow access to any user for authentication
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        # Deserialize the incoming data
        response_data = request.data
        serializer = AuthenticationResponseSerializer(data=response_data)

        # Proceed only if the serializer is valid
        if serializer.is_valid():
            # Extract and decode the challenge stored in the session
            challenge_base64 = request.session.pop('webauthn_challenge', None)
            challenge = self._base64_urlsafe_decode(challenge_base64) if challenge_base64 else None

            try:
                # Convert the received data into bytes for processing
                credential_id_bytes = base64url_to_bytes(response_data['credential_id'])
                authenticator_data_bytes = base64url_to_bytes(response_data['authenticator_data'])
                client_data_json_bytes = base64url_to_bytes(response_data['client_data_json'])
                signature_bytes = base64url_to_bytes(response_data['signature'])

                # Retrieve the stored credential using the credential ID
                stored_credential = WebAuthnCredential.objects.get(credential_id=credential_id_bytes)
                user = stored_credential.user

                # Prepare data for verification
                response_data_for_verification = {
                    'id': bytes_to_base64url(credential_id_bytes),
                    'rawId': bytes_to_base64url(credential_id_bytes),
                    'response': {
                        'clientDataJSON': bytes_to_base64url(client_data_json_bytes),
                        'authenticatorData': bytes_to_base64url(authenticator_data_bytes),
                        'signature': bytes_to_base64url(signature_bytes),
                        'userHandle': response_data.get('user_handle', None)
                    },
                    'type': 'public-key'
                }

                # Verify the authentication response
                authentication_verification = verify_authentication_response(
                    credential=response_data_for_verification,
                    expected_challenge=challenge,
                    expected_rp_id=settings.WEBAUTHN_RP_ID,
                    expected_origin=settings.WEBAUTHN_ORIGIN,
                    credential_public_key=stored_credential.public_key,
                    credential_current_sign_count=stored_credential.sign_count,
                    require_user_verification=True,
                )

                # Update the stored credential's sign count
                stored_credential.sign_count = authentication_verification.new_sign_count
                stored_credential.save()

                # Log in the user and respond with success
                login(request, user)
                return JsonResponse({"status": "success"})

            except WebAuthnCredential.DoesNotExist:
                # Handle the case where the credential does not exist
                return JsonResponse({"status": "error", "detail": "Credential not found"}, status=404)
            except InvalidAuthenticationResponse as e:
                # Handle invalid authentication responses
                return JsonResponse({"status": "error", "detail": str(e)}, status=400)
            except KeyError as e:
                # Handle key errors in data processing
                return JsonResponse({"status": "error", "detail": str(e)}, status=400)
            except Exception as e:
                # Catch all other exceptions and return an error
                return JsonResponse({"status": "error", "detail": str(e)}, status=400)
        else:
            # Handle invalid serializer data
            return JsonResponse(serializer.errors, status=400)

    def _base64_urlsafe_decode(self, data):
        # Decoding utility for base64 data
        padding = '=' * ((4 - len(data) % 4) % 4)
        data_with_padding = data + padding
        try:
            return base64.urlsafe_b64decode(data_with_padding)
        except Exception as e:
            # Handle exceptions during base64 decoding
            raise e


class LogoutView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        logout(request)
        return JsonResponse({"status": "success", "message": "Logged out successfully"})

