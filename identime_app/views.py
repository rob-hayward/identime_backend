# views.py
import base64
import binascii
import json
import logging

from django.http import JsonResponse
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import login, logout
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.parsers import JSONParser

from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    options_to_json,
    verify_registration_response,
    verify_authentication_response,
    base64url_to_bytes,
)
from webauthn.helpers.exceptions import InvalidAuthenticationResponse
from webauthn.helpers.structs import PublicKeyCredentialDescriptor
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url

from .serializers import AuthenticationResponseSerializer
from .models import WebAuthnCredential

logger = logging.getLogger(__name__)


from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.authentication import SessionAuthentication, BasicAuthentication


@api_view(['POST'])
@permission_classes([AllowAny])
def simple_register(request):
    try:
        username = request.data.get('username')
        password = request.data.get('password')
        if not username or not password:
            return Response({'error': 'Username and password are required.'}, status=status.HTTP_400_BAD_REQUEST)

        user = User.objects.create_user(username=username, password=password)
        return Response({'status': 'success', 'message': 'User registered successfully.'})

    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def simple_login(request):
    username = request.data.get('username')
    password = request.data.get('password')
    user = authenticate(request, username=username, password=password)
    if user is not None:
        login(request, user)
        return Response({'status': 'success', 'message': 'Login successful.'})
    else:
        return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)

@api_view(['POST'])
@permission_classes([AllowAny])
def simple_logout(request):
    logout(request)
    return Response({'status': 'success', 'message': 'Logged out successfully.'})


class RegistrationChallengeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        data = JSONParser().parse(request)
        username = data.get('username')

        if not username:
            return JsonResponse({'detail': 'Username is required'}, status=400)

        # Generate registration options
        registration_options = generate_registration_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            rp_name=settings.WEBAUTHN_RP_NAME,
            user_id=username,  # Using the provided username as the user ID
            user_name=username,
            user_display_name=username,  # You can modify this as needed
            # Include other options as needed
        )

        # Convert challenge to Base64 string for storing in the session
        challenge_base64 = base64.b64encode(registration_options.challenge).decode('utf-8')
        logger.info(f"Challenge sent: {challenge_base64}")
        request.session['webauthn_challenge'] = challenge_base64
        request.session['webauthn_username'] = username
        request.session.save()
        logger.debug(f"Session Key after challenge set: {request.session.session_key}")

        # Convert options to JSON
        registration_options_dict = json.loads(options_to_json(registration_options))

        # Return the JSON response
        return JsonResponse(registration_options_dict)


class RegistrationResponseView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        response_data = request.data
        challenge_base64 = request.session.pop('webauthn_challenge', None)
        username = request.session.pop('webauthn_username', None)
        logger.info(f"Challenge expected: {challenge_base64}")
        logger.info(f"Username retrieved: {username}")
        challenge = base64.b64decode(challenge_base64) if challenge_base64 else None

        if not username:
            logger.error("Username not found in session")
            return JsonResponse({'detail': 'Username not found'}, status=400)

        try:
            # Verify the registration response
            registration_verification = verify_registration_response(
                credential=response_data,
                expected_challenge=challenge,
                expected_origin=settings.WEBAUTHN_ORIGIN,
                expected_rp_id=settings.WEBAUTHN_RP_ID,
                # ... other parameters ...
            )

            # Check if the user already exists and has WebAuthn credentials
            user = User.objects.filter(username=username).first()
            if user and WebAuthnCredential.objects.filter(user=user).exists():
                return JsonResponse({'detail': 'User already registered with WebAuthn'}, status=400)

            # Create the user if it does not exist
            if not user:
                user = User.objects.create(username=username)
                user.set_password(User.objects.make_random_password())
                user.save()
                logger.info(f"New user created: {user.username} (ID: {user.id})")
            else:
                logger.info(f"Existing user retrieved: {user.username} (ID: {user.id})")

            # Create WebAuthn credentials for the user
            WebAuthnCredential.objects.create(
                user=user,
                credential_id=registration_verification.credential_id,
                public_key=registration_verification.credential_public_key,
                sign_count=0
            )

            logger.info(f"Stored credential_id (raw_id) in database: Type: {type(registration_verification.credential_id)}, Value: {registration_verification.credential_id}")

            # Log the user in
            login(request, user)
            return JsonResponse({"status": "success"})

        except Exception as e:
            logger.error(f"Registration error: {e}")
            return JsonResponse({"status": "error", "detail": str(e)}, status=400)


class AuthenticationChallengeView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        data = JSONParser().parse(request)
        username = data.get('username')

        if not username:
            return JsonResponse({'detail': 'Username is required'}, status=400)

        try:
            user = User.objects.get(username=username)
            stored_credentials = WebAuthnCredential.objects.filter(user=user)

            if stored_credentials.exists():
                allowed_credentials = [
                    PublicKeyCredentialDescriptor(
                        id=base64.urlsafe_b64encode(cred.credential_id).decode(),
                        type='public-key'
                    ) for cred in stored_credentials
                ]
            else:
                return JsonResponse({'detail': 'No credentials found'}, status=404)

        except User.DoesNotExist:
            return JsonResponse({'detail': 'User not found'}, status=404)

        authentication_options = generate_authentication_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            allow_credentials=allowed_credentials,
            # Other parameters as needed
        )

        challenge_base64 = base64.urlsafe_b64encode(authentication_options.challenge).decode().rstrip("=")
        request.session['webauthn_challenge'] = challenge_base64

        options_dict = json.loads(options_to_json(authentication_options))

        # Logging the challenge options sent to the client
        logger.info(f"Authentication challenge options sent: {options_dict}")

        return JsonResponse(options_dict)


class AuthenticationResponseView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        logger.info("AuthenticationResponseView called")
        response_data = request.data
        logger.info(f"Received authentication response: {response_data}")

        serializer = AuthenticationResponseSerializer(data=response_data)
        if serializer.is_valid():
            logger.info("Serializer is valid")
            challenge_base64 = request.session.pop('webauthn_challenge', None)
            challenge = self._base64_urlsafe_decode(challenge_base64) if challenge_base64 else None

            try:
                # Convert Base64URL to bytes and log the conversion
                credential_id_bytes = base64url_to_bytes(response_data['credential_id'])
                authenticator_data_bytes = base64url_to_bytes(response_data['authenticator_data'])
                client_data_json_bytes = base64url_to_bytes(response_data['client_data_json'])
                signature_bytes = base64url_to_bytes(response_data['signature'])

                logger.info(f"Converted credential_id to bytes: {credential_id_bytes}")
                logger.info(f"Converted authenticator_data to bytes: {authenticator_data_bytes}")
                logger.info(f"Converted client_data_json to bytes: {client_data_json_bytes}")
                logger.info(f"Converted signature to bytes: {signature_bytes}")

                # Retrieve stored credential and log retrieval
                stored_credential = WebAuthnCredential.objects.get(credential_id=credential_id_bytes)
                user = stored_credential.user
                logger.info(f"Retrieved stored credential for user: {user.username}")

                # Prepare the data for verification and log the data structure
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
                logger.info(f"Prepared data for verification: {response_data_for_verification}")

                # Verify authentication response using the dictionary and log the process
                authentication_verification = verify_authentication_response(
                    credential=response_data_for_verification,
                    expected_challenge=challenge,
                    expected_rp_id=settings.WEBAUTHN_RP_ID,
                    expected_origin=settings.WEBAUTHN_ORIGIN,
                    credential_public_key=stored_credential.public_key,
                    credential_current_sign_count=stored_credential.sign_count,
                    require_user_verification=True,
                )
                logger.info(f"Verification result: {authentication_verification}")

                # Update stored credential and log the update
                stored_credential.sign_count = authentication_verification.new_sign_count
                stored_credential.save()
                logger.info("Stored credential sign count updated")

                # Log user login
                login(request, user)
                logger.info(f"User {user.username} logged in")

                return JsonResponse({"status": "success"})

            except WebAuthnCredential.DoesNotExist as e:
                logger.error("Credential not found", exc_info=e)
                return JsonResponse({"status": "error", "detail": "Credential not found"}, status=404)
            except InvalidAuthenticationResponse as e:
                logger.error("Invalid authentication response", exc_info=e)
                return JsonResponse({"status": "error", "detail": str(e)}, status=400)
            except KeyError as e:
                logger.error("KeyError caught in AuthenticationResponseView", exc_info=e)
                return JsonResponse({"status": "error", "detail": str(e)}, status=400)
            except Exception as e:
                logger.error("Exception caught in AuthenticationResponseView", exc_info=e)
                return JsonResponse({"status": "error", "detail": str(e)}, status=400)
        else:
            logger.error("Serializer errors", exc_info=True)
            return JsonResponse(serializer.errors, status=400)

    def _base64_urlsafe_decode(self, data):
        logger.info(f"Data before padding correction: {data}")
        padding = '=' * ((4 - len(data) % 4) % 4)
        data_with_padding = data + padding
        logger.info(f"Data with padding correction: {data_with_padding}")
        try:
            decoded_data = base64.urlsafe_b64decode(data_with_padding)
            logger.info(f"Decoded challenge: {decoded_data}")
            return decoded_data
        except Exception as e:
            logger.error(f"Error decoding Base64URL data", exc_info=e)
            raise e


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        logout(request)
        return JsonResponse({"status": "success", "message": "Logged out successfully"})

