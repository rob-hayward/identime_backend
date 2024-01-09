# views.py

from webauthn import generate_registration_options, generate_authentication_options, options_to_json, \
    verify_registration_response, verify_authentication_response, base64url_to_bytes
from .serializers import AuthenticationResponseSerializer
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.parsers import JSONParser
from .models import WebAuthnCredential
import base64
import json
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
import logging

logger = logging.getLogger(__name__)


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
        request.session.save()  # Ensure the session is saved
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
            registration_verification = verify_registration_response(
                credential=response_data,
                expected_challenge=challenge,
                expected_origin=settings.WEBAUTHN_ORIGIN,
                expected_rp_id=settings.WEBAUTHN_RP_ID,
                # ... other parameters ...
            )

            user, created = User.objects.get_or_create(username=username)
            logger.info(f"User {'created' if created else 'retrieved'}: {user.username} (ID: {user.id})")

            if created:
                user.set_password(User.objects.make_random_password())
                user.save()

            WebAuthnCredential.objects.create(
                user=user,
                credential_id=registration_verification.credential_id,
                public_key=registration_verification.credential_public_key,
                sign_count=0
            )

            login(request, user)
            return JsonResponse({"status": "success"})
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return JsonResponse({"status": "error"}, status=400)


class AuthenticationChallengeView(APIView):
    def post(self, request, *args, **kwargs):
        # Optional: You may use AuthenticationChallengeSerializer here to process any input

        # Generate authentication options
        authentication_options = generate_authentication_options(
            rp_id=settings.WEBAUTHN_RP_ID,
            # other options as needed
        )

        # Store the challenge for later verification
        request.session['webauthn_challenge'] = authentication_options.challenge

        return JsonResponse(options_to_json(authentication_options))


class AuthenticationResponseView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = AuthenticationResponseSerializer(data=request.data)
        if serializer.is_valid():
            challenge = request.session.pop('webauthn_challenge', None)
            response_data = serializer.validated_data

            # Fetch the stored credential from the database
            stored_credential = WebAuthnCredential.objects.get(credential_id=response_data['credential_id'])

            try:
                # Verify the authentication response
                authentication_verification = verify_authentication_response(
                    credential=response_data,
                    expected_challenge=base64url_to_bytes(challenge),
                    expected_origin=settings.WEBAUTHN_ORIGIN,
                    expected_rp_id=settings.WEBAUTHN_RP_ID,
                    credential_public_key=stored_credential.public_key,
                    credential_current_sign_count=stored_credential.sign_count,
                    # other necessary parameters
                )

                # Update the sign_count in the database if needed
                stored_credential.sign_count = authentication_verification.new_sign_count
                stored_credential.save()

                # Complete the authentication process
                # For example, log in the user

                return JsonResponse({"status": "success"})
            except Exception as e:
                print(e)  # Log the exception for debugging
                return JsonResponse({"status": "error"}, status=400)
        else:
            return JsonResponse(serializer.errors, status=400)
