# views.py
import base64
import binascii
import json
import logging

from django.http import JsonResponse
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.auth import login
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.parsers import JSONParser

from webauthn import (
    generate_registration_options,
    generate_authentication_options,
    options_to_json,
    verify_registration_response,
    verify_authentication_response,
    base64url_to_bytes
)
from webauthn.helpers.structs import PublicKeyCredentialDescriptor

from .serializers import AuthenticationResponseSerializer
from .models import WebAuthnCredential

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
        logger.info(f"Received authentication response: {request.data}")

        serializer = AuthenticationResponseSerializer(data=request.data)
        if serializer.is_valid():
            logger.info("Serializer is valid")
            challenge_base64 = request.session.pop('webauthn_challenge', None)
            challenge = self._base64_urlsafe_decode(challenge_base64) if challenge_base64 else None
            response_data = serializer.validated_data

            if 'raw_id' not in response_data:
                logger.error("raw_id not found in authentication response")
                return JsonResponse({"status": "error", "detail": "raw_id not found"}, status=400)

            try:
                logger.info("Starting authentication verification process")
                raw_id_bytes = base64.urlsafe_b64decode(response_data['raw_id'].encode())
                logger.info(f"Decoded raw_id: Type: {type(raw_id_bytes)}, Value: {raw_id_bytes}")

                stored_credential = WebAuthnCredential.objects.get(credential_id=raw_id_bytes)
                user = stored_credential.user

                credential_data = {
                    'id': response_data['credential_id'],  # Base64 URL-encoded string
                    'rawId': response_data['raw_id'],                 # Bytes format
                    'response': {
                        'clientDataJSON': response_data['client_data_json'],      # Base64 URL-encoded string
                        'authenticatorData': response_data['authenticator_data'],  # Base64 URL-encoded string
                        'signature': response_data['signature']                    # Base64 URL-encoded string
                    },
                    'type': 'public-key'
                }

                logger.info("Before calling verify_authentication_response")
                logger.info(f"Credential data being sent for verification: {credential_data}")

                authentication_verification = verify_authentication_response(
                    credential=credential_data,
                    expected_challenge=challenge,
                    expected_origin=settings.WEBAUTHN_ORIGIN,
                    expected_rp_id=settings.WEBAUTHN_RP_ID,
                    credential_public_key=stored_credential.public_key,
                    credential_current_sign_count=stored_credential.sign_count,
                )

                logger.info("After calling verify_authentication_response")
                logger.info(f"Verification result: {authentication_verification}")

                stored_credential.sign_count = authentication_verification.new_sign_count
                stored_credential.save()

                logger.info("Logging in user")
                login(request, user)

                logger.info("Preparing to send JSON response")
                response_data = {"status": "success"}
                logger.info(f"JSON response data: {response_data}")

                return JsonResponse(response_data)

            except WebAuthnCredential.DoesNotExist:
                logger.error("Credential not found")
                return JsonResponse({"status": "error", "detail": "Credential not found"}, status=404)
            except Exception as e:
                logger.error(f"Exception caught in AuthenticationResponseView: {e}")
                return JsonResponse({"status": "error", "detail": str(e)}, status=400)
        else:
            logger.error(f"Serializer errors: {serializer.errors}")
            return JsonResponse(serializer.errors, status=400)

    def _base64_urlsafe_decode(self, data):
        logger.info(f"Decoding Base64URL data: {data}")
        padding_needed = (4 - len(data) % 4) % 4
        if padding_needed:
            data += '=' * padding_needed
        try:
            decoded_data = base64.urlsafe_b64decode(data)
            logger.info(f"Successfully decoded Base64URL data: {decoded_data}")
            return decoded_data
        except Exception as e:
            logger.error(f"Error decoding Base64URL data: {e}")
            raise e




# # AuthenticationResponseView with hardcoded data for testing and debugging purposes
# class AuthenticationResponseView(APIView):
#     permission_classes = [AllowAny]
#
#     def post(self, request, *args, **kwargs):
#         logger.info("AuthenticationResponseView called")
#
#         # Hardcoded known good data from the py_webauthn example
#         known_good_data = {
#             'credential_id': 'ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s',
#             'raw_id': 'ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s',
#             'authenticator_data': 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ',
#             'client_data_json': 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
#             'signature': 'iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw',
#             'user_handle': 'T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p'
#         }
#
#         # Convert Base64 URL-encoded string to bytes for raw_id with correct padding
#         raw_id_bytes = self._base64_urlsafe_decode(known_good_data['raw_id'])
#
#         credential_data = {
#             'id': known_good_data['credential_id'],  # Base64 URL-encoded string
#             'rawId': raw_id_bytes,                   # Bytes format
#             'response': {
#                 'clientDataJSON': known_good_data['client_data_json'],  # Base64 URL-encoded string
#                 'authenticatorData': known_good_data['authenticator_data'],  # Base64 URL-encoded string
#                 'signature': known_good_data['signature']  # Base64 URL-encoded string
#             },
#             'type': 'public-key'
#         }
#
#         # Expected challenge (needs to be converted from base64url to bytes)
#         expected_challenge = base64url_to_bytes(
#             "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
#         )
#
#         try:
#             authentication_verification = verify_authentication_response(
#                 credential=credential_data,
#                 expected_challenge=expected_challenge,
#                 expected_origin='http://localhost:5000',
#                 expected_rp_id='example.com',
#                 credential_public_key=base64url_to_bytes(
#                     "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
#                 ),
#                 credential_current_sign_count=0,
#                 require_user_verification=True
#             )
#
#             # Convert any byte data in the authentication_verification to a string
#             # This is just an example. You need to adapt it to your actual data.
#             if isinstance(authentication_verification, bytes):
#                 authentication_verification_str = base64.b64encode(authentication_verification).decode('utf-8')
#             else:
#                 authentication_verification_str = authentication_verification
#
#             # Dummy logic for user handling, as user is not fetched from DB in this test
#             user = None  # Replace with actual user lookup if needed
#             login(request, user)
#             return JsonResponse({"status": "success", "verification_result": authentication_verification_str})
#
#         except Exception as e:
#             logger.error(f"Authentication verification failed: {e}")
#             return JsonResponse({"status": "error", "detail": str(e)}, status=400)
#     def _base64_urlsafe_decode(self, data):
#         logger.info(f"Decoding Base64URL data: {data}")
#         padding = '=' * ((4 - len(data) % 4) % 4)
#         data += padding
#         decoded_data = base64.urlsafe_b64decode(data)
#         logger.info(f"Decoded data: {decoded_data}")
#         return decoded_data
