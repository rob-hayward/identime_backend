# serializers.py

from rest_framework import serializers


class RegistrationChallengeSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    # Add other fields as required by your WebAuthn implementation


class RegistrationResponseSerializer(serializers.Serializer):
    credential_id = serializers.CharField()
    public_key = serializers.CharField()
    sign_count = serializers.IntegerField()
    # Add other fields as required by your WebAuthn implementation


class AuthenticationChallengeSerializer(serializers.Serializer):
    # Include any fields that might be needed to initiate an authentication request
    # For example, a username field if you're identifying the user first
    username = serializers.CharField(max_length=150)


class AuthenticationResponseSerializer(serializers.Serializer):
    # The structure of this serializer should match the JSON structure of the response you expect from the client
    credential_id = serializers.CharField()
    authenticator_data = serializers.CharField()
    client_data_json = serializers.CharField()
    signature = serializers.CharField()
    user_handle = serializers.CharField(required=False)  # Optional, based on your setup
    # Add any other fields as per the response structure
