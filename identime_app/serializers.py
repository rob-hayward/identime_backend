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
    credential_id = serializers.CharField(max_length=200)  # Adjust max_length as needed
    authenticator_data = serializers.CharField(max_length=1024)  # Example length
    client_data_json = serializers.CharField(max_length=1024)  # Example length
    signature = serializers.CharField(max_length=1024)  # Example length
    user_handle = serializers.CharField(required=False, max_length=200)  # Optional, adjust max_length as needed
    raw_id = serializers.CharField(max_length=200)  # Adjust max_length as needed
    type = serializers.CharField(max_length=100)  # New field for type

    def validate_credential_id(self, value):
        # Add custom validation logic for credential_id if needed
        return value

    # Add other validate_<field_name> methods for custom field validation
