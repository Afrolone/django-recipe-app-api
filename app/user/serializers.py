from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers

from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework.exceptions import AuthenticationFailed

from core.models import User

import logging

logger = logging.getLogger(__name__)

class UserSerializer(serializers.ModelSerializer):
    """Serializer for the users objects"""

    class Meta:
        model = get_user_model()
        fields = ('email', 'password', 'name')
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}

    def create(self, validated_data):
        """Create a new user with encrypted password and return it"""
        return get_user_model().objects.create_user(**validated_data)

    def update(self, instance, validated_data):
        """Update a user, setting the password correctly and return it"""
        password = validated_data.pop('password', None)
        user = super().update(instance, validated_data)

        if password:
            user.set_password(password)
            user.save()

        return user


class AuthTokenSerializer(serializers.Serializer):
    """Serializer for the user authentication object"""
    email = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """Validate and authenticate the user"""
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password
        )
        if not user:
            msg = _('Unable to authenticate with provided credentials')
            raise serializers.ValidationError(msg, code='authentication')

        attrs['user'] = user
        return attrs


class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(min_length = 5)

    class meta:
        fields = ['email']

class SetNewPasswordSerializer(serializers.Serializer):
    print("setnewpasswordclass")
    password = serializers.CharField(
        min_length=6, max_length=64, write_only=True)
    token = serializers.CharField(
        min_length=1, write_only=True)
    uidb64 = serializers.CharField(
        min_length=1, write_only=True)

    class Meta:
        field=['password', 'token', 'uidb64']
    
    def validate(self, attrs):
        print("SER UIDB64 IS "+str(attrs.get('uidb64')))
        print(smart_str(urlsafe_base64_decode(attrs.get('uidb64')).decode()))
        print(User.objects.get(id=smart_str(urlsafe_base64_decode(attrs.get('uidb64')).decode())))
        try:
            password=attrs.get('password')
            token=attrs.get('token')
            uidb64=attrs.get('uidb64')

            print("SER UIDB64 IS "+str(uidb64))

            #id=force_str(urlsafe_base64_decode(uidb64).decode())
            id=smart_str(urlsafe_base64_decode(uidb64).decode())
            
            print("SER ID IS "+str(id))

            user=User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user,token):
                raise AuthenticationFailed('The reset link is invalid', 401)

            user.set_password(password)
            user.save()

            return (user)

        except Exception as e:
            print(e.message+' ' +e.args)
            raise AuthenticationFailed('The reset link is invalid', 401)

        return super().validate(attrs)

