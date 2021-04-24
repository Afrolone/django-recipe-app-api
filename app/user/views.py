from rest_framework import generics, authentication, permissions, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from rest_framework.views import APIView
from rest_framework.response import Response
from user.serializers import UserSerializer, AuthTokenSerializer, ResetPasswordSerializer, SetNewPasswordSerializer
from core.models import User
import jwt
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site 
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, smart_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode

import logging

logger = logging.getLogger(__name__)
print("views.py")

class CreateUserView(generics.GenericAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer

    logger.log(msg ='MESSAGE VIEWS', level = 20)
    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site=get_current_site(request).domain
        relativeLink = reverse('user:email_verify')
        absurl = 'http://'+current_site+relativeLink+"?token="+str(token)
        email_body='Hi '+user.name+' Use link below to verify email \n'+absurl
        data = {'email_body':email_body, 'to_email':user.email, 'email_subject': 'Verify your email'}

        Util.send_email(data)

        return Response(user_data, status = status.HTTP_201_CREATED)


class CreateTokenView(ObtainAuthToken):
    """Create a new auth token for user"""
    serializer_class = AuthTokenSerializer
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES


class ManageUserView(generics.RetrieveUpdateDestroyAPIView):
    """Manage the authenticated user"""
    serializer_class = UserSerializer
    authentication_classes = [authentication.TokenAuthentication, ]
    permission_classes = [permissions.IsAuthenticated, ]
    queryset = User.objects.all()

    def get_object(self):
        """Retrieve and return authentication user"""
        return self.request.user


class VerifyEmailView(generics.GenericAPIView):
    """Verify the user by email"""

    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
            user.save()
            return Response({'email': 'Successfully activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(generics.GenericAPIView):
    """Change the password for the authenticated user"""
    # TODO user reset via email!!!
    #serializer_class = UserSerializer
    #authentication_classes = [authentication.TokenAuthentication, ]
    #permission_classes = [permissions.IsAuthenticated, ]
    serializer_class = ResetPasswordSerializer
    print("reset password view")

    def post(self, request):
        data={'request': request, 'data': request.data}
        serializer=self.serializer_class(data=data)

        email = request.data['email']

        print("CURRENT email " +email)

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            #uidb64=urlsafe_base64_encode(smart_bytes(user.id))
            uidb64=urlsafe_base64_encode(smart_bytes(user.id)).decode()
            token= PasswordResetTokenGenerator().make_token(user)
            print("CURRENT ID " +str(user.id))
            current_site=get_current_site(
                request=request).domain
            relativeLink = reverse(
                'user:password-reset-confirm',
                kwargs = {'uidb64': uidb64, 'token': token})
            absurl = 'http://'+current_site+relativeLink
            email_body='Hello, \n  Use link below to reset password \n'+absurl
            data = {'email_body':email_body, 'to_email':user.email, 'email_subject': 'Reset your password'}

            Util.send_email(data)

        return Response({'success': 'We have sent you a link to reset your password!'}, status=status.HTTP_200_OK )


class PasswordTokenCheckAPI(generics.GenericAPIView):
    def get(self, request, uidb64, token):
        
        try:
            id=smart_str(urlsafe_base64_decode(uidb64).decode())
            user=User.objects.get(id=id)

            logger.debug("PasswordTokenCheckAPI")
            logger.debug("ID:" + str(id))
            logger.debug("UIDB64:" + str(uidb64))

            if not PasswordResetTokenGenerator().check_token(user, token):
                return Response({'error':'Token is not valid, please request a new one'},
                status=status.HTTP_401_UNAUTHORIZED)

            return Response({'success':True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token':token},
            status=status.HTTP_200_OK)

        except DjangoUnicodeDecodeError as identifier:
            return Response({'error':'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)

class SetNewPasswordAPIView(generics.GenericAPIView):
    serializer_class=SetNewPasswordSerializer

    def patch(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message':'Password reset success'}, status=status.HTTP_200_OK)