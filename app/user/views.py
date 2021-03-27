from rest_framework import generics, authentication, permissions, status
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.settings import api_settings
from rest_framework.views import APIView
from rest_framework.response import Response
from user.serializers import UserSerializer, AuthTokenSerializer
from core.models import User
import jwt
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site 
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from django.urls import reverse


class CreateUserView(generics.GenericAPIView):
    """Create a new user in the system"""
    serializer_class = UserSerializer

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
    # Responsible for the ppost button(view)


class ManageUserView(generics.RetrieveUpdateDestroyAPIView):
    """Manage the authenticated user"""
    serializer_class = UserSerializer
    authentication_classes = [authentication.TokenAuthentication, ]
    permission_classes = [permissions.IsAuthenticated, ]
    queryset = User.objects.all()

    def get_object(self):
        """Retrieve and return authentication user"""
        return self.request.user


class VerifyEmail(generics.GenericAPIView):
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
