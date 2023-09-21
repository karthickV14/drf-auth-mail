from django.shortcuts import render

# Create your views here.
# authentication/views.py
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authtoken.models import Token
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import TokenAuthentication
from django.contrib.auth import authenticate, login, logout
from .serializers import UserSerializer

from django.core.mail import send_mail


# ---------------------------------------------------------------------------------------------------------------------


class RegistrationAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                # Send a registration confirmation email
                subject = 'Registration Confirmation'
                message = 'Thank you for registering. Your registration is complete.'
                from_email = 'karthickvinayagamoorthi@gmail.com'
                recipient_list = [user.email]

                send_mail(subject, message, from_email, recipient_list)

                return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginAPIView(APIView):
    permission_classes = (AllowAny,)

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user:
            login(request, user)
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'token': token.key}, status=status.HTTP_200_OK)
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutAPIView(APIView):
    authentication_classes = (TokenAuthentication,)
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        request.auth.delete()
        logout(request)
        return Response({'detail': 'Successfully logged out'}, status=status.HTTP_200_OK)





