from django.shortcuts import render
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.contrib.auth.hashers import check_password, make_password
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from rest_framework_simplejwt.tokens import RefreshToken
import json
from .models import User
from app_admin.models import Comment
from .serializers import UserSerializer
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response


@api_view(["POST"])
@permission_classes([])
@permission_classes([AllowAny])
def login(request):
    try:
        user_data = json.loads(request.body)
    except json.JSONDecodeError:
        return Response({"message": "Invalid JSON"}, status=HTTP_400_BAD_REQUEST)

    email = user_data.get("email")
    password = user_data.get("password")

    print(email, password)
    if not email or not password:
        return Response(
            {"message": "No credentials submitted"}, status=HTTP_400_BAD_REQUEST
        )

    try:
        user = User.objects.get(email=email)
        print(user)
    except User.DoesNotExist:
        return Response({"message": "No User found"}, status=HTTP_404_NOT_FOUND)

    user_password = user.password
    is_password_correct = check_password(password, user_password)

    if not is_password_correct:
        return Response(
            {"message": "wrong password or email"}, status=HTTP_401_UNAUTHORIZED
        )

    refresh = RefreshToken.for_user(user)

    return Response(
        {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "admin_id": user.id,
            "role": user.role,  # optional, if you store role info
        },
        status=HTTP_200_OK,
    )
