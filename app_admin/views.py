from django.shortcuts import render
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.status import (
    HTTP_200_OK,
    HTTP_201_CREATED,
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_404_NOT_FOUND,
    HTTP_500_INTERNAL_SERVER_ERROR,
)
from django.contrib.auth.hashers import check_password, make_password
from rest_framework_simplejwt.tokens import RefreshToken
import json
from users.models import User
from .models import Admin, Comment
from users.serializers import UserSerializer
from .serializers import CommentSerializer
from rest_framework.decorators import api_view, permission_classes
from django.core.mail import send_mail


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

    if not email or not password:
        return Response(
            {"message": "No credentials submitted"}, status=HTTP_400_BAD_REQUEST
        )

    try:
        admin = Admin.objects.get(email=email)
    except Admin.DoesNotExist:
        return Response({"message": "No admin found"}, status=HTTP_404_NOT_FOUND)

    admin_password = admin.password
    is_password_correct = check_password(admin_password, password)

    # if not is_password_correct:
    #     return Response(
    #         {"message": "wrong password or email"}, status=HTTP_401_UNAUTHORIZED
    #     )

    refresh = RefreshToken.for_user(admin)

    return Response(
        {
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "admin_id": admin.id,
            "role": admin.role,  # optional, if you store role info
        },
        status=HTTP_200_OK,
    )


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def create_user(request):
    requested_by = request.user
    try:
        admin = Admin.objects.get(email=requested_by)
    except Admin.DoesNotExist:
        return Response({"message": "Not an admin"}, status=HTTP_401_UNAUTHORIZED)

    if not admin.role == "admin":
        return Response({"message": "Not an admin"}, status=HTTP_401_UNAUTHORIZED)

    try:
        user_data = json.loads(request.body)

    except json.JSONDecodeError:
        return Response({"message": "Invalid JSON"}, status=HTTP_400_BAD_REQUEST)

    user_mail = user_data.get("email")
    username = user_data.get("username")

    if not user_mail or not username:
        return Response(
            {"message": "Please add user email and username"},
            status=HTTP_400_BAD_REQUEST,
        )
    user_password = f"{username}password@comment"
    hashed_password = make_password(user_password)
    user_data["password"] = hashed_password
    print(user_password)

    user_serializer = UserSerializer(data=user_data)

    if not user_serializer.is_valid():
        print(user_serializer.errors)
        return Response(user_serializer.errors, status=HTTP_400_BAD_REQUEST)

    user_serializer.save()
    response = {
        "username": user_serializer.data["username"],
        "email": user_serializer.data["email"],
        "role": user_serializer.data["role"],
    }

    # subject = "Welcome to our platform"
    # message = f"Hi {username}, \n nice to have you on our platform \n your login credentials is \n email: {user_serializer.data['email']}\n and password : {user_serializer.data['password']} \n Thank you"
    # send_mail(subject, message, None, user_serializer.data["email"])
    return Response(response, status=HTTP_201_CREATED)


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def add_comment(request):
    requested_by = request.user

    try:
        admin = Admin.objects.get(email=requested_by.email)
    except Admin.DoesNotExist:
        return Response({"message": "Not an admin"}, status=HTTP_401_UNAUTHORIZED)

    if admin.role != "admin":
        return Response({"message": "Not an admin"}, status=HTTP_401_UNAUTHORIZED)

    try:
        comment_data = json.loads(request.body)
    except json.JSONDecodeError:
        return Response({"message": "Invalid JSON"}, status=HTTP_400_BAD_REQUEST)

    comment_text = comment_data.get("comment")
    user_ids = comment_data.get("has_access")

    if not comment_text or not user_ids:
        return Response(
            {"message": "Please add the comment and users who has access"},
            status=HTTP_400_BAD_REQUEST,
        )

    valid_users = User.objects.filter(id__in=user_ids)
    if not valid_users.exists():
        return Response({"message": "No valid users found"}, status=HTTP_404_NOT_FOUND)

    comment = Comment.objects.create(content=comment_text)
    comment.has_access.set(valid_users)

    serializer = CommentSerializer(comment)
    return Response(serializer.data, status=HTTP_201_CREATED)
