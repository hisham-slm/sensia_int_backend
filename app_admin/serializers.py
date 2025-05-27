from django.forms import fields
from rest_framework import serializers
from rest_framework.serializers import ModelSerializer
from .models import Admin, Comment


class AdminSerializer(serializers.ModelSerializer):
    class Meta:
        model = Admin
        fields = ["id", "email", "role"]


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ["id", "content", "has_access"]
