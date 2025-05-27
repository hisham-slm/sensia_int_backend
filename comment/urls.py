from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("users/", include("users.urls")),
    path("superadmin/", include("app_admin.urls")),
]
