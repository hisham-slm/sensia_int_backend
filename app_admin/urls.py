from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.login, name="login"),
    path("create_user/", views.create_user, name="create_user"),
    path("comment/", views.add_comment, name="add_comment"),
]
