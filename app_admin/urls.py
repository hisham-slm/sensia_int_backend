from django.urls import path
from . import views

urlpatterns = [
    path("login/", views.login, name="login"),
    path("create_user/", views.create_user, name="create_user"),
    path("add_comment/", views.add_comment, name="add_comment"),
    path("get_comments/", views.get_comments, name="get_comments"),
    path("edit_comment/", views.edit_comment, name="edit_comment"),
    path("get_users/", views.get_users, name="get_users"),
    path("add_role/", views.add_role, name="add_role"),
]
