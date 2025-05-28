from random import choice
from django.db import models
from django.contrib.postgres.fields import ArrayField


class User(models.Model):
    PAGE_CHOICES = [
        ("marketing", "Marketing"),
        ("sales", "Sales"),
        ("finance", "Finance"),
        ("operations", "Operations"),
    ]

    username = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    role = models.CharField(max_length=10, default="user")

    page_access = ArrayField(
        models.CharField(max_length=50, choices=PAGE_CHOICES),
        default=list,
        blank=True,
    )

    class Meta:
        db_table = "users"
