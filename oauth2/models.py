from django.db import models
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    auth_provider = models.CharField(max_length=255)
    externaluserid = models.CharField(max_length=255, unique=True)


class UserToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.PROTECT)
    token = models.CharField(max_length=255, unique=True)
