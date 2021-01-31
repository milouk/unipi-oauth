from django.db import models


class UserToken(models.Model):
    user_email = models.CharField(max_length=255, unique=True)
    token = models.CharField(max_length=255)
