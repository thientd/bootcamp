from django.db import models
from django.template.defaultfilters import slugify
from django.contrib.auth.models import User
from django.urls import reverse


class InfoPost(models.Model):
    title = models.CharField(max_length=255)
    author = models.TextField()
    total_cm = models.CharField(max_length=255)
    total_like = models.CharField(max_length=255)
    created_on = models.DateTimeField(auto_now_add=True)
    tag = models.CharField(max_length=255)
    id = models.AutoField(primary_key=True)
