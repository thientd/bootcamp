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


class Spost(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.TextField()
    phone = models.TextField()
    email = models.TextField()
    message = models.TextField()
    image_filename = models.TextField()
    title = models.TextField()


class Spost2(models.Model):
    id = models.CharField(max_length=255, primary_key=True)
    name = models.TextField()
    phone = models.TextField()
    email = models.TextField()
    message = models.TextField()
    image_filename = models.TextField()
    title = models.TextField()


class Spost3(models.Model):
    post_id = models.TextField()
    name = models.TextField()
    phone = models.TextField()
    email = models.TextField()
    message = models.TextField()
    image_filename = models.TextField()
    title = models.TextField()


class Spost4(models.Model):
    post_id = models.TextField()
    name = models.TextField()
    phone = models.TextField()
    email = models.TextField()
    message = models.TextField()
    image_filename = models.TextField()
    title = models.TextField()
    status = models.TextField()


class Feed(models.Model):
    name = models.TextField()
    email = models.TextField()
    message = models.TextField()


class User(models.Model):
    user_id = models.TextField()
    name = models.TextField()
    phone = models.TextField()
    email = models.TextField()
    password = models.TextField()


class resetpassword2(models.Model):
    user_id = models.TextField()
    status = models.TextField()
    token = models.TextField()
    timeout_token = models.TextField()


class FTP(models.Model):
    user_name = models.TextField()
    password = models.TextField()
    host = models.TextField()
    schedule = models.IntegerField()


class File_info(models.Model):
    file_name = models.TextField()
    hash = models.TextField()
    status = models.TextField()
    time_to_push = models.IntegerField()
