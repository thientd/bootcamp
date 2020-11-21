"""CTF2 URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from vul_web.views import homePageView
from vul_web.views import getInfoPost
from vul_web.views import gComment
from vul_web.views import sPost
from vul_web.views import sPost_process_new_post
from vul_web.views import show_post_detail
from vul_web.views import downloadImage
from vul_web.views import login
from vul_web.views import resetpass
from vul_web.views import feedback
from vul_web.views import processfeedback
from vul_web.views import register
from vul_web.views import processAccount
from vul_web.views import profile
from vul_web.views import processlogin
from vul_web.views import admin
from vul_web.views import processReset
from vul_web.views import processChangePass
from vul_web.views import display_reset_pass

urlpatterns = [
    path('admin/', admin),
    path('', homePageView),
    path('gPostInfo/', getInfoPost),
    path('gComment/', gComment),
    path('Post/', sPost),
    path(r'sPost_process_new_post/', sPost_process_new_post),
    path(r'show_post_detail/', show_post_detail),
    path(r'downloadImage/', downloadImage),
    path(r'login/', login),
    path(r'processlogin/', processlogin),
    path(r'resetpass/', resetpass),
    path(r'feedback/', feedback),
    path(r'processfeedback/', processfeedback),
    path(r'register/', register),
    path(r'processAccount/', processAccount),
    path(r'profile/', profile),
    path(r'processReset/', processReset),
    path(r'processChangePass/', processChangePass),
    path(r'display_reset_pass/', display_reset_pass),
]

