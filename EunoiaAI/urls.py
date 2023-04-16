from django.contrib import admin
from django.urls import path
from EunoiaAI.views import chat_page, upload_page, chat, upload_file
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", views.index, name="index"),
    path('chat-page/', chat, name='chat-page'),
    path('upload-page/', upload_page, name='upload_page'),
    path('chat/', chat, name='chat'),
    path('upload/', upload_file, name='upload_file'),
    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("callback", views.callback, name="callback"),
]