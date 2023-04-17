from django.contrib import admin
from django.urls import path
from EunoiaAI.views import chat_page, upload_page, chat, upload_file
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", views.index, name="index"),
    path('chat-page/', chat_page, name='chat_page'),
    path('upload-page/', upload_page, name='upload_page'),
    path('chat/', chat, name='chat'),
    path('upload/', upload_file, name='upload_file'),
    path("accounts/login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("auth0-callback/", views.callback, name="callback"),
    path('manage-organization/', views.manage_organization, name='manage_organization'),
    path('manage-agent/', views.manage_agent, name='create_agent'),
    path('manage-agent/<uuid:agent_id>/', views.manage_agent, name='update_agent'),
    path('manage-user/', views.manage_user, name='manage_user'),
    path('manage-user/<int:user_id>/', views.manage_user, name='manage_user'),
    path('invite-user/', views.invite_user, name='invite_user'),
    path('dashboard/', views.dashboard, name='dashboard'),
]