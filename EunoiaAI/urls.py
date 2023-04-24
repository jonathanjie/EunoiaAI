from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", views.index, name="index"),
    path('agent/create/', views.manage_agent, name='create_agent'),
    path('agent/<str:agent_namespace>/', views.manage_agent, name='manage_agent'),
    path('agent/<str:agent_namespace>/chat/', views.chat_page, name='chat_page'),
    path('agent/<str:agent_namespace>/chat/<str:session_id>/get_conversation_history/', views.get_conversation_history, name='get_conversation_history'),
    path('agent/<str:agent_namespace>/chat/send-message/', views.send_message, name='send_message'),
    path('agent/<str:agent_namespace>/upload-page/', views.upload_page, name='upload_page'),
    path('agent/<str:agent_namespace>/upload-page/upload/', views.upload_file, name='upload_file'),
    path('api/agent/<str:agent_namespace>/send-message/', views.api_send_message, name='api_send_message'),
    path('api/agent/<str:agent_namespace>/upload-file/', views.api_upload_file, name='api_upload_file'),
    path("accounts/login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("auth0-callback/", views.callback, name="callback"),
    path('manage-organization/', views.manage_organization, name='manage_organization'),
    path('manage-user/', views.manage_user, name='manage_user'),
    path('manage-user/<int:user_id>/', views.manage_user, name='manage_user'),
    path('manage_keys/', views.manage_keys, name='manage_keys'),
    path('manage_keys/create_key/', views.create_key, name='create_key'),
    path('manage_keys/<str:key>/delete/', views.delete_key, name='delete_key'),
    path('dashboard/', views.dashboard, name='dashboard'),
]