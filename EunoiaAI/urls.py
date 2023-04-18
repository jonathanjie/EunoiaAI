from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path("", views.index, name="index"),
    path('agent/create/', views.manage_agent, name='create_agent'),
    path('agent/<str:agent_namespace>/', views.manage_agent, name='manage_agent'),
    path('agent/<str:agent_namespace>/chat/', views.chat_page, name='chat_page'),
    path('agent/<str:agent_namespace>/chat/send-message/', views.send_message, name='send_message'),
    path('upload-page/', views.upload_page, name='upload_page'),
    path('upload/', views.upload_file, name='upload_file'),
    path("accounts/login/", views.login, name="login"),
    path("logout/", views.logout, name="logout"),
    path("auth0-callback/", views.callback, name="callback"),
    path('manage-organization/', views.manage_organization, name='manage_organization'),
    path('manage-user/', views.manage_user, name='manage_user'),
    path('manage-user/<int:user_id>/', views.manage_user, name='manage_user'),
    path('invite-user/', views.invite_user, name='invite_user'),
    path('dashboard/', views.dashboard, name='dashboard'),
]
