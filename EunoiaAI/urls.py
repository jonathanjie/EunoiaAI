from django.contrib import admin
from django.urls import path
from EunoiaAI.views import home, upload_page, chat, upload_file

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', home, name='home'),
    path('upload-page/', upload_page, name='upload_page'),
    path('chat/', chat, name='chat'),
    path('upload/', upload_file, name='upload_file'),
]