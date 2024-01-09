# identime_backend/urls.py

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('identime_app.urls')),  # Replace 'your_app_name' with the actual name of your app
]


