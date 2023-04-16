from django.urls import path

from . import views

app_name = 'compiler'
urlpatterns = [
    path('', views.IndexView.as_view(), name='index'),
    path('edit', views.EditView.as_view(), name='edit'),
]
