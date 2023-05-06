from django.urls import path

from . import views

app_name = 'compiler'
urlpatterns = [
    path('', views.index, name='index'),
    path('files/<int:file_info_id>/show', views.show_file, name='show_file'),
    path('files/<int:file_info_id>/compile', views.compile_file, name='compile_file'),
    path('files/<int:file_info_id>/sections', views.change_sections, name='change_sections'),
]
