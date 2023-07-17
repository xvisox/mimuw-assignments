from django.urls import path

from . import views

app_name = 'compiler'
urlpatterns = [
    path('', views.index, name='index'),
    path('files/tree', views.directories_tree, name='directories_tree'),
    path('files/<int:file_info_id>/show', views.show_file, name='show_file'),
    path('files/<int:file_info_id>/compile', views.compile_file, name='compile_file'),
    path('files/<int:file_info_id>/sections', views.change_sections, name='change_sections'),
    path('files/<int:file_info_id>/delete', views.delete_file, name='delete_file'),
    path('files/upload', views.upload_file, name='upload_file'),
    path('files/directory/create', views.create_directory, name='create_directory'),
]
