from django.urls import path

from . import views

app_name = 'compiler'
urlpatterns = [
    path('', views.index, name='index'),
    path('files/edit', views.edit, name='edit'),
    path('files/add', views.upload_file, name='add_file'),
    path('files/<int:file_info_id>/edit', views.edit_file, name='edit_file'),
    path('files/<int:file_info_id>/show', views.show_file, name='show_file'),
    path('files/<int:file_info_id>/remove', views.remove_file, name='remove_file'),
    path('files/add/directory', views.add_directory, name='add_directory')
]
