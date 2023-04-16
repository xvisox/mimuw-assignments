from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views import generic

from compiler.models import Directory, FileInfo


class IndexView(generic.ListView):
    template_name = 'compiler/index.html'

    def get_queryset(self):
        return None

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get all user directories with no parent
        if self.request.user.is_authenticated:
            context['directories'] = Directory.objects.filter(info__owner=self.request.user, parent=None,
                                                              info__available=True)
        else:
            context['directories'] = None
        return context


class EditView(generic.ListView):
    template_name = 'compiler/editor.html'
    context_object_name = 'all_directories'

    def get_queryset(self):
        if (not self.request.user.is_authenticated) or (not self.request.user.is_active):
            return None
        return Directory.objects.filter(info__owner=self.request.user, info__available=True)

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get all user directories with no parent
        if self.request.user.is_authenticated:
            context['directories'] = Directory.objects.filter(info__owner=self.request.user, parent=None,
                                                              info__available=True)
        else:
            context['directories'] = None
        return context


def remove_file(request, file_info_id):
    file_info = get_object_or_404(FileInfo, pk=file_info_id)
    file_info.available = False
    file_info.save()
    return HttpResponseRedirect(reverse('compiler:edit'))


def add_directory(request):
    if request.method == 'POST':
        name = request.POST['name']
        description = request.POST['description']
        parent_id = request.POST['parent']
        if parent_id == '':
            parent = None
        else:
            parent = Directory.objects.get(pk=parent_id)
        directory = Directory.objects.create(info=FileInfo.objects.create(name=name, description=description,
                                                                          owner=request.user), parent=parent)
        directory.save()
    return HttpResponseRedirect(reverse('compiler:edit'))
