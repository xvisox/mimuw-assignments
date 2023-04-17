import json

from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from django.views import generic

from compiler.models import Directory, FileInfo, File


class IndexView(generic.ListView):
    template_name = 'compiler/index.html'

    def get_queryset(self):
        return None

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get all user directories with no parent
        context['directories'] = get_root_directories(self.request.user)
        # Get sample code
        context['code'] = get_code(SAMPLE_CODE)
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
        context['directories'] = get_root_directories(self.request.user)
        return context


def remove_file(request, file_info_id):
    file_info = get_object_or_404(FileInfo, pk=file_info_id)
    file_info.available = False
    file_info.save()
    return HttpResponseRedirect(reverse('compiler:edit'))


def add_directory(request):
    if request.method == 'POST' and request.user.is_authenticated:
        name = request.POST['name']
        description = request.POST['description']
        parent_id = request.POST['parent']
        if parent_id == '':
            parent = None
        else:
            parent = Directory.objects.get(pk=parent_id)
            parent.info.last_modified = timezone.now()
            parent.info.save()
        directory = Directory.objects.create(info=FileInfo.objects.create(name=name, description=description,
                                                                          owner=request.user), parent=parent)
        directory.save()
    return HttpResponseRedirect(reverse('compiler:edit'))


class FileView(generic.ListView):
    template_name = 'compiler/file-editor.html'

    def get_queryset(self):
        return None


class ShowFileView(generic.DetailView):
    template_name = 'compiler/index.html'
    model = FileInfo

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get all user directories with no parent
        context['directories'] = get_root_directories(self.request.user)
        # Get file
        file_info = FileInfo.objects.get(pk=self.kwargs['pk'])
        file = File.objects.get(info=file_info)
        context['code'] = get_code(file.content)
        return context


def get_root_directories(user):
    if user.is_authenticated:
        return Directory.objects.filter(info__owner=user, parent=None, info__available=True)
    else:
        return None


def get_code(raw):
    code_obj = {'code': raw.split(' ')}
    return json.dumps(code_obj, cls=DjangoJSONEncoder)


SAMPLE_CODE = '// Welcome to home page!\\n#include <stdio.h>\\n\\nint main() {\\n\\tprintf(\\"Hello, ' \
              'World!\\");\\n\\treturn 0;\\n}\\n'
