import json

from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.views import generic

from compiler.forms import UploadFileForm, CompileForm
from compiler.models import Directory, FileInfo, File


class IndexView(generic.ListView):
    template_name = 'compiler/index.html'
    context_object_name = 'directories'

    def get_queryset(self):
        return get_root_directories(self.request.user)

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get sample code
        context['code'] = get_code(SAMPLE_CODE)
        return context


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
        context['code'] = get_code(file.content.read().decode('utf-8'))
        # Provide file id
        context['file_id'] = file_info.id
        # Provide form
        form = CompileForm()
        context['form'] = form
        return context


class CompileFileView(ShowFileView):

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get file
        file_info = FileInfo.objects.get(pk=self.kwargs['pk'])
        file = File.objects.get(info=file_info)
        # Compiling the file
        import os
        # Change directory to temporary
        temporary_path = file.content.path.replace("media/files", "temporary")
        os.chdir(os.path.dirname(temporary_path))
        # Compile with options
        OPTIONS = ''
        cmd = 'sdcc' + ' ' + OPTIONS + ' ' + file.content.path
        err_message = os.popen(cmd + ' 2>&1').read()
        # Get output
        try:
            with open(temporary_path.replace('.c', '.asm'), 'r') as output_file:
                context['output'] = separate_code_to_sections(output_file.read().split('\n'))
        except FileNotFoundError:
            context['output'] = parse_err_message(err_message)
        # Remove all files from temporary directory
        os.system('rm -rf ' + os.path.dirname(temporary_path) + '/*')
        return context


class DirectoryEditView(generic.ListView):
    template_name = 'compiler/dir-editor.html'
    context_object_name = 'all_directories'

    def get_queryset(self):
        return get_all_directories(self.request.user)

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get all user directories with no parent
        context['directories'] = get_root_directories(self.request.user)
        return context


def remove_file(request, file_info_id):
    file_info = get_object_or_404(FileInfo, pk=file_info_id)
    file_info.available = False
    file_info.available_modification_date = timezone.now()
    file_info.save()
    return HttpResponseRedirect(reverse('compiler:edit'))


def add_directory(request):
    if request.method == 'POST' and request.user.is_authenticated and request.POST['name'] != '':
        name = request.POST['name']
        description = request.POST['description']
        parent = get_and_update_parent(request.POST['parent'])
        # Create directory info and directory
        file_info = FileInfo.objects.create(name=name, description=description, owner=request.user)
        directory = Directory.objects.create(info=file_info, parent=parent)
        directory.save()
    return HttpResponseRedirect(reverse('compiler:edit'))


def upload_file(request):
    if request.method == 'POST' and request.user.is_authenticated:
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            name = request.FILES['file'].name
            description = request.POST['description']
            parent = get_and_update_parent(request.POST['parent'])
            # Create file info and file
            file_info = FileInfo.objects.create(name=name, description=description, owner=request.user)
            file = File.objects.create(info=file_info, parent=parent, content=request.FILES['file'])
            file.save()
            return HttpResponseRedirect(reverse('compiler:show_file', args=(file.info.id,)))
    form = UploadFileForm()
    all_directories = get_all_directories(request.user)
    return render(request, 'compiler/file-editor.html', {'form': form, 'all_directories': all_directories})


def get_root_directories(user):
    if not user.is_authenticated:
        return None
    return Directory.objects.filter(info__owner=user, parent=None, info__available=True)


def get_all_directories(user):
    if (not user.is_authenticated) or (not user.is_active):
        return None
    all_directories = get_root_directories(user)
    root_directories = get_root_directories(user)
    for directory in root_directories:
        all_directories = all_directories | get_all_subdirectories(directory)
    return all_directories


def get_all_subdirectories(directory):
    subdirectories = Directory.objects.filter(parent=directory, info__available=True)
    for subdirectory in subdirectories:
        subdirectories = subdirectories | get_all_subdirectories(subdirectory)
    return subdirectories


def get_and_update_parent(parent_id):
    if parent_id == '':
        parent = None
    else:
        parent = Directory.objects.get(pk=parent_id)
        parent.info.last_modified = timezone.now()
        parent.info.save()
    return parent


SAMPLE_CODE = '// Welcome to home page!\n#include <stdio.h>\n\nint main()' \
              '{\n\tprintf("Hello, World!");\n\treturn 0;\n}\n'


def get_code(raw):
    code_list = raw.split('\n')
    for i in range(len(code_list)):
        code_list[i] = code_list[i].replace('\t', '\\t').replace('"', '\\"').replace('\\n', ' newline')

    # Convert to json
    code_obj = {'code': code_list}
    return json.dumps(code_obj, cls=DjangoJSONEncoder)


def parse_err_message(err_message):
    err_list = err_message.split('\n')
    for i in range(len(err_list)):
        idx = find_first_index(err_list[i])
        if idx != -1:
            err_list[i] = err_list[i][idx:]
    return err_list


def find_first_index(message):
    idx = message.find(".c:")
    for i in range(idx, 0, -1):
        if message[i] == '/':
            return i + 1


def separate_code_to_sections(raw):
    count = 0
    sections = []
    SEPARATOR = ';---------'
    for line in raw:
        if SEPARATOR in line:
            count += 1
            if count % 2 == 1:
                sections.append([])
        sections[-1].append(line)
    # Concatenate each section
    for i in range(len(sections)):
        sections[i] = '\n'.join(sections[i])
    return sections
