from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.csrf import csrf_exempt

from compiler import utils
from compiler.forms import CompileForm, ChangeSectionsForm, UploadFileForm, CreateDirectoryForm
from compiler.models import FileInfo, File, Section, Directory


def index(request):
    context = dict()
    context['directories'] = utils.get_root_directories(request.user)
    context['form'] = CompileForm()
    context['sectionsForm'] = ChangeSectionsForm()
    context['fileForm'] = UploadFileForm()
    context['directoryForm'] = CreateDirectoryForm()
    return render(request, 'compiler/index.html', context)


def compile_file(request, file_info_id):
    if request.method == 'POST':
        context = dict()
        # Get file
        file_info = get_object_or_404(FileInfo, pk=file_info_id)
        file = get_object_or_404(File, info=file_info)
        # Get compilation options
        form = CompileForm(request.POST)
        options = utils.get_options(form)
        # Compiling the file, saving the output to the temporary directory
        import os
        temporary_path = file.content.path.replace("media/files", "temporary")
        os.chdir(os.path.dirname(temporary_path))
        # Compile with options
        cmd = 'sdcc' + ' -S ' + options + ' ' + file.content.path
        context['cmd'] = cmd
        err_message = os.popen(cmd + ' 2>&1').read()
        status_code = 200
        # Get output
        try:
            with open(temporary_path.replace('.c', '.asm'), 'r') as output_file:
                [headers, bodies] = utils.separate_assembly_sections(output_file.read())
                context['headers'] = headers
                context['bodies'] = bodies
        except FileNotFoundError:
            context['errors'] = utils.parse_err_message(err_message)
            status_code = 400
        # Remove all files from temporary directory
        os.system('rm -rf ' + os.path.dirname(temporary_path) + '/*')
        return JsonResponse(status=status_code, data=context)


def show_file(request, file_info_id):
    file_info = get_object_or_404(FileInfo, pk=file_info_id)
    file = get_object_or_404(File, info=file_info)
    content = file.content.read().decode('utf-8')
    code = utils.get_formatted_code(Section.objects.filter(file=file), content.split('\n'))
    return JsonResponse({'code': code})


def change_sections(request, file_info_id):
    if request.method == 'POST':
        form = ChangeSectionsForm(request.POST)
        if form.is_valid():
            context = dict()
            # Get file
            file_info = get_object_or_404(FileInfo, pk=file_info_id)
            file = get_object_or_404(File, info=file_info)
            # Get sections
            utils.replace_sections(form.cleaned_data['start'],
                                   form.cleaned_data['end'],
                                   form.cleaned_data['sectionType'],
                                   file)
            # Null response
            return JsonResponse(context)
        else:
            print(form.errors)


def upload_file(request):
    if request.method == 'POST':
        form = UploadFileForm(request.POST, request.FILES)
        if form.is_valid():
            context = dict()
            # Parse form
            name = form.cleaned_data['file'].name
            description = form.cleaned_data['description']
            file_info_id = form.cleaned_data['parent']
            # Get parent directory
            parent_info_id = get_object_or_404(FileInfo, pk=file_info_id)
            parent = get_object_or_404(Directory, info=parent_info_id)
            # Create file info and file
            file_info = FileInfo.objects.create(name=name, description=description, owner=request.user)
            file = File.objects.create(info=file_info, parent=parent, content=form.cleaned_data['file'])
            utils.create_file_sections(file.content.read().decode('utf-8'), file)
            file.save()
            # Null response
            return JsonResponse(context)
        else:
            print(form.errors)


def create_directory(request):
    if request.method == 'POST':
        form = CreateDirectoryForm(request.POST)
        if form.is_valid():
            context = dict()
            # Parse form
            name = form.cleaned_data['name']
            description = form.cleaned_data['description']
            parent_info_id = form.cleaned_data['parent']
            # Get parent directory
            parent = utils.get_parent(parent_info_id)
            # Create directory info and directory
            directory_info = FileInfo.objects.create(name=name, description=description, owner=request.user)
            directory = Directory.objects.create(info=directory_info, parent=parent)
            directory.save()
            # Null response
            return JsonResponse(context)
        else:
            print(form.errors)


@csrf_exempt
def delete_file(request, file_info_id):
    if request.method == 'DELETE':
        context = dict()
        # Get file
        file_info = get_object_or_404(FileInfo, pk=file_info_id)
        file_info.available = False
        file_info.save()
        # Null response
        return JsonResponse(context)


def directories_tree(request):
    return render(request, 'compiler/directories.html', {'directories': utils.get_root_directories(request.user)})
