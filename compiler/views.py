import json

from django.core.serializers.json import DjangoJSONEncoder
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone

from compiler.forms import UploadFileForm, CompileForm
from compiler.models import Directory, FileInfo, File, Section


def index(request):
    context = dict()
    # Get all user directories with no parent
    context['directories'] = get_root_directories(request.user)
    # Get sample code
    context['code'] = get_code(SAMPLE_CODE)
    return render(request, 'compiler/index.html', context)


def edit(request):
    context = dict()
    context['directories'] = get_root_directories(request.user)
    context['all_directories'] = get_all_directories(request.user)
    return render(request, 'compiler/dir-editor.html', context)


def show_file(request, file_info_id):
    context = dict()
    # Get all user directories with no parent
    context['directories'] = get_root_directories(request.user)
    # Get file
    file_info = get_object_or_404(FileInfo, pk=file_info_id)
    file = get_object_or_404(File, info=file_info)
    # Provide file id and code to display
    context['code'] = get_code(file.content.read().decode('utf-8'))
    context['file_id'] = file_info.id
    if request.method == 'POST':
        # Get compilation options
        form = CompileForm(request.POST)
        options = get_options(form)
        # Compiling the file, firstly save it to temporary directory
        import os
        temporary_path = file.content.path.replace("media/files", "temporary")
        os.chdir(os.path.dirname(temporary_path))
        # Compile with options
        cmd = 'sdcc' + ' -S ' + options + ' ' + file.content.path
        context['cmd'] = cmd
        err_message = os.popen(cmd + ' 2>&1').read()
        # Get output
        try:
            with open(temporary_path.replace('.c', '.asm'), 'r') as output_file:
                context['output'] = separate_code_to_sections(output_file.read().split('\n'))
        except FileNotFoundError:
            context['output'] = parse_err_message(err_message)
        # Remove all files from temporary directory
        os.system('rm -rf ' + os.path.dirname(temporary_path) + '/*')

    # Provide form
    form = CompileForm()
    context['form'] = form
    # Return rendered page
    return render(request, 'compiler/index.html', context)


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
            name = form.cleaned_data['file'].name
            description = form.cleaned_data['description']
            parent = get_and_update_parent(request.POST['parent'])  # no parent field in django form
            # Create file info and file
            file_info = FileInfo.objects.create(name=name, description=description, owner=request.user)
            file = File.objects.create(info=file_info, parent=parent, content=form.cleaned_data['file'])
            create_file_sections(file.content.read().decode('utf-8'), file)
            file.save()
            return HttpResponseRedirect(reverse('compiler:edit_file', args=(file_info.id,)))

    form = UploadFileForm()
    all_directories = get_all_directories(request.user)
    return render(request, 'compiler/file-editor.html', {'form': form, 'all_directories': all_directories})


def edit_file(request, file_info_id):
    # Provide form and directories
    form = UploadFileForm()
    all_directories = get_all_directories(request.user)
    # Get file with sections
    file_info = get_object_or_404(FileInfo, pk=file_info_id)
    file = get_object_or_404(File, info=file_info)
    content = file.content.read().decode('utf-8')
    sections = get_line_by_line(Section.objects.filter(file=file), len(content.split('\n')))
    # Return rendered page
    return render(request, 'compiler/file-editor.html', {'form': form, 'all_directories': all_directories,
                                                         'content': content, 'sections': sections})


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
        code_list[i] = code_list[i] \
            .replace('\t', '\\t') \
            .replace('"', '\\"') \
            .replace("'", '\\"') \
            .replace('\\n', ' newline') \
            .replace('\\0', ' nullchar')

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


def get_options(form):
    form.is_valid()  # ignore errors
    processor = form.cleaned_data['processor']
    standard = form.cleaned_data['standard']
    optimization = form.cleaned_data['optimization']
    options = ''

    if processor == '-mmcs51':
        options = form.cleaned_data['options_MCS51']
    elif processor == '-mz80':
        options = form.cleaned_data['options_Z80']
    elif processor == '-mstm8':
        options = form.cleaned_data['options_STM8']

    # return concatenation of all options
    all_options = [processor, standard, " ".join(optimization), options]
    return " ".join(all_options).replace('Default', '')


def create_file_sections(lines, file):
    labels = []
    label_bounds = []
    i = 0
    for line in lines.split('\n'):
        labels.append(get_label(line))
        label_bounds.append([i, i])
        i += 1

    # todo: merge consecutive sections with the same label
    for i in range(len(labels)):
        section = Section.objects.create(file=file,
                                         start_row=label_bounds[i][0],
                                         end_row=label_bounds[i][1],
                                         type=labels[i])
        section.save()


def get_label(line):
    if line.startswith("//"):
        return Section.SectionType.COMMENT
    elif "asm" in line or "__asm__" in line:
        return Section.SectionType.INLINE_ASM
    elif line.startswith("#"):
        return Section.SectionType.DIRECTIVE
    elif "(" in line and ")" in line and "{" in line:
        return Section.SectionType.PROCEDURE
    elif "=" in line or ";" in line:
        return Section.SectionType.VARIABLE
    else:
        return Section.SectionType.UNKNOWN


def get_line_by_line(sections, length):
    line_by_line = []
    for i in range(length):
        line_by_line.append(Section.SectionType.UNKNOWN)
    for section in sections:
        for i in range(section.start_row, section.end_row + 1):
            line_by_line[i] = section.type
    return line_by_line
