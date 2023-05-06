import re

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils import timezone

from compiler.forms import CompileForm, ChangeSectionsForm
from compiler.models import Directory, FileInfo, File, Section


def index(request):
    context = dict()
    context['directories'] = get_root_directories(request.user)
    context['form'] = CompileForm()
    context['sectionsForm'] = ChangeSectionsForm()
    return render(request, 'compiler/index.html', context)


def compile_file(request, file_info_id):
    if request.method == 'POST':
        context = dict()
        # Get file
        file_info = get_object_or_404(FileInfo, pk=file_info_id)
        file = get_object_or_404(File, info=file_info)
        # Get compilation options
        form = CompileForm(request.POST)
        options = get_options(form)
        # Compiling the file, saving the output to the temporary directory
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
                context['output'] = separate_code_to_sections(output_file.read())
        except FileNotFoundError:
            context['output'] = parse_err_message(err_message)
        # Remove all files from temporary directory
        os.system('rm -rf ' + os.path.dirname(temporary_path) + '/*')
        return JsonResponse(context)


def show_file(request, file_info_id):
    file_info = get_object_or_404(FileInfo, pk=file_info_id)
    file = get_object_or_404(File, info=file_info)
    content = file.content.read().decode('utf-8')
    code = get_line_by_line(Section.objects.filter(file=file), content.split('\n'))
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
            replace_sections(form.cleaned_data['start'],
                             form.cleaned_data['end'],
                             form.cleaned_data['sectionType'],
                             file)
            # Null response
            return JsonResponse(context)


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
    code_list = raw.split('\n')
    count = 0
    sections = []
    separator = ';---------'
    for line in code_list:
        if separator in line:
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

    for i in range(len(labels)):
        section = Section.objects.create(file=file,
                                         start_row=label_bounds[i][0],
                                         end_row=label_bounds[i][1],
                                         type=labels[i])
        section.save()


def get_label(line):
    # Check for comments
    if line.startswith("//") or line.startswith("/*") or line.endswith("*/"):
        return Section.SectionType.COMMENT

    # Check for inline assembly
    if re.search(r"\basm\b|\b__asm__\b", line):
        return Section.SectionType.INLINE_ASM

    # Check for preprocessor directives
    if line.startswith("#"):
        return Section.SectionType.DIRECTIVE

    # Check for function declarations or definitions
    if re.match(r"\s*(\w+\s+){0,2}\w+\s+\**\w+\s*\([^)]*\)\s*\{?", line):
        return Section.SectionType.PROCEDURE

    # Check for function calls
    if re.match(r"\s*\w+\s*\([^)]*\)\s*;", line):
        return Section.SectionType.FUNCTION

    # Check for variable declarations
    if re.match(r"\s*(\w+\s+)+\**\w+\s*(, *\**\w+\s*)*;?", line):
        return Section.SectionType.VARIABLE

    # Check for variable assignments or other statements
    if re.search(r"[\w\s]+\s*([=;])", line):
        return Section.SectionType.VARIABLE

    # If none of the above apply, return unknown
    return Section.SectionType.UNKNOWN


def get_line_by_line(sections, code_lines):
    line_by_line = []
    # Add dummy sections to fill in the gaps
    for i in range(len(code_lines)):
        line_by_line.append(Section.SectionType.UNKNOWN)

    for section in sections:
        for i in range(section.start_row, section.end_row + 1):
            line_by_line[i] = section.type.ljust(10) + ' ' + code_lines[i]
    return "\n".join(line_by_line)


def replace_sections(start, end, section_type, file):
    sections = Section.objects.filter(file=file, start_row__gte=start, end_row__lte=end)
    for section in sections:
        section.type = section_type
        section.save()
