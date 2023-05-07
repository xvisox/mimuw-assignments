import re

from compiler.models import Directory, Section


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


def get_parent(parent_info_id):
    return None if parent_info_id == (-1) else Directory.objects.get(info__id=parent_info_id)


def parse_err_message(err_message):
    print(err_message)
    err_list = err_message.split('\n')
    for i in range(len(err_list)):
        if '/' in err_list[i]:
            err_list[i] = parse_error_path(err_list[i])
        else:
            err_list[i] = [err_list[i], '-1']
    return err_list


def parse_error_path(path):
    # Split the path into components using the colon as the delimiter
    components = path.split(':')
    # Extract the filename and error message from the components
    filename = components[0].split('/')[-1]
    line_number = components[1]
    error_message = ':'.join(components[1:])
    # Join the filename and error message with a colon
    result = filename + ':' + error_message
    return [result, line_number]


def separate_assembly_sections(raw):
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
    # Separate each section into header and body
    headers = []
    bodies = []
    for i in range(len(sections)):
        count = 0
        for j in range(len(sections[i])):
            if separator in sections[i][j]:
                count += 1
            if count == 2:
                headers.append(sections[i][:j + 1])
                bodies.append(sections[i][j + 1:])
                break
    for i in range(len(headers)):
        headers[i] = '\n'.join(headers[i])
        bodies[i] = '\n'.join(bodies[i])
    return [headers, bodies]


def get_options(form):
    if form.is_valid():  # the form will always be valid because of the default values
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


def get_formatted_code(sections, code_lines):
    line_by_line = []
    # Add dummy sections to fill in the gaps
    for i in range(len(code_lines)):
        line_by_line.append(Section.SectionType.UNKNOWN)

    for section in sections:
        for i in range(section.start_row, section.end_row + 1):
            line_by_line[i] = str(i + 1).ljust(4) + section.type.ljust(10) + ' ' + code_lines[i]
    return "\n".join(line_by_line)


def replace_sections(start, end, section_type, file):
    sections = Section.objects.filter(file=file, start_row__gte=start, end_row__lte=end)
    for section in sections:
        section.type = section_type
        section.save()
