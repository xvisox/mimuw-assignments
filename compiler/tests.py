from datetime import timedelta

from django.contrib.auth.models import User
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, Client
from django.urls import reverse
from django.utils import timezone

from compiler.forms import CreateDirectoryForm, UploadFileForm, ChangeSectionsForm, CompileForm
from compiler.models import FileInfo, File, Section, Directory

# Tests constants
SAMPLE_NAME = 'test'
SAMPLE_NAME2 = 'test.v2'
SAMPLE_DESCRIPTION = 'test'
SAMPLE_DESCRIPTION2 = 'test.v2'
SAMPLE_PARENT = 1
ROOT_PARENTS = [-1, '', None]
WRONG_PARENT = -100
NULL_FIELDS = ['', None]
COMPILING_CONTENT = b'#define TEST 1\nint main() { return 0; }'
NON_COMPILING_CONTENT = b'oops'
SAMPLE_FILE = SimpleUploadedFile('test.c', COMPILING_CONTENT)
WRONG_EXTENSION_FILE = SimpleUploadedFile('test.txt', COMPILING_CONTENT)
NON_COMPILING_FILE = SimpleUploadedFile('wrong.c', NON_COMPILING_CONTENT)
SAMPLE_SECTION_TYPE = 'UNKNOWN'
NOT_SECTION_TYPE = 'STH_ELSE'
START_ROW = 100
END_ROW = 200
SAMPLE_USERNAME = 'usr'
SAMPLE_PASSWORD = 'pwd'
SAMPLE_ADD_INFO = 'info'


# ---- Form tests -----
class CreateDirectoryFormTests(TestCase):
    def test_form_valid(self):
        form_data = {'name': SAMPLE_NAME, 'description': SAMPLE_DESCRIPTION, 'parent': SAMPLE_PARENT}
        form = CreateDirectoryForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_form_invalid(self):
        form_data = {'name': SAMPLE_NAME, 'description': SAMPLE_DESCRIPTION, 'parent': WRONG_PARENT}
        form = CreateDirectoryForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_null_name(self):
        for parent in ROOT_PARENTS + [SAMPLE_PARENT]:
            for null_field in NULL_FIELDS:
                form_data = {'name': null_field, 'description': SAMPLE_DESCRIPTION, 'parent': parent}
                form = CreateDirectoryForm(data=form_data)
                self.assertFalse(form.is_valid())

    def test_null_description(self):
        for parent in ROOT_PARENTS + [SAMPLE_PARENT]:
            for null_field in NULL_FIELDS:
                form_data = {'name': SAMPLE_NAME, 'description': null_field, 'parent': parent}
                form = CreateDirectoryForm(data=form_data)
                self.assertTrue(form.is_valid())

    def test_null_parent(self):
        for null_field in NULL_FIELDS:
            form_data = {'name': SAMPLE_NAME, 'description': SAMPLE_DESCRIPTION, 'parent': null_field}
            form = CreateDirectoryForm(data=form_data)
            self.assertTrue(form.is_valid())


class UploadFileFormTests(TestCase):
    def test_form_valid(self):
        form_data = {'description': SAMPLE_DESCRIPTION, 'parent': SAMPLE_PARENT}
        form = UploadFileForm(data=form_data, files={'file': SAMPLE_FILE})
        self.assertTrue(form.is_valid())

    def test_form_invalid(self):
        form_data = {'description': SAMPLE_DESCRIPTION, 'parent': WRONG_PARENT}
        form = UploadFileForm(data=form_data, files={'file': SAMPLE_FILE})
        self.assertFalse(form.is_valid())

    def test_null_description(self):
        for null_field in NULL_FIELDS:
            form_data = {'description': null_field, 'parent': SAMPLE_PARENT}
            form = UploadFileForm(data=form_data, files={'file': SAMPLE_FILE})
            self.assertTrue(form.is_valid())

    def test_null_parent(self):
        for null_field in NULL_FIELDS:
            form_data = {'description': SAMPLE_DESCRIPTION, 'parent': null_field}
            form = UploadFileForm(data=form_data, files={'file': SAMPLE_FILE})
            self.assertFalse(form.is_valid())

    def test_null_file(self):
        for null_field in NULL_FIELDS:
            form_data = {'description': SAMPLE_DESCRIPTION, 'parent': SAMPLE_PARENT}
            form = UploadFileForm(data=form_data, files={'file': null_field})
            self.assertFalse(form.is_valid())

    def test_good_extension(self):
        form_data = {'description': SAMPLE_DESCRIPTION, 'parent': SAMPLE_PARENT}
        for extension in ['.c', '.cc', '.h']:
            temp_file = SimpleUploadedFile('test' + extension, b'content')
            form = UploadFileForm(data=form_data, files={'file': temp_file})
            self.assertTrue(form.is_valid())

    def test_wrong_extension(self):
        form_data = {'description': SAMPLE_DESCRIPTION, 'parent': SAMPLE_PARENT}
        form = UploadFileForm(data=form_data, files={'file': WRONG_EXTENSION_FILE})
        self.assertFalse(form.is_valid())

    def test_root_parent(self):
        for parent in ROOT_PARENTS:
            form_data = {'description': SAMPLE_DESCRIPTION, 'parent': parent}
            form = UploadFileForm(data=form_data, files={'file': SAMPLE_FILE})
            self.assertFalse(form.is_valid())


class ChangeSectionsFormTest(TestCase):
    def test_form_valid(self):
        form_data = {'start': START_ROW, 'end': END_ROW, 'sectionType': SAMPLE_SECTION_TYPE}
        form = ChangeSectionsForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_form_invalid_range(self):
        form_data = {'start': END_ROW, 'end': START_ROW, 'sectionType': SAMPLE_SECTION_TYPE}
        form = ChangeSectionsForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_wrong_section_type(self):
        form_data = {'start': START_ROW, 'end': END_ROW, 'sectionType': NOT_SECTION_TYPE}
        form = ChangeSectionsForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_range_equal(self):
        form_data = {'start': START_ROW, 'end': START_ROW, 'sectionType': SAMPLE_SECTION_TYPE}
        form = ChangeSectionsForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_null_start(self):
        form_data = {'start': None, 'end': END_ROW, 'sectionType': SAMPLE_SECTION_TYPE}
        form = ChangeSectionsForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_null_end(self):
        form_data = {'start': START_ROW, 'end': None, 'sectionType': SAMPLE_SECTION_TYPE}
        form = ChangeSectionsForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_null_section_type(self):
        form_data = {'start': START_ROW, 'end': END_ROW, 'sectionType': None}
        form = ChangeSectionsForm(data=form_data)
        self.assertFalse(form.is_valid())


# ---- Models tests ----
class FileInfoModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)

    def test_file_info_creation(self):
        self.assertTrue(isinstance(self.file, FileInfo))
        self.assertEqual(self.file.__str__(), self.file.name)

    def test_file_info_update(self):
        self.file.name = SAMPLE_NAME2
        self.file.description = SAMPLE_DESCRIPTION2
        self.file.save()
        self.assertEqual(self.file.name, SAMPLE_NAME2)
        self.assertEqual(self.file.description, SAMPLE_DESCRIPTION2)

    def test_file_info_delete(self):
        self.file.delete()
        self.assertEqual(FileInfo.objects.count(), 0)

    def test_file_info_owner(self):
        self.assertEqual(self.file.owner, self.user)

    def test_file_info_creation_date(self):
        self.assertLess(self.file.creation_date, timezone.now())

    def test_file_info_available_modification_date(self):
        self.assertLess(self.file.available_modification_date, timezone.now())

    def test_file_info_last_modified(self):
        self.assertLess(self.file.last_modified, timezone.now())


class DirectoryModelTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.file_info_2 = FileInfo.objects.create(name=SAMPLE_NAME2, description=SAMPLE_DESCRIPTION2, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)
        self.file = File.objects.create(info=self.file_info_2, parent=self.directory, content=SAMPLE_FILE)

    def test_directory_creation(self):
        self.assertTrue(isinstance(self.directory, Directory))
        self.assertEqual(self.directory.__str__(), self.directory.info.name)

    def test_directory_update(self):
        self.directory.info.name = SAMPLE_NAME2
        self.directory.info.description = SAMPLE_DESCRIPTION2
        self.directory.save()
        self.assertEqual(self.directory.info.name, SAMPLE_NAME2)
        self.assertEqual(self.directory.info.description, SAMPLE_DESCRIPTION2)

    def test_directory_delete(self):
        self.directory.delete()
        self.assertEqual(Directory.objects.count(), 0)

    def test_directory_owner(self):
        self.assertEqual(self.directory.info.owner, self.user)

    def test_directory_parent(self):
        self.assertEqual(self.directory.parent, None)


class FileTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.file_info_2 = FileInfo.objects.create(name=SAMPLE_NAME2, description=SAMPLE_DESCRIPTION2, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)
        self.file = File.objects.create(info=self.file_info_2, parent=self.directory, content=SAMPLE_FILE)

    def test_fileinfo_name_max_length(self):
        file_info = self.file_info_1
        max_length = file_info._meta.get_field('name').max_length
        self.assertEquals(max_length, 20)

    def test_fileinfo_str_method(self):
        file_info = self.file_info_1
        self.assertEquals(str(file_info), file_info.name)

    def test_file_creation_date_default_value(self):
        file_info = self.file_info_1
        self.assertTrue(file_info.creation_date is not None)
        self.assertTrue(timezone.now() - file_info.creation_date < timedelta(seconds=1))

    def test_file_owner_foreign_key(self):
        file_info = self.file_info_1
        self.assertEquals(file_info.owner, self.user)

    def test_file_available_default_value(self):
        file_info = self.file_info_1
        self.assertTrue(file_info.available)

    def test_file_available_modification_date_auto_now(self):
        file_info = self.file_info_1
        old_modification_date = file_info.available_modification_date
        file_info.available = False
        file_info.save()
        new_modification_date = file_info.available_modification_date
        self.assertNotEquals(old_modification_date, new_modification_date)

    def test_file_str_method(self):
        self.assertEquals(str(self.file), self.file.info.name)

    def test_directory_info_foreign_key(self):
        self.assertEquals(self.directory.info, self.file_info_1)

    def test_directory_parent_foreign_key(self):
        self.assertIsNone(self.directory.parent)

    def test_file_parent_foreign_key(self):
        self.assertEquals(self.file.parent, self.directory)


class SectionModelTestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.file_info_2 = FileInfo.objects.create(name=SAMPLE_NAME2, description=SAMPLE_DESCRIPTION2, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)
        self.file = File.objects.create(info=self.file_info_2, parent=self.directory, content=SAMPLE_FILE)

    def test_create_section(self):
        section = Section.objects.create(
            file=self.file,
            name=SAMPLE_NAME,
            description=SAMPLE_DESCRIPTION,
            start_row=START_ROW,
            end_row=END_ROW,
            type=Section.SectionType.PROCEDURE,
            status=Section.SectionStatus.COMPILE_OK,
            additional_status_info=SAMPLE_ADD_INFO
        )

        self.assertEqual(section.file, self.file)
        self.assertEqual(section.name, SAMPLE_NAME)
        self.assertEqual(section.description, SAMPLE_DESCRIPTION)
        self.assertEqual(section.start_row, START_ROW)
        self.assertEqual(section.end_row, END_ROW)
        self.assertEqual(section.type, Section.SectionType.PROCEDURE)
        self.assertEqual(section.status, Section.SectionStatus.COMPILE_OK)
        self.assertEqual(section.additional_status_info, SAMPLE_ADD_INFO)

    def test_create_subsection(self):
        parent_section = Section.objects.create(
            file=self.file,
            name='parent_section',
            start_row=1,
            end_row=10,
            type=Section.SectionType.PROCEDURE,
            status=Section.SectionStatus.COMPILE_OK
        )

        subsection = Section.objects.create(
            file=self.file,
            name=SAMPLE_NAME2,
            description=SAMPLE_DESCRIPTION2,
            start_row=2,
            end_row=5,
            parent=parent_section,
            type=Section.SectionType.COMMENT,
            status=Section.SectionStatus.COMPILES_WITH_WARNINGS,
            additional_status_info=SAMPLE_ADD_INFO
        )

        self.assertEqual(subsection.file, self.file)
        self.assertEqual(subsection.name, SAMPLE_NAME2)
        self.assertEqual(subsection.description, SAMPLE_DESCRIPTION2)
        self.assertEqual(subsection.start_row, 2)
        self.assertEqual(subsection.end_row, 5)
        self.assertEqual(subsection.parent, parent_section)
        self.assertEqual(subsection.type, Section.SectionType.COMMENT)
        self.assertEqual(subsection.status, Section.SectionStatus.COMPILES_WITH_WARNINGS)
        self.assertEqual(subsection.additional_status_info, SAMPLE_ADD_INFO)

    def test_string_representation(self):
        section = Section.objects.create(
            file=self.file,
            name=SAMPLE_NAME,
            start_row=START_ROW,
            end_row=END_ROW,
            type=Section.SectionType.PROCEDURE,
            status=Section.SectionStatus.COMPILE_OK
        )

        self.assertEqual(str(section), SAMPLE_NAME)

    def test_creation_date_is_readonly(self):
        section = Section.objects.create(
            file=self.file,
            name=SAMPLE_NAME,
            start_row=1,
            end_row=10,
            type=Section.SectionType.PROCEDURE,
            status=Section.SectionStatus.COMPILE_OK
        )

        section.creation_date = timezone.now()
        section.save()

        self.assertNotEqual(section.creation_date, timezone.now())


# ---- View tests ----
class IndexViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.file_info_2 = FileInfo.objects.create(name=SAMPLE_NAME2, description=SAMPLE_DESCRIPTION2, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)
        self.file = File.objects.create(info=self.file_info_2, parent=self.directory, content=SAMPLE_FILE)

    def test_index_view_returns_correct_template(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        response = self.client.get(reverse('compiler:index'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'compiler/index.html')

    def test_index_view_context_data(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        response = self.client.get(reverse('compiler:index'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['directories']), 1)
        self.assertEqual(response.context['directories'][0], self.directory)
        self.assertIsInstance(response.context['form'], CompileForm)
        self.assertIsInstance(response.context['sectionsForm'], ChangeSectionsForm)
        self.assertIsInstance(response.context['fileForm'], UploadFileForm)
        self.assertIsInstance(response.context['directoryForm'], CreateDirectoryForm)


class CompileFileViewTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.file_info_2 = FileInfo.objects.create(name=SAMPLE_NAME2, description=SAMPLE_DESCRIPTION2, owner=self.user)
        self.file_info_3 = FileInfo.objects.create(name=SAMPLE_NAME2, description=SAMPLE_DESCRIPTION2, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)
        self.file = File.objects.create(info=self.file_info_2, parent=self.directory, content=SAMPLE_FILE)
        self.file2 = File.objects.create(info=self.file_info_3, parent=self.directory, content=NON_COMPILING_FILE)

    def test_upload_file(self):
        self.assertEqual(self.file.content.read(), COMPILING_CONTENT)

    def test_successful_compile(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        url = reverse('compiler:compile_file', args=[self.file_info_2.pk])
        data = {
            'standard': '--std-c99',
            'optimization': ['--nolabelopt'],
            'processor': '-mmcs51',
            'options_MCS51': '--model-small'
        }
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('headers' in response.json())
        self.assertTrue('bodies' in response.json())

    def test_unsuccessful_compile(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        url = reverse('compiler:compile_file', args=[self.file_info_3.pk])
        data = {
            'standard': '--std-c99',
            'optimization': ['--nolabelopt'],
            'processor': '-mmcs51',
            'options_MCS51': '--model-small'
        }
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 400)
        self.assertTrue('errors' in response.json())

    def test_post_request_with_invalid_form_returns_400_status_code(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        url = reverse('compiler:compile_file', args=[self.file_info_2.pk])
        data = {
            'standard': 'invalid',
            'optimization': ['invalid'],
            'processor': 'invalid',
            'options_MCS51': 'invalid'
        }
        response = self.client.post(url, data=data)
        self.assertEqual(response.status_code, 400)
        self.assertTrue('message' in response.json())

    def test_compile_file_bad_request(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        url = reverse('compiler:compile_file', args=[self.file_info_2.pk])
        response = self.client.get(url)
        self.assertEqual(response.status_code, 400)
        self.assertTrue('message' in response.json())


class ShowFileViewTestCase(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.file_info_2 = FileInfo.objects.create(name=SAMPLE_NAME2, description=SAMPLE_DESCRIPTION2, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)
        self.file = File.objects.create(info=self.file_info_2, parent=self.directory, content=SAMPLE_FILE)

    def test_authenticated_user_can_access_file(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        response = self.client.get(reverse('compiler:show_file', args=[self.file_info_2.id]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue('code' in response.json())

    def test_unauthenticated_user_cannot_access_file(self):
        response = self.client.get(reverse('compiler:show_file', args=[self.file_info_2.id]))
        self.assertEqual(response.status_code, 302)

    def test_accessing_nonexistent_file_returns_404(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        response = self.client.get(reverse('compiler:show_file', args=[1000]))
        self.assertEqual(response.status_code, 404)


class ChangeSectionsViewTest(TestCase):

    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.file_info_2 = FileInfo.objects.create(name=SAMPLE_NAME2, description=SAMPLE_DESCRIPTION2, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)
        self.file = File.objects.create(info=self.file_info_2, parent=self.directory, content=SAMPLE_FILE)

    def test_change_sections_view(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        data = {
            'start': START_ROW,
            'end': END_ROW,
            'sectionType': SAMPLE_SECTION_TYPE,
        }
        response = self.client.post(reverse('compiler:change_sections', args=[self.file_info_2.id]), data=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('message' in response.json())

    def test_change_sections_view_bad_request(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        data = {
            'start': START_ROW,
            'end': END_ROW,
            'sectionType': 'invalid',
        }
        response = self.client.post(reverse('compiler:change_sections', args=[self.file_info_2.id]), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertTrue('message' in response.json())

    def test_change_sections_view_unauthenticated_user(self):
        data = {
            'start': START_ROW,
            'end': END_ROW,
            'sectionType': SAMPLE_SECTION_TYPE,
        }
        response = self.client.post(reverse('compiler:change_sections', args=[self.file_info_2.id]), data=data)
        self.assertEqual(response.status_code, 302)

    def test_change_sections_view_nonexistent_file(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        data = {
            'start': START_ROW,
            'end': END_ROW,
            'sectionType': SAMPLE_SECTION_TYPE,
        }
        response = self.client.post(reverse('compiler:change_sections', args=[1000]), data=data)
        self.assertEqual(response.status_code, 404)


class UploadFileViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)

    def test_upload_file_view_nonexistent_directory(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        data = {
            'file': SimpleUploadedFile('test.c', b'content'),
            'parent': 1000
        }
        response = self.client.post(reverse('compiler:upload_file'), data=data)
        self.assertEqual(response.status_code, 404)

    def test_upload_file_view(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        data = {
            'file': SimpleUploadedFile('test.c', b'content'),
            'parent': self.directory.info.id
        }
        response = self.client.post(reverse('compiler:upload_file'), data=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('message' in response.json())

    def test_upload_file_view_unauthenticated_user(self):
        data = {
            'file': SAMPLE_FILE,
            'parent': self.directory.info.id
        }
        response = self.client.post(reverse('compiler:upload_file'), data=data)
        self.assertEqual(response.status_code, 302)


class CreateDirectoryViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)

    def test_create_directory_view(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        data = {
            'name': SAMPLE_NAME,
            'description': SAMPLE_DESCRIPTION,
            'parent': self.directory.info.id
        }
        response = self.client.post(reverse('compiler:create_directory'), data=data)
        self.assertEqual(response.status_code, 200)
        self.assertTrue('message' in response.json())

    def test_create_directory_view_bad_request(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        data = {
            'name': NULL_FIELDS[0],
            'description': SAMPLE_DESCRIPTION,
            'parent': self.directory.info.id,
        }
        response = self.client.post(reverse('compiler:create_directory'), data=data)
        self.assertEqual(response.status_code, 400)
        self.assertTrue('message' in response.json())


class DeleteFileViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        self.file_info_1 = FileInfo.objects.create(name=SAMPLE_NAME, description=SAMPLE_DESCRIPTION, owner=self.user)
        self.directory = Directory.objects.create(info=self.file_info_1, parent=None)

    def test_delete_file_view(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        response = self.client.delete(reverse('compiler:delete_file', args=[self.file_info_1.id]))
        self.assertEqual(response.status_code, 200)
        self.assertTrue('message' in response.json())

    def test_delete_file_view_unauthenticated_user(self):
        response = self.client.delete(reverse('compiler:delete_file', args=[self.file_info_1.id]))
        self.assertEqual(response.status_code, 302)

    def test_delete_file_view_nonexistent_file(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        response = self.client.delete(reverse('compiler:delete_file', args=[1000]))
        self.assertEqual(response.status_code, 404)

    def test_delete_file_view_different_method(self):
        self.client.login(username=SAMPLE_USERNAME, password=SAMPLE_PASSWORD)
        response = self.client.get(reverse('compiler:delete_file', args=[self.file_info_1.id]))
        self.assertEqual(response.status_code, 400)
