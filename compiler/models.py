from django.conf import settings
from django.db import models
from django.utils import timezone


class FileInfo(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=20)
    description = models.CharField(max_length=100, null=True, blank=True)
    creation_date = models.DateTimeField(default=timezone.now)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    available = models.BooleanField(default=True)
    available_modification_date = models.DateTimeField(default=timezone.now)
    last_modified = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name


class Directory(models.Model):
    id = models.AutoField(primary_key=True)
    info = models.OneToOneField(FileInfo, on_delete=models.CASCADE)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)

    def is_file(self):
        return False

    def __str__(self):
        return self.info.name

    def get_children(self):
        return list(Directory.objects.filter(parent=self, info__available=True)) \
            + list(File.objects.filter(parent=self, info__available=True))

    def has_children(self):
        return len(self.get_children()) > 0


class File(models.Model):
    id = models.AutoField(primary_key=True)
    info = models.OneToOneField(FileInfo, on_delete=models.CASCADE)
    parent = models.ForeignKey(Directory, on_delete=models.CASCADE)
    content = models.FileField(upload_to='files/')

    def is_file(self):
        return True

    def __str__(self):
        return self.info.name
