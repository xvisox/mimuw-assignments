from django.db import models
from django.conf import settings


class FileInfo(models.Model):
    id = models.AutoField(primary_key=True)
    name = models.CharField(max_length=20)
    description = models.CharField(max_length=100)
    creation_date = models.DateTimeField()
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    available = models.BooleanField(default=True)
    last_modified = models.DateTimeField()


class Directory(models.Model):
    id = models.AutoField(primary_key=True)
    info = models.ForeignKey(FileInfo, on_delete=models.CASCADE)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True)


class File(models.Model):
    id = models.AutoField(primary_key=True)
    info = models.ForeignKey(FileInfo, on_delete=models.CASCADE)
    parent = models.ForeignKey(Directory, on_delete=models.CASCADE)
    content = models.TextField()
