from django.contrib import admin

from .models import *

admin.site.register(FileInfo)
admin.site.register(Directory)
admin.site.register(File)
