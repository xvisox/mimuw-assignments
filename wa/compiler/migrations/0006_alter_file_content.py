# Generated by Django 4.2 on 2023-04-19 12:28

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('compiler', '0005_fileinfo_available_modification_date_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='file',
            name='content',
            field=models.FileField(upload_to='files/'),
        ),
    ]
