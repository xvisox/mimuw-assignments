# Generated by Django 4.2 on 2023-04-15 20:30

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Directory',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
            ],
        ),
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('username', models.CharField(max_length=20)),
                ('login', models.CharField(max_length=20)),
                ('password', models.CharField(max_length=20)),
            ],
        ),
        migrations.CreateModel(
            name='FileInfo',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('name', models.CharField(max_length=20)),
                ('description', models.CharField(max_length=100)),
                ('creation_date', models.DateTimeField()),
                ('available', models.BooleanField(default=True)),
                ('last_modified', models.DateTimeField()),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='compiler.user')),
            ],
        ),
        migrations.CreateModel(
            name='File',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('content', models.TextField()),
                ('info', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='compiler.fileinfo')),
                ('parent', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='compiler.directory')),
            ],
        ),
        migrations.AddField(
            model_name='directory',
            name='info',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='compiler.fileinfo'),
        ),
        migrations.AddField(
            model_name='directory',
            name='parent',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='compiler.directory'),
        ),
    ]
