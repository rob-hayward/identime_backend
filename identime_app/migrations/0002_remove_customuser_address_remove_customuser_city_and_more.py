# Generated by Django 4.2.9 on 2024-01-05 13:53

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('identime_app', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='customuser',
            name='address',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='city',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='country',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='is_verified',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='last_visited',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='phone_number',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='post_code',
        ),
        migrations.RemoveField(
            model_name='customuser',
            name='preferred_name',
        ),
    ]
