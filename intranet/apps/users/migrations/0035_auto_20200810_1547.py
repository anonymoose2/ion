# Generated by Django 2.2.13 on 2020-08-10 19:47

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0034_remove_userdarkmodeproperties__dark_mode_unlocked'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='userproperties',
            name='_birthday',
        ),
        migrations.RemoveField(
            model_name='userproperties',
            name='parent_show_birthday',
        ),
        migrations.RemoveField(
            model_name='userproperties',
            name='self_show_birthday',
        ),
    ]
