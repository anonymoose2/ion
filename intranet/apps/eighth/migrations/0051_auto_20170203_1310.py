# -*- coding: utf-8 -*-
# Generated by Django 1.10.3 on 2017-02-03 18:10
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('eighth', '0050_eighthwaitlist_block'),
    ]

    operations = [
        migrations.AddField(
            model_name='eighthactivity',
            name='finance',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='historicaleighthactivity',
            name='finance',
            field=models.BooleanField(default=False),
        ),
    ]
