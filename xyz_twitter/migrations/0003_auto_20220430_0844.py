# Generated by Django 3.2.2 on 2022-04-30 00:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('twitter', '0002_auto_20220427_0725'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='name',
            field=models.CharField(blank=True, default='', max_length=255, verbose_name='名称'),
        ),
        migrations.AlterField(
            model_name='user',
            name='tid',
            field=models.CharField(blank=True, default='', max_length=32, verbose_name='推特编号'),
        ),
    ]
