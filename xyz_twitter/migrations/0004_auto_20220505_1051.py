# Generated by Django 3.2.2 on 2022-05-05 02:51

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('twitter', '0003_auto_20220430_0844'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='user',
            options={'ordering': ('-created_at',), 'verbose_name': '用户', 'verbose_name_plural': '用户'},
        ),
        migrations.AddField(
            model_name='tweet',
            name='url',
            field=models.URLField(blank=True, default='', max_length=255, verbose_name='URL地址'),
        ),
    ]
