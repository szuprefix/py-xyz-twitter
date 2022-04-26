# -*- coding:utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.models import User
from xyz_util import modelutils
from . import choices


class User(models.Model):
    class Meta:
        verbose_name_plural = verbose_name = "用户"
        ordering = ('-created_at', '-create_time',)

    user = models.ForeignKey(User, verbose_name=User._meta.verbose_name, related_name="twitter_users", blank=True,
                             null=True,
                             on_delete=models.PROTECT)
    screen_name = models.CharField("帐号名称", max_length=255,  unique=True)
    tid = models.CharField('推特编号', max_length=32, unique=True)
    name = models.CharField("名称", max_length=255, blank=False)
    url = models.URLField('URL地址', max_length=255, blank=True, default='')
    avatar = models.URLField('头像', max_length=255, blank=True, default='')
    description = models.CharField("简介", max_length=255, blank=True, default="")
    detail = modelutils.JSONField("内容对象", blank=True, null=True)
    created_at = models.DateTimeField("推特注册时间", blank=True, null=True)
    create_time = models.DateTimeField("创建时间", auto_now_add=True)
    is_active = models.BooleanField("有效", blank=False, default=True)

    def __str__(self):
        return self.screen_name

    def sync_all_tweets(self):
        from .helper import sync_user_tweets
        sync_user_tweets(self)


class Tweet(models.Model):
    class Meta:
        verbose_name_plural = verbose_name = "推文"
        ordering = ('-is_active', '-created_at', '-create_time',)

    user = models.ForeignKey(User, verbose_name=User._meta.verbose_name, related_name="tweets",
                             on_delete=models.PROTECT)
    tid = models.CharField('推特编号', max_length=32, blank=True, unique=True)
    full_text = models.TextField("名称", blank=False)
    created_at = models.DateTimeField("推特创建时间", blank=True, null=True)
    create_time = models.DateTimeField("创建时间", auto_now_add=True)
    is_active = models.BooleanField("有效", blank=False, default=True)

    def __str__(self):
        return self.full_text