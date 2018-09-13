# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016, OVH SAS
#
# This file is part of Cerberus-core.
#
# Cerberus-core is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""
    Cache related functions for Cerberus
"""

import json

from functools import wraps
from time import sleep

from django.contrib.auth.models import User
from redis import ConnectionError as RedisError
from redis import Redis


class RedisHandler(object):

    client = None

    @classmethod
    def set_up(cls, config):

        cls.client = Redis(
            host=config['host'],
            port=int(config['port']),
            password=config['password']
        )

    @classmethod
    def keys(cls):

        return cls.client.keys()

    @classmethod
    def blpop(cls, queue):

        return cls.client.blpop(queue)

    @classmethod
    def llen(cls, queue):

        return cls.client.llen(queue)

    @classmethod
    def ldump(cls, queue):

        return cls.client.lrange(queue, 0, -1)

    @classmethod
    def lrem(cls, queue, val):

        cls.client.lrem(queue, val)

    @classmethod
    def rpush(cls, queue, data):

        cls.client.rpush(queue, data)


def redis_lock(key):
    """
        Decorator using redis as a lock manager

        :param str string: The redis key to monitor
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            count = 0
            while RedisHandler.client.exists(key):
                if count > 180:
                    raise Exception('%s seems locked' % key)
                count += 1
                sleep(1)
            RedisHandler.client.set(key, True)
            try:
                return func(*args, **kwargs)
            finally:
                RedisHandler.client.delete(key)
        return wrapper
    return decorator


def push_notification(data, user=None):
    """
        Push notification to Cerberus user(s)

        :param dict data: The content of the notification
    """
    notification_queue = 'cerberus:notification:{}'
    if not user:
        usernames = User.objects.all().values_list('username', flat=True)
        notif_queues = [notification_queue.format(name) for name in usernames]
    else:
        notif_queues = [notification_queue.format(user.username)]

    for notif_queue in notif_queues:
        try:
            RedisHandler.rpush(notif_queue, data)
        except RedisError:
            pass


def get_user_notifications(username, limit=3):
    """
        Get notifications for given user

        :param str username: The username of the user
        :param int limit: The number of notifications to return
        :rtype: list
        :return: A list of dict
    """
    notification_queue = 'cerberus:notification:i{}'.format(username)
    response = []

    if not limit:
        return response

    for _ in xrange(0, limit):
        if RedisHandler.llen(notification_queue) == 0:
            break
        notification = RedisHandler.blpop(notification_queue)[1]
        response.append(json.loads(notification))

    return response
