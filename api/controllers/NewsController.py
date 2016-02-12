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


""" Cerberus news manager
"""

import json
import time
from urllib import unquote

from django.contrib.auth.models import User
from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import ObjectDoesNotExist, ProtectedError
from django.forms.models import model_to_dict

from abuse.models import News


def index(**kwargs):
    """ Get all news
    """
    filters = {}
    if 'filters' in kwargs:
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex)}

    try:
        limit = int(filters['paginate']['resultsPerPage'])
        offset = int(filters['paginate']['currentPage'])
    except (KeyError, ValueError):
        limit = 10
        offset = 1

    try:
        nb_record_filtered = News.objects.count()
        news_list = News.objects.filter().order_by('-date').values(*[f.name for f in News._meta.fields])
        news_list = news_list[(offset - 1) * limit:limit * offset]
        len(news_list)  # Force django to evaluate query now
    except (AttributeError, KeyError, FieldError, SyntaxError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex)}

    for news in news_list:
        if news.get('author', None):
            news['author'] = User.objects.get(id=news['author']).username
        if news.get('date', None):
            news['date'] = time.mktime(news['date'].timetuple())

    resp = {'news': [dict(n) for n in news_list]}
    resp['newsCount'] = nb_record_filtered

    return 200, resp


def show(news_id):
    """ Get infos for specified news
    """
    try:
        news = News.objects.filter(id=news_id).values(*[f.name for f in News._meta.fields])[0]
        if news.get('author', None):
            news['author'] = User.objects.get(id=news['author']).username
        if news.get('date', None):
            news['date'] = time.mktime(news['date'].timetuple())
    except (IndexError, ValueError):
        return 400, {'status': 'Bad request', 'code': 400, 'message': 'Not a valid news id'}
    except ObjectDoesNotExist:
        return 400, {'status': 'Bad request', 'code': 400, 'message': 'Author not found'}

    return 200, news


def create(body, user):
    """ Create news
    """
    try:
        body.pop('author', None)
        body['author'] = user
        news, created = News.objects.get_or_create(**body)
    except (KeyError, FieldError, IntegrityError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid fields in body'}
    if not created:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'News already exists'}
    return show(news.id)


def update(news_id, body, user):
    """ Update news
    """
    try:
        if user.is_superuser:
            news = News.objects.get(id=news_id)
        else:
            news = News.objects.get(id=news_id, author__id=user.id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    try:
        body = {k: v for k, v in body.iteritems() if k not in ['author', 'date', 'tags']}
        News.objects.filter(pk=news.pk).update(**body)
        news = News.objects.get(pk=news.pk)
    except (KeyError, FieldError, IntegrityError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid fields in body'}
    return 200, model_to_dict(news)


def destroy(news_id):
    """ Remove news
    """
    try:
        news = News.objects.get(id=news_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    try:
        news.delete()
        return 200, {'status': 'OK', 'code': 200, 'message': 'News successfully removed'}
    except ProtectedError:
        return 403, {'status': 'Forbidden', 'message': 'News still referenced in reports/tickets', 'code': 403}
