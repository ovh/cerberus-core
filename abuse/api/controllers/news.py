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
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from ...models import News


def get_news(**kwargs):
    """ Get all news
    """
    filters = {}
    if kwargs.get("filters"):
        try:
            filters = json.loads(unquote(unquote(kwargs["filters"])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex))

    try:
        limit = int(filters["paginate"]["resultsPerPage"])
        offset = int(filters["paginate"]["currentPage"])
    except (KeyError, ValueError):
        limit = 10
        offset = 1

    try:
        nb_record_filtered = News.count()
        news_list = (
            News.filter().order_by("-date").values(*[f.name for f in News._meta.fields])
        )
        news_list = news_list[(offset - 1) * limit : limit * offset]
        len(news_list)  # Force django to evaluate query now
    except (
        AttributeError,
        KeyError,
        FieldError,
        SyntaxError,
        TypeError,
        ValueError,
    ) as ex:
        raise BadRequest(str(ex))

    for news in news_list:
        if news.get("author", None):
            news["author"] = User.objects.get(id=news["author"]).username
        if news.get("date", None):
            news["date"] = time.mktime(news["date"].timetuple())

    resp = {"news": list(news_list)}
    resp["newsCount"] = nb_record_filtered

    return resp


def show(news_id):
    """ Get infos for specified news
    """
    try:
        news = News.filter(id=news_id).values(*[f.name for f in News._meta.fields])[0]
        if news.get("author", None):
            news["author"] = User.objects.get(id=news["author"]).username
        if news.get("date", None):
            news["date"] = time.mktime(news["date"].timetuple())
    except (IndexError, ValueError):
        return BadRequest("Not a valid news id")
    except ObjectDoesNotExist:
        return NotFound("Author not found")

    return news


def create(body, user):
    """ Create news
    """
    try:
        body.pop("author", None)
        body["author"] = user
        news, created = News.get_or_create(**body)
    except (KeyError, FieldError, IntegrityError):
        raise BadRequest("Invalid fields in body")
    if not created:
        raise BadRequest("News already exists")
    return show(news.id)


def update(news_id, body, user):
    """ Update news
    """
    try:
        if user.is_superuser:
            news = News.get(id=news_id)
        else:
            news = News.get(id=news_id, author__id=user.id)
    except (ObjectDoesNotExist, ValueError):
        return NotFound("News not found")
    try:
        body = {
            k: v for k, v in body.iteritems() if k not in ["author", "date", "tags"]
        }
        News.filter(pk=news.pk).update(**body)
        news = News.get(pk=news.pk)
    except (KeyError, FieldError, IntegrityError):
        raise BadRequest("Invalid fields in body")
    return model_to_dict(news)


def destroy(news_id):
    """ Remove news
    """
    try:
        news = News.get(id=news_id)
    except (ObjectDoesNotExist, ValueError):
        return NotFound("News not found")
    try:
        news.delete()
        return {"message": "News successfully removed"}
    except ProtectedError:
        raise Forbidden("News still referenced in reports/tickets")
