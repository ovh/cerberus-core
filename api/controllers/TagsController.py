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
    Cerberus tags manager
"""

import operator

from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import Q, ObjectDoesNotExist, ProtectedError
from django.forms.models import model_to_dict

from abuse.models import Tag

TAG_TYPE = [t[0] for t in Tag.TAG_TYPE]


def index(**kwargs):
    """ Get all tags
    """
    where = [Q()]
    if 'tagType' in kwargs:
        where.append(Q(tagType__iexact=kwargs['tagType']))

    where = reduce(operator.and_, where)
    tags = Tag.objects.filter(where)
    return 200, [model_to_dict(tag) for tag in tags]


def show(tag_id):
    """ Get tag
    """
    try:
        tag = Tag.objects.get(id=tag_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    return 200, model_to_dict(tag)


def create(body):
    """ Create new tag
    """
    try:
        body.pop('id', None)
        if body.get('tagType') not in TAG_TYPE:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid or missing tag type'}

        existing = [tag.lower() for tag in Tag.objects.all().values_list('name', flat=True)]
        if body['name'].lower().strip() in existing:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Tag already exists'}
        body['codename'] = body['name'].lower().replace(' ', '_')
        tag = Tag.objects.get_or_create(**body)[0]
    except (AttributeError, KeyError, FieldError, IntegrityError, ValueError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid fields in body'}
    return 201, model_to_dict(tag)


def update(tag_id, body):
    """ Update category
    """
    try:
        tag = Tag.objects.get(id=tag_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    try:
        body.pop('id', None)

        existing = [tg.lower() for tg in Tag.objects.exclude(id=tag.id).values_list('name', flat=True)]
        if body['name'].lower().strip() in existing:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Tag already exists'}

        Tag.objects.filter(pk=tag.pk).update(**body)
        tag = Tag.objects.get(pk=tag.pk)
    except (AttributeError, KeyError, FieldError, IntegrityError, ValueError, TypeError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid fields in body'}
    return 200, model_to_dict(tag)


def destroy(tag_id):
    """ Remove tag
    """
    try:
        tag = Tag.objects.get(id=tag_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    try:
        tag.delete()
        return 200, {'status': 'OK', 'code': 200, 'message': 'Tag successfully removed'}
    except ProtectedError:
        return 403, {'status': 'Forbidden', 'message': 'Tag still referenced in reports/tickets', 'code': 403}


def get_tag_type():
    """ Get tag type
    """
    return [{'label': v} for _, v in Tag.TAG_TYPE]
