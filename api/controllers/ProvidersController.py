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
    Providers manager
"""

import json
import operator
from urllib import unquote

from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import Q, ObjectDoesNotExist, ProtectedError
from django.forms.models import model_to_dict

from abuse.models import Category, Provider, Tag

PROVIDER_FIELDS = [field.name for field in Provider._meta.fields]


def index(**kwargs):
    """ Get all providers in db
    """
    filters = {}

    if 'filters' in kwargs:
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}
    try:
        limit = int(filters['paginate']['resultsPerPage'])
        offset = int(filters['paginate']['currentPage'])
    except KeyError:
        limit = 10
        offset = 1

    try:
        where = __generate_request_filter(filters)
    except (AttributeError, KeyError, IndexError, FieldError, SyntaxError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}

    try:
        sort = ['-' + k if v < 0 else k for k, v in filters['sortBy'].iteritems()]
    except KeyError:
        sort = ['email']

    if 'queryFields' in filters:
        fields = filters['queryFields']
    else:
        fields = [f.name for f in Provider._meta.fields]

    try:
        count = Provider.objects.filter(where).count()
        providers = Provider.objects.filter(where).values('email', 'tags', *fields).order_by(*sort)
        providers = providers[(offset - 1) * limit:limit * offset]
        len(providers)  # Force django to evaluate query now
    except (KeyError, FieldError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}

    for provider in providers:
        provider.pop('apiKey', None)
        tags = Provider.objects.get(email=provider['email']).tags.all()
        provider['tags'] = [model_to_dict(tag) for tag in tags]

    return 200, {'providers': list(providers), 'providersCount': count}


def __generate_request_filter(filters):
    """ Generates filters from filter query string
    """
    where = [Q()]
    if 'where' in filters and len(filters['where']):
        keys = set(k for k in filters['where'])
        if 'like' in keys:
            for i in filters['where']['like']:
                for key, val in i.iteritems():
                    field = key + '__icontains'
                    where.append(reduce(operator.or_, [Q(**{field: val[0]})]))
        where = reduce(operator.and_, where)
    else:
        where = reduce(operator.and_, where)
    return where


def show(provider_email):
    """ Get one provider
    """
    try:
        provider = Provider.objects.get(email=provider_email)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Provider does not exist'}

    provider = model_to_dict(provider)
    provider.pop('apiKey', None)
    tags = Provider.objects.get(email=provider['email']).tags.all()
    provider['tags'] = [model_to_dict(tag) for tag in tags]

    return 200, provider


def create(body):
    """ Create provider
    """
    if 'email' not in body:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Email field required'}
    if len(Provider.objects.filter(email=body['email'])) > 1:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Provider already exists'}

    try:
        cat = None
        if body.get('defaultCategory'):
            cat = Category.objects.get(name=body['defaultCategory'])
        body.pop('defaultCategory', None)
        body = {k: v for k, v in body.iteritems() if k in PROVIDER_FIELDS}
        provider = Provider.objects.create(defaultCategory=cat, **body)
        return 201, model_to_dict(provider)
    except (FieldError, IntegrityError, ObjectDoesNotExist) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}


def update(prov, body):
    """ Update provider infos
    """
    try:
        provider = Provider.objects.get(email=prov)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Provider does not exist'}
    try:
        body = {k: v for k, v in body.iteritems() if k in PROVIDER_FIELDS}
        cat = None
        if body.get('defaultCategory'):
            cat = Category.objects.get(name=body['defaultCategory'])
        body.pop('defaultCategory', None)
        Provider.objects.filter(pk=provider.pk).update(defaultCategory=cat, **body)
        provider = Provider.objects.get(pk=provider.pk)
    except (FieldError, IntegrityError, ObjectDoesNotExist) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}
    return 200, model_to_dict(provider)


def destroy(prov):
    """ Remove provider
    """
    try:
        provider = Provider.objects.filter(email=prov)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    try:
        provider.delete()
        return 200, {'status': 'OK', 'code': 200, 'message': 'Provider successfully removed'}
    except ProtectedError:
        return 403, {'status': 'Provider still referenced in reports', 'code': 403}


def get_provider_by_key(key):
    """ Return provider associated with API key
    """
    try:
        provider = Provider.objects.get(apiKey=key)
        return provider
    except (ObjectDoesNotExist, TypeError, ValueError):
        pass
    return None


def get_priorities():
    """ Get provider priorities
    """
    return [{'label': p[0]} for p in Provider.PROVIDER_PRIORITY]


def add_tag(provider_email, body):
    """ Add provider tag
    """
    try:
        tag = Tag.objects.get(**body)
        provider = Provider.objects.get(email=provider_email)

        if provider.__class__.__name__ != tag.tagType:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid tag for provider'}

        provider.tags.add(tag)
        provider.save()

    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    return 200, model_to_dict(provider)


def remove_tag(provider_email, tag_id):
    """ Remove defendant tag
    """
    try:
        tag = Tag.objects.get(id=tag_id)
        provider = Provider.objects.get(email=provider_email)

        if provider.__class__.__name__ != tag.tagType:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid tag for provider'}

        provider.tags.remove(tag)
        provider.save()

    except (ObjectDoesNotExist, FieldError, IntegrityError, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    return 200, model_to_dict(provider)
