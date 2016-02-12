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
    Cerberus categories manager
"""

from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import ObjectDoesNotExist, ProtectedError
from django.forms.models import model_to_dict

from abuse.models import AbusePermission, Category


def index(**kwargs):
    """ Get all categories
    """

    if 'user' in kwargs:
        user = kwargs['user']
        allowed = AbusePermission.objects.filter(user=user.id).values_list('category')
        cats = Category.objects.filter(name__in=allowed)
    else:
        cats = Category.objects.all()

    return 200, [model_to_dict(c) for c in cats]


def show(cat):
    """ Get infos for specified category
    """
    result = Category.objects.filter(name=cat)
    if not result:
        return 404, {'status': 'Not Found', 'code': 404}

    return 200, model_to_dict(result[0])


def create(cat):
    """ Create new category
    """
    try:
        category, created = Category.objects.get_or_create(**cat)
    except (FieldError, IntegrityError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid fields in body'}
    return 201, model_to_dict(category)


def update(cat, body):
    """ Update category
    """
    try:
        category = Category.objects.get(name=cat)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    try:
        Category.objects.filter(pk=category.pk).update(**body)
        category = Category.objects.get(pk=category.pk)
    except (FieldError, IntegrityError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid fields in body'}
    return 200, model_to_dict(category)


def destroy(cat):
    """ Remove category
    """
    try:
        category = Category.objects.get(name=cat)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    try:
        category.delete()
        return 200, {'status': 'OK', 'code': 200, 'message': 'Category successfully removed'}
    except ProtectedError:
        return 403, {'status': 'Forbidden', 'message': 'Category still referenced in reports/tickets', 'code': 403}
