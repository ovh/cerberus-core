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
from werkzeug.exceptions import BadRequest, Forbidden, NotFound

from ...models import AbusePermission, Category


def get_categories(**kwargs):
    """ Get all categories
    """

    if 'user' in kwargs:
        user = kwargs['user']
        allowed = AbusePermission.filter(
            user=user.id
        ).values_list('category')
        cats = Category.filter(name__in=allowed)
    else:
        cats = Category.all()

    return [model_to_dict(c) for c in cats]


def show(cat):
    """ Get infos for specified category
    """
    result = Category.filter(name=cat)
    if not result:
        raise NotFound('Category not found')

    return model_to_dict(result[0])


def create(cat):
    """ Create new category
    """
    try:
        category, _ = Category.get_or_create(**cat)
    except (FieldError, IntegrityError):
        raise BadRequest('Invalid fields in body')
    return model_to_dict(category)


def update(cat, body):
    """ Update category
    """
    try:
        category = Category.get(name=cat)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Category not found')
    try:
        Category.filter(pk=category.pk).update(**body)
        category = Category.get(pk=category.pk)
    except (FieldError, IntegrityError):
        raise BadRequest('Invalid fields in body')
    return model_to_dict(category)


def destroy(cat):
    """ Remove category
    """
    try:
        category = Category.get(name=cat)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Category not found')
    try:
        category.delete()
        return {'message': 'Category successfully removed'}
    except ProtectedError:
        raise Forbidden('Category still referenced in reports/tickets')
