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
    Cerberus threshold manager
"""

from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import ObjectDoesNotExist
from django.forms.models import model_to_dict
from werkzeug.exceptions import BadRequest, NotFound

from ...models import Category, ReportThreshold


def get_all():
    """ Get all threshold
    """
    return [model_to_dict(thres) for thres in ReportThreshold.all()]


def show(threshold_id):
    """ Get infos for specified threshold
    """
    try:
        threshold = ReportThreshold.get(id=threshold_id)
        return model_to_dict(threshold)
    except ValueError:
        raise BadRequest('Not a valid threshold id')
    except ObjectDoesNotExist:
        raise NotFound('Threshold not found')


def create(body):
    """ Create threshold
    """
    try:
        category = Category.get(name=body['category'])
        if ReportThreshold.filter(category=category).exists():
            raise BadRequest('Threshold already exists for this category')
        body['category'] = category
        threshold, created = ReportThreshold.get_or_create(**body)
    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist):
        raise BadRequest('Missing or invalid fields in body')
    if not created:
        raise BadRequest('Threshold already exists')
    return model_to_dict(threshold)


def update(threshold_id, body):
    """ Update threshold
    """
    try:
        threshold = ReportThreshold.get(id=threshold_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Threshold not found')
    try:
        body = {k: v for k, v in body.iteritems() if k in ['threshold', 'interval']}
        ReportThreshold.filter(pk=threshold.pk).update(**body)
        threshold = ReportThreshold.get(pk=threshold.pk)
    except (KeyError, FieldError, IntegrityError):
        raise BadRequest('Missing or invalid fields in body')
    return model_to_dict(threshold)


def destroy(threshold_id):
    """ Remove threshold
    """
    try:
        threshold = ReportThreshold.get(id=threshold_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Threshold not found')

    threshold.delete()
    return {'message': 'Threshold successfully removed'}
