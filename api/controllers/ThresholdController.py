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

from abuse.models import Category, ReportThreshold


def get_all():
    """ Get all threshold
    """
    return 200, [model_to_dict(thres) for thres in ReportThreshold.objects.all()]


def show(threshold_id):
    """ Get infos for specified threshold
    """
    try:
        threshold = ReportThreshold.objects.get(id=threshold_id)
        return 200, model_to_dict(threshold)
    except ValueError:
        return 400, {'status': 'Bad request', 'code': 400, 'message': 'Not a valid threshold id'}
    except ObjectDoesNotExist:
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Threshold not found'}


def create(body):
    """ Create threshold
    """
    try:
        category = Category.objects.get(name=body['category'])
        if ReportThreshold.objects.filter(category=category).exists():
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Threshold already exists for this category'}
        body['category'] = category
        threshold, created = ReportThreshold.objects.get_or_create(**body)
    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing or invalid fields in body'}
    if not created:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Threshold already exists'}
    return 200, model_to_dict(threshold)


def update(threshold_id, body):
    """ Update threshold
    """
    try:
        threshold = ReportThreshold.objects.get(id=threshold_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Threshold not found'}
    try:
        body = {k: v for k, v in body.iteritems() if k in ['threshold', 'interval']}
        ReportThreshold.objects.filter(pk=threshold.pk).update(**body)
        threshold = ReportThreshold.objects.get(pk=threshold.pk)
    except (KeyError, FieldError, IntegrityError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing or invalid fields in body'}
    return 200, model_to_dict(threshold)


def destroy(threshold_id):
    """ Remove threshold
    """
    try:
        threshold = ReportThreshold.objects.get(id=threshold_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Threshold not found'}

    threshold.delete()
    return 200, {'status': 'OK', 'code': 200, 'message': 'Threshold successfully removed'}
