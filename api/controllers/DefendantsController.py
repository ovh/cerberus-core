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
    Cerberus defendant manager
"""

from collections import Counter
from time import mktime, time

from django.core.exceptions import FieldError
from django.db import IntegrityError
from django.db.models import ObjectDoesNotExist, Q
from django.forms.models import model_to_dict

from abuse.models import (Category, Defendant, DefendantComment,
                          DefendantHistory, DefendantRevision, Report, Stat,
                          Tag, Ticket)
from adapters.dao.customer.abstract import CustomerDaoException
from factory.factory import ImplementationFactory
from utils import schema, utils
from worker import database

DEFENDANT_FIELDS = [fld.name for fld in Defendant._meta.fields]


def show(defendant_id):
    """
        Get defendant
    """
    try:
        defendant = Defendant.objects.get(id=defendant_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}

    # BTW, refresh defendant infos
    utils.default_queue.enqueue('database.refresh_defendant_infos', defendant_id=defendant.id)

    # Flat details
    defendant_dict = model_to_dict(defendant)
    details = model_to_dict(defendant.details)
    details.pop('id')  # Else override defendant id with details id ....
    defendant_dict.update(details)

    # Add comments
    defendant_dict['comments'] = [{
        'id': c.comment.id,
        'user': c.comment.user.username,
        'date': mktime(c.comment.date.timetuple()),
        'comment': c.comment.comment
    } for c in DefendantComment.objects.filter(defendant=defendant.id).order_by('-comment__date')]

    if defendant_dict.get('creationDate', None):
        defendant_dict['creationDate'] = defendant_dict['creationDate'].strftime("%d/%m/%y")

    # Add tags
    tags = Defendant.objects.get(id=defendant.id).tags.all()
    defendant_dict['tags'] = [model_to_dict(tag) for tag in tags]

    return 200, defendant_dict


def add_tag(defendant_id, body, user):
    """ Add defendant tag
    """
    try:
        tag = Tag.objects.get(**body)
        defendant = Defendant.objects.get(id=defendant_id)

        if defendant.__class__.__name__ != tag.tagType:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid tag for defendant'}

        for defendt in Defendant.objects.filter(customerId=defendant.customerId):

            defendt.tags.add(tag)
            defendt.save()
            for ticket in defendt.ticketDefendant.all():
                database.log_action_on_ticket(
                    ticket=ticket,
                    action='add_tag',
                    user=user,
                    tag_name=tag.name
                )

    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}

    code, resp = show(defendant_id)
    return code, resp


def remove_tag(defendant_id, tag_id, user):
    """ Remove defendant tag
    """
    try:
        tag = Tag.objects.get(id=tag_id)
        defendant = Defendant.objects.get(id=defendant_id)

        for defendt in Defendant.objects.filter(customerId=defendant.customerId):
            defendt.tags.remove(tag)
            defendt.save()

            for ticket in defendt.ticketDefendant.all():
                database.log_action_on_ticket(
                    ticket=ticket,
                    action='remove_tag',
                    user=user,
                    tag_name=tag.name
                )

    except (ObjectDoesNotExist, FieldError, IntegrityError, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}

    code, resp = show(defendant_id)
    return code, resp


def get_or_create(customer_id=None):
    """
        Get or create defendant
        Attach previous tag if updated defendant infos
    """
    if not customer_id:
        return None

    defendant = None
    try:
        defendant = Defendant.objects.get(customerId=customer_id)
    except (TypeError, ObjectDoesNotExist):
        try:
            revision_infos = ImplementationFactory.instance.get_singleton_of('CustomerDaoBase').get_customer_infos(customer_id)
            schema.valid_adapter_response('CustomerDaoBase', 'get_customer_infos', revision_infos)
            revision_infos.pop('customerId', None)
        except (CustomerDaoException, schema.InvalidFormatError, schema.SchemaNotFound):
            return None

        revision, _ = DefendantRevision.objects.get_or_create(**revision_infos)
        defendant = Defendant.objects.create(customerId=customer_id, details=revision)
        DefendantHistory.objects.create(defendant=defendant, revision=revision)

    return defendant


def get_defendant_top20():
    """ Get top 20 defendant with open tickets/reports
    """
    ticket = Ticket.objects.filter(~Q(defendant=None), ~Q(status='Closed')).values_list('defendant__id', flat=True)
    ticket = Counter(ticket).most_common(20)
    report = Report.objects.filter(~Q(defendant=None), ~Q(status='Archived')).values_list('defendant__id', flat=True)
    report = Counter(report).most_common(20)

    res = {'report': [], 'ticket': []}
    for kind in res.keys():
        for defendant_id, count in locals()[kind]:
            defendant = Defendant.objects.get(id=defendant_id)
            res[kind].append({
                'id': defendant.id,
                'customerId': defendant.customerId,
                'email': defendant.details.email,
                'count': count
            })
    return 200, res


def get_defendant_services(customer_id):
    """
        Get services for a defendant
    """
    try:
        response = ImplementationFactory.instance.get_singleton_of('CustomerDaoBase').get_customer_services(customer_id)
        schema.valid_adapter_response('CustomerDaoBase', 'get_customer_services', response)
    except (CustomerDaoException, schema.InvalidFormatError, schema.SchemaNotFound) as ex:
        return 500, {'status': 'Internal Server Error', 'code': 500, 'message': str(ex)}

    return 200, response


def get_defendant_stats(**kwargs):
    """
        Get abuse stats for a defendant
    """
    if 'defendant' in kwargs:
        customer_id = kwargs['defendant']
    else:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'No defendant specified'}

    if 'nature' in kwargs:
        nature = kwargs['nature']
    else:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'No type specified'}

    defendants = Defendant.objects.filter(customerId=customer_id)
    if not len(defendants):
        return 404, {'status': 'Not Found', 'code': 404}

    resp = []
    now = int(time())

    for category in Category.objects.all():
        data = {'name': category.name}
        stats = Stat.objects.filter(defendant__in=defendants, category=category.name).order_by('date')
        #  * 1000 for HighCharts
        data['data'] = [[mktime(stat.date.timetuple()) * 1000, getattr(stat, nature)] for stat in stats]
        try:
            data['data'].append([now * 1000, data['data'][-1][1]])
        except IndexError:
            pass
        resp.append(data)

    return 200, resp
