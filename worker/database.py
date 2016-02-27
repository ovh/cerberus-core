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
    Database wrapper for worker
"""

import random
import re
import string
from datetime import datetime

from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned, ValidationError
from django.db import IntegrityError
from django.db.models import Q, ObjectDoesNotExist

from abuse.models import (Category, DefendantRevision, Defendant, EmailFilterTag, History,
                          DefendantHistory, Provider, Report, Service, Tag, Ticket, UrlStatus,
                          User)
from adapters.services.kpi.abstract import KPIServiceException
from factory.factory import ImplementationFactory
from parsing import regexp
from worker import Logger

BOT_USER = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
DEFENDANT_REVISION_FIELDS = [f.name for f in DefendantRevision._meta.fields]
SERVICE_FIELDS = [f.name for f in Service._meta.fields]


class MultipleDefendantWithSameCustomerId(Exception):
    """
        Raise if there's multiple defendant with same customerId in DB
    """
    def __init__(self, message):
        super(MultipleDefendantWithSameCustomerId, self).__init__(message)


def insert_url_status(item, direct_status, proxied_status, http_code, score):
    """
        Insert url status in db
    """
    UrlStatus.objects.create(**{
        'item': item,
        'directStatus': direct_status,
        'proxiedStatus': proxied_status,
        'httpCode': http_code,
        'score': score,
    })


def get_item_status_score(item_id, last=3):
    """
        Get item scoring
    """
    return UrlStatus.objects.filter(item_id=item_id).values_list('score', flat=True).order_by('-date')[:last]


def log_action_on_ticket(ticket, action, user=None):
    """
        Log ticket updates
    """
    if not user:
        user = BOT_USER

    History.objects.create(
        date=datetime.now(),
        ticket=ticket,
        user=user,
        action=action
    )

    search_closed = re.search('change status from .* to closed', action.lower())

    if search_closed and ImplementationFactory.instance.is_implemented('KPIServiceBase'):
        try:
            ImplementationFactory.instance.get_singleton_of('KPIServiceBase').close_ticket(ticket)
        except KPIServiceException as ex:
            Logger.error(unicode('Error while pushing KPI - %s' % (ex)))


def get_or_create_provider(email):
    """
        Create provider or get it if existing
    """
    provider = Provider.objects.get_or_create(email=email)[0]

    # For providers using special email addresses (e.g uniqueid-4942456@provider.com)
    # these addresses are trusted if the general *@provider is trusted
    for reg, val in regexp.PROVIDERS_GENERIC.iteritems():
        if reg.match(provider.email):
            try:
                prov = Provider.objects.get(email=val)
                if prov.trusted:
                    provider.trusted = True
                if prov.defaultCategory:
                    provider.defaultCategory = prov.defaultCategory
                provider.save()
                break
            except (KeyError, ObjectDoesNotExist):
                break

    return provider


def get_or_create_defendant(defendant_infos):
    """
        Create defendant or get it if exists
    """
    revision_infos = {k: v for k, v in defendant_infos.iteritems() if k in DEFENDANT_REVISION_FIELDS}
    customer_id = defendant_infos.pop('customerId')

    try:
        created = False
        if DefendantRevision.objects.filter(**revision_infos).count():
            revision = DefendantRevision.objects.filter(**revision_infos).last()
        else:
            revision = DefendantRevision.objects.create(**revision_infos)
            created = True
        defendants = Defendant.objects.filter(customerId=customer_id)
        if len(defendants) > 1:
            raise MultipleDefendantWithSameCustomerId('for customerId %s' % str(customer_id))
        if len(defendants) == 1:
            defendant = defendants.first()
        else:
            defendant = Defendant.objects.create(customerId=customer_id, details=revision)
        if created:
            defendant.details = revision
            defendant.save()
            DefendantHistory.objects.create(defendant=defendant, revision=revision)
    except ValidationError as ex:
        raise ValidationError(ex + " " + str(revision_infos))
    return defendant


def get_or_create_service(service_infos):
    """
        Create service or get it if exists
    """
    valid_infos = {}
    for key, value in service_infos.iteritems():
        if key in SERVICE_FIELDS:
            valid_infos[key] = value
    try:
        service, _ = Service.objects.get_or_create(**valid_infos)
    except MultipleObjectsReturned:
        service = Service.objects.filter(name=valid_infos['name'])[0]
    return service


def search_ticket(defendant, category, service):
    """
        Get ticket if exists
    """
    ticket = None

    tickets = Ticket.objects.filter(
        ~(Q(status='Closed')),
        defendant=defendant,
        category=category,
        service=service,
        update=True
    )
    if len(tickets):
        ticket = tickets[0]
    return ticket


def create_ticket(defendant, category, service, provider, attach_new=True):
    """
        Create ticket
    """
    # While publicId is not valid
    while True:
        try:
            public_id = ''.join(random.sample(string.ascii_uppercase.translate(None, 'AEIOUY'), 10))
            ticket = Ticket.objects.create(
                publicId=public_id,
                creationDate=datetime.now(),
                defendant=defendant,
                category=category,
                service=service,
                update=True,
            )
            if all((defendant, service, category)) and attach_new:
                Report.objects.filter(
                    service=service,
                    defendant=defendant,
                    category=category,
                    ticket=None,
                    status='New'
                ).update(
                    ticket=ticket,
                    status='Attached',
                )
            ticket.priority = provider.priority if provider.priority else 'Normal'
            ticket.save()
            log_new_ticket(ticket)
            break
        except (IntegrityError, ValueError):
            continue
    return ticket


def get_category(name):
    """
        Create category or get it if exists
    """
    return Category.objects.get(name=name)


def get_tags(provider, recipients, subject, body):
    """
        Check if email match tag filters
    """
    tags = []
    if not all((provider, subject, body)):
        return tags

    data = {
        'provider': provider.email,
        'recipients': ' '.join(recipients).lower() if recipients else '',
        'subject': subject.lower(),
        'body': body.lower(),
    }

    for eft in EmailFilterTag.objects.all():
        add = True
        for filtr in eft.filters.all():
            if filtr.value.lower() not in data[filtr.scope]:
                add = False
                break
        if add:
            tags.append(eft.tags.all())

    tags.append(provider.tags.all())
    tags = [i for sub in tags for i in sub]
    tags = list(set(tags))
    return tags


def add_phishing_blocked_tag(report):
    """
        Add Phishing blocked tag to report
    """
    try:
        tag = Tag.objects.get(tagType='Report', name=settings.TAGS['phishing_autoblocked'])
        report.tags.add(tag)
        report.save()
    except ObjectDoesNotExist:
        pass


def log_new_report(report):
    """
        Log report creation
    """
    Logger.debug(
        unicode('New report %d' % (report.id)),
        extra={
            'from': report.provider.email,
            'action': 'new report',
            'report': report.id,
        }
    )

    if ImplementationFactory.instance.is_implemented('KPIServiceBase'):
        try:
            ImplementationFactory.instance.get_singleton_of('KPIServiceBase').new_report(report)
        except KPIServiceException as ex:
            Logger.error(unicode('Error while pushing KPI - %s' % (ex)))


def log_new_ticket(ticket):
    """
        Log ticket creation
    """
    Logger.debug(
        str('new ticket %d' % (ticket.id)),
        extra={
            'ticket': ticket.id,
            'action': 'new ticket',
            'public_id': ticket.publicId
        }
    )

    if ImplementationFactory.instance.is_implemented('KPIServiceBase'):
        try:
            ImplementationFactory.instance.get_singleton_of('KPIServiceBase').new_ticket(ticket)
        except KPIServiceException as ex:
            Logger.error(unicode('Error while pushing KPI - %s' % (ex)))
