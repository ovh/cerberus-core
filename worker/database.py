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

import operator
import random
import re
import string

from datetime import datetime, timedelta

from django.conf import settings
from django.core.exceptions import MultipleObjectsReturned, ValidationError
from django.db import IntegrityError
from django.db.models import Q, ObjectDoesNotExist

from abuse.models import (Category, DefendantRevision, Defendant, EmailFilterTag, History,
                          DefendantHistory, Provider, Report, Service, Tag, Ticket, UrlStatus,
                          User)

from adapters.dao.customer.abstract import CustomerDaoException
from adapters.services.kpi.abstract import KPIServiceException
from factory.implementation import ImplementationFactory
from parsing import regexp
from utils import schema, utils
from worker import Logger

DEFENDANT_REVISION_FIELDS = [f.name for f in DefendantRevision._meta.fields]
SERVICE_FIELDS = [f.name for f in Service._meta.fields]


GENERIC_LOG_ACTION = (
    'add_item',
    'update_item',
    'delete_item',
    'add_proof',
    'update_proof',
    'delete_proof',
    'add_comment',
    'update_comment',
    'delete_comment',
)


PRIORITY_LEVEL = {
    'Low': 3,
    'Normal': 2,
    'High': 1,
    'Critical': 0,
}  # Lower, higher


class InvalidTicketHistoryAction(Exception):
    """
        Raise if the specified log action if not valid
    """
    def __init__(self, message):
        super(InvalidTicketHistoryAction, self).__init__(message)


class MultipleDefendantWithSameCustomerId(Exception):
    """
        Raise if there's multiple defendant with same customerId in DB
    """
    def __init__(self, message):
        super(MultipleDefendantWithSameCustomerId, self).__init__(message)


def insert_url_status(item, direct_status, proxied_status, http_code, score, is_phishing):
    """
        Insert url status in db
    """
    UrlStatus.objects.create(**{
        'item': item,
        'directStatus': direct_status,
        'proxiedStatus': proxied_status,
        'httpCode': http_code,
        'score': score,
        'isPhishing': is_phishing,
    })


def get_item_status_score(item_id, last=3):
    """
        Get item scoring
    """
    return UrlStatus.objects.filter(item_id=item_id).values_list('score', flat=True).order_by('-date')[:last]


def get_item_status_phishing(item_id, last=3):
    """
        Get item scoring
    """
    return UrlStatus.objects.filter(item_id=item_id).values_list('isPhishing', flat=True).order_by('-date')[:last]


def log_action_on_ticket(ticket=None, action=None, user=None, **kwargs):
    """
        Log ticket updates
    """
    if not user:
        user = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])

    log_msg = _get_log_message(ticket, action, user, **kwargs)

    History.objects.create(
        date=datetime.now(),
        ticket=ticket,
        user=user,
        action=log_msg,
        actionType=''.join(word.capitalize() for word in action.split('_')),
        ticketStatus=ticket.status,
    )

    if ImplementationFactory.instance.is_implemented('KPIServiceBase'):
        _generates_kpi_infos(ticket, log_msg)

    Logger.debug(
        unicode(action),
        extra={
            'ticket': ticket.id,
            'public_id': ticket.publicId,
            'user': user.username,
            'action': action,
        }
    )


def _get_log_message(ticket, action, user, **kwargs):

    action_execution_date = kwargs.get('action_execution_date')
    action_name = kwargs.get('action_name')
    close_reason = kwargs.get('close_reason')
    email = kwargs.get('email')
    new_ticket = kwargs.get('new_ticket')
    report = kwargs.get('report')
    tag_name = kwargs.get('tag_name')
    previous_value = kwargs.get('previous_value')
    new_value = kwargs.get('new_value')
    field = kwargs.get('property')
    threshold_count = kwargs.get('threshold_count')
    threshold_interval = kwargs.get('threshold_interval')
    campaign_name = kwargs.get('campaign_name')

    log_msg = None
    if action in GENERIC_LOG_ACTION:
        log_msg = '%s' % action.replace('_', ' ')
    elif action in ('add_tag', 'remove_tag'):
        log_msg = '%s %s' % (action.replace('_', ' '), tag_name)
    elif action == 'validate_phishtocheck':
        log_msg = 'validate PhishToCheck report %d' % report.id
    elif action == 'deny_phishtocheck':
        log_msg = 'deny PhishToCheck report %d' % report.id
    elif action == 'change_status':
        reason = ', reason : %s' % close_reason if close_reason else ''
        log_msg = 'change status from %s to %s%s' % (previous_value, new_value, reason)
    elif action == 'change_treatedby':
        before = previous_value if previous_value else 'nobody'
        after = new_value if new_value else 'nobody'
        log_msg = 'change treatedBy from %s to %s' % (before, after)
    elif action == 'send_email':
        log_msg = 'sent an email to %s' % email
    elif action == 'receive_email':
        log_msg = 'received an email from %s' % email
    elif action == 'attach_report':
        if new_ticket:
            log_msg = 'create this ticket with report %d from %s (%s ...)' % (report.id, report.provider.email, report.subject[:30])
        else:
            log_msg = 'attach report %d from %s (%s ...) to this ticket' % (report.id, report.provider.email, report.subject[:30])
    elif action == 'set_action':
        if action_execution_date:
            log_msg = 'set action: %s, execution %s' % (action_name, action_execution_date)
        else:
            log_msg = 'set action: %s, execution now' % action_name
    elif action == 'cancel_action':
        log_msg = 'cancel action: %s' % action_name
    elif action == 'update_property':
        log_msg = 'change %s from %s to %s' % (field, previous_value, new_value)
    elif action == 'create_threshold':
        log_msg = 'create this ticket with threshold (more than %s reports received in %s days)' % (threshold_count, threshold_interval)
    elif action == 'create_masscontact':
        log_msg = 'create this ticket with mass contact campaign %s' % campaign_name
    else:
        raise InvalidTicketHistoryAction('%s is not a valid log action' % action)

    return log_msg


def _generates_kpi_infos(ticket, action):
    """
        Generates KPI infos
    """
    search_assign = re.search('change treatedby from nobody to', action.lower())
    if search_assign:
        _generates_onassign_kpi(ticket)
        return

    search_closed = re.search('change status from .* to closed', action.lower())
    if search_closed:
        _generates_onclose_kpi(ticket)
        return

    search_create = re.search('create this ticket with report', action.lower())
    if search_create:
        _genereates_oncreate_kpi(ticket)
        return


def _generates_onassign_kpi(ticket):
    """
        Kpi on ticket assignation
    """
    try:
        ImplementationFactory.instance.get_singleton_of('KPIServiceBase').new_ticket_assign(ticket)
    except KPIServiceException as ex:
        Logger.error(unicode('Error while pushing KPI - %s' % (ex)))


def _generates_onclose_kpi(ticket):
    """
        Kpi on ticket close
    """
    try:
        ImplementationFactory.instance.get_singleton_of('KPIServiceBase').close_ticket(ticket)
    except KPIServiceException as ex:
        Logger.error(unicode('Error while pushing KPI - %s' % (ex)))


def _genereates_oncreate_kpi(ticket):
    """
        Kpi on ticket creation
    """
    Logger.debug(
        unicode('new ticket %d' % (ticket.id)),
        extra={
            'ticket': ticket.id,
            'action': 'new ticket',
            'public_id': ticket.publicId
        }
    )

    try:
        ImplementationFactory.instance.get_singleton_of('KPIServiceBase').new_ticket(ticket)
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
        raise ValidationError(str(ex) + " " + str(revision_infos))
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
    ).order_by(
        '-creationDate',
    )
    if len(tickets):
        ticket = tickets[0]
    return ticket


def create_ticket(defendant, category, service, priority='Normal', attach_new=True):
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
                priority=priority,
                update=True,
            )
            if all((defendant, service, category)) and attach_new:   # Automatically attach similar reports
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
            break
        except (IntegrityError, ValueError):
            continue
    return ticket


def set_ticket_higher_priority(ticket):
    """
        Set `abuse.models.Ticket` higher priority available through it's
        `abuse.models.Report`'s `abuse.models.Provider`
    """
    ticket_priority = 'Normal'

    priorities = list(set(ticket.reportTicket.all().values_list('provider__priority', flat=True)))
    for priority, _ in sorted(PRIORITY_LEVEL.items(), key=operator.itemgetter(1)):
        if priority in priorities:
            ticket_priority = priority
            break

    if ticket.defendant:  # Warning for new customer
        defendant = Defendant.objects.get(customerId=ticket.defendant.customerId)
        if defendant.details.creationDate >= datetime.now() - timedelta(days=30):
            if PRIORITY_LEVEL[ticket_priority] > PRIORITY_LEVEL['High']:
                ticket_priority = 'High'

    Logger.debug(unicode('set priority %s to ticket %d' % (ticket_priority, ticket.id)))
    ticket.priority = ticket_priority
    ticket.save()


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


def add_mass_contact_tag(ticket, campaign_name):
    """
        Add mass contact tag to report
    """
    try:
        tag, _ = Tag.objects.get_or_create(tagType='Ticket', name=campaign_name)
        ticket.tags.add(tag)
        ticket.save()
    except ObjectDoesNotExist:
        pass


def refresh_defendant_infos(defendant_id=None):
    """
        Try to update `abuse.models.Defendant`'s revision
    """
    try:
        defendant = Defendant.objects.get(id=defendant_id)
    except (AttributeError, ObjectDoesNotExist, ValueError):
        pass

    fresh_defendant_infos = None

    try:
        fresh_defendant_infos = ImplementationFactory.instance.get_singleton_of('CustomerDaoBase').get_customer_infos(defendant.customerId)
        schema.valid_adapter_response('CustomerDaoBase', 'get_customer_infos', fresh_defendant_infos)
        fresh_defendant_infos.pop('customerId', None)
        if DefendantRevision.objects.filter(**fresh_defendant_infos).count():
            revision = DefendantRevision.objects.filter(**fresh_defendant_infos).last()
        else:
            revision = DefendantRevision.objects.create(**fresh_defendant_infos)
            DefendantHistory.objects.create(defendant=defendant, revision=revision)
        defendant.details = revision
        defendant.save()
    except (CustomerDaoException, schema.InvalidFormatError, schema.SchemaNotFound):
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


def set_report_specificworkflow_tag(report, workflow_name):
    """
        Add workflow tag to `abuse.models.Report`
    """
    name = utils.string_to_underscore_case(workflow_name)
    report.tags.add(Tag.objects.get_or_create(
        codename=name,
        name='report:%s' % name,
        tagType='Report',
    )[0])
