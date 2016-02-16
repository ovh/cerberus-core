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
    Cerberus tickets manager
"""

import json
import operator
import random
import re
import string
import time
from copy import deepcopy
from datetime import datetime, timedelta
from urllib import unquote

from django.contrib.auth.models import User
from django.core.exceptions import FieldError, MultipleObjectsReturned
from django.db import IntegrityError, transaction
from django.db.models import Q, Count, FieldDoesNotExist, ObjectDoesNotExist
from django.forms.models import model_to_dict
from netaddr import AddrConversionError, AddrFormatError, IPNetwork

import DefendantsController
import GeneralController
import ProvidersController
from abuse.models import (AbusePermission, ServiceAction, ServiceActionJob,
                          ContactedProvider, Defendant, History, Proof, Report,
                          Resolution, Service, Tag, Ticket, TicketComment)
from adapters.services.action.abstract import ActionServiceException
from adapters.services.mailer.abstract import MailerServiceException
from adapters.services.search.abstract import SearchServiceException
from factory.factory import ImplementationFactory
from utils import utils

IP_CIDR_RE = re.compile(r"(?<!\d\.)(?<!\d)(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}(?!\d|(?:\.\d))")
STATUS = [status[0].lower() for status in Ticket.TICKET_STATUS]


def index(**kwargs):
    """
        Main endpoint, get all tickets from db and eventually contains
        filters (json format) in query like sortBy, where ...
    """

    # Parse filters from request
    filters = {}
    if kwargs.get('filters'):
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}, 0
    try:
        limit = int(filters['paginate']['resultsPerPage'])
        offset = int(filters['paginate']['currentPage'])
    except KeyError:
        limit = 10
        offset = 1

    # Generate Django filter based on parsed filters
    try:
        where = __generate_request_filters(filters, kwargs['user'], kwargs.get('treated_by'))
    except (AttributeError, KeyError, FieldError, SyntaxError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}, 0

    # Try to identify sortby in request
    sort = []
    if filters.get('sortBy') and filters['sortBy'].get('attachedReportsCount'):
        if filters['sortBy']['attachedReportsCount'] < 0:
            sort.append('-attachedReportsCount')
        else:
            sort.append('attachedReportsCount')
        filters['sortBy'].pop('attachedReportsCount', None)

    try:
        sort += ['-' + k if v < 0 else k for k, v in filters['sortBy'].iteritems()]
    except KeyError:
        sort += ['id']

    try:
        fields = filters['queryFields']
    except KeyError:
        fields = [fld.name for fld in Ticket._meta.fields]

    fields.append('id')
    try:
        fields = list(set(fields))
        nb_record_filtered = Ticket.objects.filter(where).distinct().count()
        tickets = Ticket.objects.filter(where).values(*fields).annotate(
            attachedReportsCount=Count('reportTicket')).order_by(*sort)
        tickets = tickets[(offset - 1) * limit:limit * offset]
        len(tickets)  # Force django to evaluate query now
    except (AttributeError, KeyError, FieldError, SyntaxError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}, 0

    __format_ticket_response(tickets)
    return 200, [dict(ticket) for ticket in tickets], nb_record_filtered


def __generate_request_filters(filters, user=None, treated_by=None):
    """
        Generates filters base on filter query string
    """
    # Mapping JSON fields name to django syntax
    relation_field = {
        'ticketsTag': 'tags__name',
        'reportsTag': 'reportTicket__tags__name',
        'treatedBy': 'treatedBy__username',
        'defendantCustomerId': 'defendant__customerId',
        'defendantCountry': 'defendant__country',
        'defendantEmail': 'defendant__email',
        'defendantTag': 'defendant__tags__name',
        'providerEmail': 'reportTicket__provider__email',
        'providerTag': 'reportTicket__provider__tags__name',
        'itemRawItem': 'reportTicket__reportItemRelatedReport__rawItem',
        'itemIpReverse': 'reportTicket__reportItemRelatedReport__ipReverse',
        'itemFqdnResolved': 'reportTicket__reportItemRelatedReport__fqdnResolved',
    }

    where = [Q()]
    if treated_by:
        where.append(Q(treatedBy=treated_by))

    # Add SearchService results if fulltext search
    try:
        for field in filters['where']['like']:
            for key, value in field.iteritems():
                if key == 'fulltext':
                    if ImplementationFactory.instance.is_implemented('SearchServiceBase'):
                        add_search_filters(filters, value[0])
                    filters['where']['like'].remove({key: value})
                    break
    except KeyError:
        pass

    # Generates Django query filter
    if 'where' in filters and len(filters['where']):
        keys = set(k for k in filters['where'])
        if 'in' in keys:
            for param in filters['where']['in']:
                for key, val in param.iteritems():
                    field = relation_field[key] if key in relation_field else key
                    where.append(reduce(operator.or_, [Q(**{field: i}) for i in val]))
        if 'like' in keys:
            like = []
            for param in filters['where']['like']:
                for key, val in param.iteritems():
                    field = relation_field[key] if key in relation_field else key
                    field = field + '__icontains'
                    like.append(Q(**{field: val[0]}))
            if len(like):
                where.append(reduce(operator.or_, like))
        if 'between' in keys:
            for param in filters['where']['between']:
                for key, val in param.iteritems():
                    field = relation_field[key] if key in relation_field else key
                    field = field + '__range'
                    start = datetime.fromtimestamp(val[0])
                    end = datetime.fromtimestamp(val[1])
                    where.append(reduce(operator.or_, [Q(**{field: (start, end)})]))
    else:
        # All except closed
        where.append(~Q(status='Closed'))

    # Filter allowed category for this user
    user_specific_where = []
    abuse_permissions = AbusePermission.objects.filter(user=user.id)

    for perm in abuse_permissions:
        if perm.profile.name == 'Expert':
            user_specific_where.append(Q(category=perm.category))
        elif perm.profile.name == 'Advanced':
            user_specific_where.append(Q(category=perm.category, confidential=False))
        elif perm.profile.name in ['Read-only', 'Beginner']:
            user_specific_where.append(Q(category=perm.category, confidential=False, escalated=False, moderation=False))

    if len(user_specific_where):
        user_specific_where = reduce(operator.or_, user_specific_where)
        where.append(user_specific_where)
    else:
        # If no category allowed
        where.append(Q(category=None))
    # Aggregate all filters
    where = reduce(operator.and_, where)
    return where


def __format_ticket_response(tickets):
    """ Convert datetime object and add flat foreign key
    """
    for ticket in tickets:
        for key, val in ticket.iteritems():
            if isinstance(val, datetime):
                ticket[key] = time.mktime(val.timetuple())

        # Flat foreign models
        if ticket.get('defendant'):
            ticket['defendant'] = model_to_dict(Defendant.objects.get(id=ticket['defendant']))
            for key, val in ticket['defendant'].iteritems():
                if isinstance(val, datetime):
                    ticket['defendant'][key] = time.mktime(val.timetuple())
        if ticket.get('service'):
            ticket['service'] = model_to_dict(Service.objects.get(id=ticket['service']))
        if ticket.get('treatedBy'):
            ticket['treatedBy'] = User.objects.get(id=ticket['treatedBy']).username
        if ticket.get('tags'):
            tags = Ticket.objects.get(id=ticket['id']).tags.all()
            ticket['tags'] = [model_to_dict(tag) for tag in tags]
        ticket['commentsCount'] = TicketComment.objects.filter(ticket=ticket['id']).count()


def add_search_filters(filters, query):
    """
        Add SearchService response to filters
    """
    search_query = query
    if IP_CIDR_RE.match(query):
        try:  # Try to parse IP/CIDR search
            network = IPNetwork(query)
            if network.size <= 4096:
                search_query = ' '.join([str(host) for host in network.iter_hosts()])
                search_query = search_query if search_query else query
        except (AttributeError, IndexError, AddrFormatError, AddrConversionError):
            pass
    try:
        reports = ImplementationFactory.instance.get_singleton_of('SearchServiceBase').search_reports(search_query)
        if not reports:
            reports = [None]
    except SearchServiceException:
        return

    if 'in' in filters['where']:
        for field in filters['where']['in']:
            for key, values in field.iteritems():
                if key == 'reportTicket__id' and len(values):
                    reports.extend(values)
                    filters['where']['in'].remove({key: values})
            filters['where']['in'].append({'reportTicket__id': reports})
    else:
        filters['where']['in'] = [{'reportTicket__id': reports}]


def show(ticket_id, user):
    """ Get a ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        just_assigned = False
        if not ticket.treatedBy:
            just_assigned = assign_if_not(ticket, user)
        ticket_dict = Ticket.objects.filter(id=ticket_id).values(*[f.name for f in Ticket._meta.fields])[0]
    except (IndexError, ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    # Convert dates
    for key, val in ticket_dict.iteritems():
        if isinstance(val, datetime):
            ticket_dict[key] = time.mktime(val.timetuple())

    # Add related infos
    if ticket.treatedBy:
        ticket_dict['treatedBy'] = ticket.treatedBy.username
    if ticket.defendant:
        ticket_dict['defendant'] = DefendantsController.show(ticket.defendant.id)[1]
    if ticket.action:
        ticket_dict['action'] = model_to_dict(ServiceAction.objects.get(id=ticket.action.id))
    if ticket.service:
        ticket_dict['service'] = model_to_dict(Service.objects.get(id=ticket.service.id))
    if ticket.jobs:
        ticket_dict['jobs'] = []
        for job in ticket.jobs.all():
            info = model_to_dict(job)
            for key, val in info.iteritems():
                if isinstance(val, datetime):
                    info[key] = int(time.mktime(val.timetuple()))
            ticket_dict['jobs'].append(info)

    ticket_dict['comments'] = [{
        'id': c.comment.id,
        'user': c.comment.user.username,
        'date': time.mktime(c.comment.date.timetuple()),
        'comment': c.comment.comment
    } for c in TicketComment.objects.filter(ticket=ticket.id).order_by('-comment__date')]

    ticket_dict['history'] = [{
        'username': c.user.username,
        'date': time.mktime(c.date.timetuple()),
        'action': c.action
    } for c in History.objects.filter(ticket=ticket.id).order_by('-date')]

    ticket_dict['attachedReportsCount'] = ticket.reportTicket.count()

    report_tags = list(set([report.tags.all() for report in ticket.reportTicket.all()]))
    report_tags = [item for sublist in report_tags for item in sublist]
    tags = list(set(list(set(ticket.tags.all())) + list(set(report_tags))))
    ticket_dict['tags'] = [model_to_dict(tag) for tag in tags]
    ticket_dict['justAssigned'] = just_assigned

    return 200, ticket_dict


def assign_if_not(ticket, user):
    """ If ticket is not assigned and user not just set ticket owner to nobody
        assign ticket to current user
    """
    try:
        perm = AbusePermission.objects.get(user=user, category=ticket.category)
        if perm.profile.name == 'Read-only':
            return False
    except ObjectDoesNotExist:
        return False

    assigned = False
    delta = datetime.now() - timedelta(seconds=15)
    just_unassigned = ticket.ticketHistory.filter(date__gt=delta, action__icontains='to nobody').order_by('-date')[:1]
    if not ticket.treatedBy and not ticket.protected and not just_unassigned:
        ticket.treatedBy = user
        ticket.save()
        action = 'change treatedBy from nobody to %s' % (user.username)
        GeneralController.log_action(ticket, user, action)
        assigned = True
    return assigned


def create(report, user):
    """ Create a ticket from a report or attach it
        if ticket with same defendant/category already exists
    """
    if not all(k in report.keys() for k in ('id', 'status')) or report['status'] not in ['New', 'Attached']:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Can not create a ticket with this status'}

    try:
        report = Report.objects.get(id=report['id'])
    except (KeyError, ObjectDoesNotExist):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid or missing report id'}

    code, resp = GeneralController.check_perms(method='POST', user=user, report=report.id)
    if code != 200:
        return code, resp

    # Retrieve foreign model from body
    defendant = None
    if report.defendant:
        try:
            defendant = DefendantsController.get_or_create(
                defendant_id=report.defendant.id,
                customer_id=report.defendant.customerId
            )
            if not defendant:
                return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Defendant not found'}
        except KeyError:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing id in defendant object'}

    service = None
    if report.service:
        try:
            service = Service.objects.get(
                id=report.service.id,
                name=report.service.name,
            )
        except (KeyError, ObjectDoesNotExist):
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid service or missing id in service object'}

    ticket = None
    actions = []
    # Try to attach to existing
    if all((defendant, service, report.category)):
        tickets = Ticket.objects.filter(
            ~(Q(status='Closed')),
            defendant=defendant,
            category=report.category,
            service=service,
            update=True
        )
        if len(tickets):
            ticket = tickets[0]
            actions.append('attach report %d from %s (%s ...) to this ticket' % (report.id, report.provider.email, report.subject[:30]))

    # Else creates ticket
    if not ticket:
        while True:
            try:
                public_id = ''.join(random.sample(string.ascii_uppercase.translate(None, 'AEIOUY'), 10))
                ticket = Ticket.objects.create(
                    publicId=public_id,
                    creationDate=datetime.now(),
                    category=report.category,
                    defendant=defendant,
                    service=service,
                    update=True
                )
                break
            except IntegrityError:
                pass
        actions.append('create this ticket with report %d from %s (%s ...)' % (report.id, report.provider.email, report.subject[:30]))

    report.ticket = ticket
    report.status = 'Attached'
    report.save()

    # If new report, try to attach existing reports with status "New" to this new created ticket
    if all((defendant, service, report.category)):
        for rep in Report.objects.filter(~Q(id__in=[report.id]), status='New', category=report.category, defendant=defendant, service=service):
            rep.status = 'Attached'
            rep.ticket = ticket
            rep.save()
            actions.append('attach report %d from %s (%s ...) to this ticket' % (rep.id, rep.provider.email, rep.subject[:30]))

    for action in actions:
        GeneralController.log_action(ticket, user, action)

    _, resp = show(ticket.id, user)
    return 201, resp


def update(ticket_id, body, user):
    """ Update a ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}

    if 'defendant' in body and body['defendant'] != ticket.defendant:
        code, resp = update_ticket_defendant(ticket, body['defendant'])
        if code != 200:
            return code, resp
        else:
            body['defendant'] = resp

    if 'category' in body and body['category'] != ticket.category:
        try:
            ticket.reportTicket.update(category=body['category'])
        except IntegrityError:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid category'}

    # If the user is a Beginner, he does not have the rights to modify these infos
    if user.abusepermission_set.filter(category=ticket.category, profile__name='Beginner').count():
        body.pop('escalated', None)
        body.pop('moderation', None)

    if not ticket.escalated and body.get('escalated'):
        body['treatedBy'] = None

    if 'treatedBy' in body and ticket.treatedBy and ticket.protected and ticket.treatedBy.username != body['treatedBy']:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Ticket is protected'}

    # remove invalid fields
    valid_fields = ['defendant', 'category', 'level', 'alarm', 'treatedBy', 'confidential', 'priority', 'pauseStart']
    valid_fields.extend(['pauseDuration', 'moderation', 'protected', 'escalated', 'update'])
    body = {k: v for k, v in body.iteritems() if k in valid_fields}

    if body.get('treatedBy'):
        if body['treatedBy'] in ['abuse.robot', 'monitoring']:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Can not assign ticket to this user'}
        body['treatedBy'] = User.objects.get(username=body['treatedBy'])

    body['modificationDate'] = datetime.now()
    old = deepcopy(ticket)

    try:
        Ticket.objects.filter(pk=ticket.pk).update(**body)
        ticket = Ticket.objects.get(pk=ticket.pk)
        actions = get_modifications(old, ticket)

        for action in actions:
            GeneralController.log_action(ticket, user, action)

    except (KeyError, FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}

    return show(ticket_id, user)


def get_modifications(old, new):
    """ Track ticket changes
    """
    actions = []
    if getattr(old, 'category') != getattr(new, 'category'):
        old_value = getattr(old, 'category').name if getattr(old, 'category') is not None else 'nothing'
        new_value = getattr(new, 'category').name if getattr(new, 'category') is not None else 'nothing'
        actions.append('change %s from %s to %s' % ('category', old_value, new_value))
    if getattr(old, 'defendant') != getattr(new, 'defendant'):
        old_value = getattr(old, 'defendant').customerId if getattr(old, 'defendant') is not None else 'nobody'
        new_value = getattr(new, 'defendant').customerId if getattr(new, 'defendant') is not None else 'nobody'
        actions.append('change %s from %s to %s' % ('defendant', old_value, new_value))
    if getattr(old, 'treatedBy') != getattr(new, 'treatedBy'):
        old_value = getattr(old, 'treatedBy').username if getattr(old, 'treatedBy') is not None else 'nobody'
        new_value = getattr(new, 'treatedBy').username if getattr(new, 'treatedBy') is not None else 'nobody'
        actions.append('change %s from %s to %s' % ('treatedBy', old_value, new_value))

    invalid_fields = ['defendant', 'category', 'treatedBy', 'snoozeStart', 'creationDate', 'modificationDate']
    for field in [f.name for f in Ticket._meta.fields if f.name not in invalid_fields]:
        if getattr(old, field) != getattr(new, field):
            actions.append('change %s from %s to %s' % (field, getattr(old, field), getattr(new, field)))
    return actions


def update_snooze_duration(ticket_id, body, user):
    """ Update ticket snooze duration
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}

    try:
        data = {'snoozeDuration': body['snoozeDuration']}

        if data['snoozeDuration'] == 0 and ticket.status == 'WaitingAnswer':
            ticket.previousStatus = ticket.status
            ticket.status = 'Alarm'
            ticket.save()

        if int(data['snoozeDuration']) > 10000000:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid duration'}

        return __update_duration(ticket, data, user)
    except (KeyError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}


def update_pause_duration(ticket_id, body, user):
    """ Update ticket pause duration
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        if ticket.status != 'Paused':
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Ticket is not paused'}
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}

    try:
        data = {'pauseDuration': body['pauseDuration']}
        if int(data['pauseDuration']) > 10000000:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid duration'}
        return __update_duration(ticket, data, user)
    except (KeyError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}


def __update_duration(ticket, data, user):
    """ Generic update for duration
    """
    try:
        key = data.keys()[0]
        previous = getattr(ticket, key)
        data[key.replace('Duration', 'Start')] = datetime.now()

        Ticket.objects.filter(pk=ticket.pk).update(**data)
        ticket = Ticket.objects.get(pk=ticket.pk)

        change = '%s to %s' % (str(timedelta(seconds=previous)), str(timedelta(seconds=getattr(ticket, key))))
        action = 'change %s duration from %s' % (key.replace('Duration', ''), change)
        GeneralController.log_action(ticket, user, action)

    except (FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}

    return show(ticket.id, user)


def update_ticket_defendant(ticket, defendant):
    """ Update defendant infos
    """
    defendant_obj = None
    if defendant is None:
        ticket.service = None
        ticket.save()
        for report in ticket.reportTicket.all():  # flushing tickets's reports defendant
            report.service = None
            report.defendant = None
            report.reportItemRelatedReport.all().delete()
            report.save()
    else:
        try:
            defendant_obj = DefendantsController.get_or_create(defendant_id=int(defendant['id']), customer_id=defendant['customerId'])
            if not defendant_obj:
                return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Defendant not found'}
        except KeyError:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing customerId or id in defendant body'}

        # Cascade update
        if ticket.defendant != defendant:
            ticket.reportTicket.update(defendant=defendant_obj.id)

    return 200, defendant_obj


def get_providers(ticket_id):
    """ Get ticket's providers
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    emails = ticket.reportTicket.all().values_list('provider__pk', flat=True).distinct()
    providers = [ProvidersController.show(email)[1] for email in emails]

    for prov in providers:
        prov['contacted'] = ContactedProvider.objects.filter(ticket=ticket, provider__email=prov['email']).exists()

    return 200, providers


def get_priorities():
    """ Get ticket model priorities
    """
    return [{'label': p[0]} for p in Ticket.TICKET_PRIORITY]


def get_proof(ticket_id):
    """ Get ticket proof
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    return 200, [model_to_dict(p) for p in ticket.proof.all()]


def add_proof(ticket_id, body, user):
    """ Add proof to ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}

    try:
        ticket.proof.create(**body)
        ticket.save()
        GeneralController.log_action(ticket, user, 'add proof')
    except (KeyError, FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}
    return 201, {'status': 'Created', 'code': 201, 'message': 'Proof successfully added to ticket'}


def update_proof(ticket_id, proof_id, body, user):
    """ Update proof
    """
    ticket = None
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        Proof.objects.get(id=proof_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}

    try:
        body.pop('id', None)
        body.pop('ticket', None)
        ticket.proof.update(**body)
        ticket.save()
        GeneralController.log_action(ticket, user, 'update proof')
    except (KeyError, FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}
    return 200, {'status': 'OK', 'code': 201, 'message': 'Proof successfully updated'}


def delete_proof(ticket_id, proof_id, user):
    """ Delete proof
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    try:
        proof = ticket.proof.get(id=proof_id)
        proof.delete()
        GeneralController.log_action(ticket, user, 'delete proof')
    except (ObjectDoesNotExist, KeyError, FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}
    return 200, {'status': 'OK', 'code': 200, 'message': 'Proof successfully deleted'}


def update_status(ticket, status, body, user):
    """
        Update ticket status
    """
    try:
        status = status.lower()
    except AttributeError:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid status'}

    if not isinstance(ticket, Ticket):
        try:
            ticket = Ticket.objects.get(id=ticket)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    if not status == 'waitinganswer' and status == ticket.status.lower():
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Ticket had already this status'}

    code = 200
    actions = []
    if status == 'paused':
        try:
            code, resp = pause_ticket(ticket, body)
            msg = 'change status from %s to %s (for %s hour(s))'
            actions.append(msg % (ticket.previousStatus, ticket.status, str(int(body['pauseDuration'] / 3600))))
        except (ValueError, TypeError, ObjectDoesNotExist):
            code = 400
            resp = {'status': 'Bad Request', 'code': 400, 'message': 'Invalid parameter'}
        except KeyError as ex:
            code = 400
            resp = {'status': 'Bad Request', 'code': 400, 'message': 'Missing %s field' % (str(ex.message))}

    elif status == 'unpaused':
        try:
            code, resp = unpause_ticket(ticket)
            actions.append('change status from %s to %s' % (ticket.previousStatus, ticket.status))
        except (ValueError, TypeError, ObjectDoesNotExist):
            code = 400
            resp = {'status': 'Bad Request', 'code': code, 'message': 'Invalid parameter'}
        except KeyError as ex:
            code = 400
            resp = {'status': 'Bad Request', 'code': code, 'message': 'Missing %s field' % (str(ex.message))}

    elif status == 'waitinganswer':
        resp = {'status': 'OK', 'code': code, 'message': 'Ticket waiting answer from customer'}
        try:
            if int(body['snoozeDuration']) > 10000000:
                return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid snooze duration'}
            ticket.snoozeDuration = int(body['snoozeDuration'])
            ticket.snoozeStart = datetime.now()
            ticket.previousStatus = ticket.status
            if ticket.snoozeDuration == 0:
                ticket.status = 'Alarm'
            else:
                ticket.status = 'WaitingAnswer'
            ticket.reportTicket.all().update(status='Attached')
            msg = 'change status from %s to %s (for %s hour(s))'
            actions.append(msg % (ticket.previousStatus, ticket.status, str(ticket.snoozeDuration / 3600)))
        except (KeyError, ValueError):
            code = 400
            resp = {'status': 'Bad Request', 'code': code, 'message': 'Missing or invalid snoozeDuration'}

    elif status == 'closed':

        try:
            resolution = Resolution.objects.get(id=int(body['resolution']))
        except (AttributeError, KeyError, ValueError, ObjectDoesNotExist):
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing or invalid resolution id'}

        resp = {'status': 'OK', 'code': 200, 'message': 'Ticket closed'}

        if ticket.mailerId:
            try:
                ImplementationFactory.instance.get_singleton_of('MailerServiceBase').close_thread(ticket)
            except MailerServiceException:
                code = 500
                resp = {'status': 'Internal Server Error', 'code': 500, 'message': 'Unable to close thread'}

        if code == 200:
            resp = {'status': 'OK', 'code': 200, 'message': 'Ticket closed'}
            ticket.previousStatus = ticket.status
            ticket.status = 'Closed'
            ticket.reportTicket.all().update(status='Archived')
            ticket.resolution = resolution

            if user.abusepermission_set.filter(category=ticket.category, profile__name='Beginner').count():
                ticket.moderation = True

            msg = 'change status from %s to %s, reason : %s'
            actions.append(msg % (ticket.previousStatus, ticket.status, ticket.resolution.codename))

    elif status == 'reopened':
        resp = {'status': 'OK', 'code': 200, 'message': 'Ticket reopened'}

        if code == 200:
            resp = {'status': 'OK', 'code': 200, 'message': 'Ticket reopened'}
            ticket.previousStatus = ticket.status
            ticket.status = 'Reopened'
            ticket.reportTicket.all().update(status='Attached')
            actions.append('change status from %s to %s' % (ticket.previousStatus, ticket.status))

    else:
        code = 400
        resp = {'status': 'Bad Request', 'code': 400, 'message': 'Invalid status'}

    if code == 200:
        ticket.save()
        for action in actions:
            GeneralController.log_action(ticket, user, action)
    return code, resp


def pause_ticket(ticket, body):
    """ Pause ticket
    """
    if int(body['pauseDuration']) > 10000000:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid pause duration'}

    ticket.pauseStart = datetime.now()
    ticket.pauseDuration = int(body['pauseDuration'])
    ticket.previousStatus = ticket.status
    ticket.status = 'Paused'

    # Delay jobs
    delay = timedelta(seconds=ticket.pauseDuration)
    __delay_jobs(ticket, delay, back=False)

    return 200, {'status': 'OK', 'code': 200, 'message': 'Ticket paused for %d hour(s)' % (ticket.pauseDuration)}


def unpause_ticket(ticket):
    """ Unpause ticket
    """
    # Delay jobs
    delay = timedelta(seconds=ticket.pauseDuration) - (datetime.now() - ticket.pauseStart)
    __delay_jobs(ticket, delay, back=True)

    if ticket.previousStatus == 'WaitingAnswer' and ticket.snoozeDuration and ticket.snoozeStart:
        ticket.snoozeDuration = ticket.snoozeDuration + (datetime.now() - ticket.pauseStart).seconds
    ticket.pauseStart = None
    ticket.pauseDuration = None
    ticket.status = ticket.previousStatus
    ticket.previousStatus = 'Paused'

    return 200, {'status': 'OK', 'code': 200, 'message': 'Ticket unpaused'}


def __delay_jobs(ticket, delay, back=True):
    """ Delay jobs for pause/unpaused
    """
    list_of_job_instances = utils.scheduler.get_jobs(
        until=timedelta(days=5),
        with_times=True
    )

    for job in ticket.jobs.all():
        if job.asynchronousJobId in utils.scheduler:
            for scheduled_job in list_of_job_instances:
                if scheduled_job[0].id == job.asynchronousJobId:
                    if back:
                        date = scheduled_job[1] - delay
                    else:
                        date = scheduled_job[1] + delay
                    utils.scheduler.change_execution_time(
                        scheduled_job[0],
                        date
                    )
                    break


@transaction.commit_manually
def bulk_add(body, user, method):
    """
        Add or update infos for multiple tickets
    """
    code, resp = __check_bulk_conformance(body, user, method)
    if code != 200:
        transaction.rollback()
        return code, resp

    for ticket in resp:
        assign_if_not(ticket, user)

    # Update status
    if 'status' in body['properties']:
        valid_status = ['unpaused', 'paused', 'closed', 'reopened']
        if body['properties']['status'].lower() not in valid_status:
            transaction.rollback()
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Status not supported'}

        valid_fields = ['pauseDuration', 'resolution']
        properties = {k: v for k, v in body['properties'].iteritems() if k in valid_fields}

        for ticket in resp:
            code, resp = update_status(ticket.id, body['properties']['status'], properties, user)
            if code != 200:
                transaction.rollback()
                return code, resp

    # Update tags
    if 'tags' in body['properties'] and isinstance(body['properties']['tags'], list):
        for ticket in resp:
            for tag in body['properties']['tags']:
                code, resp = add_tag(ticket.id, tag, user)
                if code != 200:
                    transaction.rollback()
                    return code, resp

    # Update general fields
    valid_fields = ['category', 'level', 'alarm', 'treatedBy', 'confidential', 'priority']
    valid_fields.extend(['moderation', 'protected', 'escalated', 'update', 'pauseDuration'])
    properties = {k: v for k, v in body['properties'].iteritems() if k in valid_fields}

    for ticket in resp:
        code, resp = update(ticket.id, properties, user)
        if code != 200:
            transaction.rollback()
            return code, resp

    transaction.commit()
    return 200, {'status': 'OK', 'code': 200, 'message': 'Ticket(s) successfully updated'}


@transaction.commit_manually
def bulk_delete(body, user, method):
    """
        Delete infos from multiple tickets
    """
    code, resp = __check_bulk_conformance(body, user, method)
    if code != 200:
        transaction.rollback()
        return code, resp

    # Update tags
    try:
        if 'tags' in body['properties'] and isinstance(body['properties']['tags'], list):
            for ticket in resp:
                for tag in body['properties']['tags']:
                    code, resp = remove_tag(ticket.id, tag['id'], user)
                    if code != 200:
                        transaction.rollback()
                        return code, resp
    except (KeyError, TypeError, ValueError):
        transaction.rollback()
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid or missing tag(s) id'}

    transaction.commit()
    return 200, {'status': 'OK', 'code': 200, 'message': 'Ticket(s) successfully updated'}


def __check_bulk_conformance(body, user, method):
    """
        Check request conformance for bulk
    """
    if not body.get('tickets') or not body.get('properties'):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing tickets or properties in body'}

    try:
        tickets = Ticket.objects.filter(id__in=list(body['tickets']))
    except (TypeError, ValueError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid ticket(s) id'}

    for ticket in tickets:
        code, resp = GeneralController.check_perms(method=method, user=user, ticket=ticket.id)
        if code != 200:
            return code, resp

    return 200, tickets


def add_tag(ticket_id, body, user):
    """ Add ticket tag
    """
    try:
        tag = Tag.objects.get(**body)
        ticket = Ticket.objects.get(id=ticket_id)

        if ticket.__class__.__name__ != tag.tagType:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid tag for ticket'}

        ticket.tags.add(tag)
        ticket.save()
        GeneralController.log_action(ticket, user, 'add tag %s' % (tag.name))
    except MultipleObjectsReturned:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Please use tag id'}
    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Tag or ticket not found'}
    return 200, {'status': 'OK', 'code': 200, 'message': 'Tag successfully added'}


def remove_tag(ticket_id, tag_id, user):
    """ Remove ticket tag
    """
    try:
        tag = Tag.objects.get(id=tag_id)
        ticket = Ticket.objects.get(id=ticket_id)

        if ticket.__class__.__name__ != tag.tagType:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid tag for ticket'}

        ticket.tags.remove(tag)
        ticket.save()
        GeneralController.log_action(ticket, user, 'remove tag %s' % (tag.name))

    except (ObjectDoesNotExist, FieldError, IntegrityError, ValueError):
        return 404, {'status': 'Not Found', 'code': 404}
    return 200, {'status': 'OK', 'code': 200, 'message': 'Tag successfully removed'}


def interact(ticket_id, body, user):
    """ Magic endpoint to save operator's time
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    if not all(key in body for key in ('emails', 'action')):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing param(s): need emails and action'}

    action = body['action']
    code = 200

    try:
        code, resp = __parse_interact_action(ticket, action, user)
        if not code == 200:
            return code, resp
    except (AttributeError, KeyError, ValueError, TypeError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing or invalid params in action'}

    for email_to_send in body['emails']:
        params = {k: v for k, v in email_to_send.iteritems() if k in ['to', 'body', 'subject']}
        for recipient in params['to']:
            try:
                ImplementationFactory.instance.get_singleton_of('MailerServiceBase').send_email(
                    ticket,
                    recipient,
                    params['subject'],
                    params['body']
                )
                GeneralController.log_action(ticket, user, 'send an email to %s' % (recipient))
            except MailerServiceException as ex:
                return 500, {'status': 'Internal Server Error', 'code': 500, 'message': str(ex)}

    return 200, {'status': 'OK', 'code': 200, 'message': 'Ticket successfully updated'}


def __parse_interact_action(ticket, action, user):
    """ Parse action of interact endpoint's body
    """
    code = 200
    resp = {'status': 'OK', 'code': 200, 'message': 'OK'}

    # Check resolution
    resolution_id = None
    if action.get('params') and action['params'].get('resolution'):
        resolution_id = int(action['params']['resolution'])
        if not Resolution.objects.filter(id=resolution_id).exists():
            return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket resolution not found'}

    if 'action' in action['codename']:

        # Check action
        try:
            action_id = int(action['params']['action'])
        except ObjectDoesNotExist:
            return 404, {'status': 'Not Found', 'code': 404, 'message': 'Action not found'}

        # Check IP address
        ip_addr = None
        code, resp = __get_ip_for_action(ticket, action)
        if not code == 200:
            return code, resp
        else:
            ip_addr = resp

        if not ip_addr:
            return 404, {'status': 'Not Found', 'code': 400, 'message': 'No IP specified'}

        if not __check_action_rights(ticket, action_id, user):
            return 403, {'status': 'Forbidden', 'code': 403, 'message': 'Invalid permission for action'}

        if action['codename'] == 'waiting_answer_then_action':
            code, resp = update_status(
                ticket,
                'waitinganswer',
                {'snoozeDuration': action['params']['snoozeDuration']},
                user,
            )
            code, resp = schedule_asynchronous_job(
                ticket.id,
                action_id,
                ip_addr,
                user,
                seconds=action['params']['snoozeDuration'],
                method='action.apply_if_no_reply',
                params={
                    'ticket_id': ticket.id,
                    'action_id': action_id,
                    'ip_addr': ip_addr,
                    'resolution_id': None,
                    'user_id': user.id,
                    'close': False,
                }
            )
        elif action['codename'] == 'waiting_answer_then_action_and_close':
            code, resp = update_status(
                ticket,
                'waitinganswer',
                {'snoozeDuration': action['params']['snoozeDuration']},
                user,
            )
            code, resp = schedule_asynchronous_job(
                ticket.id,
                action_id,
                ip_addr,
                user,
                seconds=action['params']['snoozeDuration'],
                method='action.apply_if_no_reply',
                params={
                    'ticket_id': ticket.id,
                    'action_id': action_id,
                    'ip_addr': ip_addr,
                    'resolution_id': resolution_id,
                    'user_id': user.id,
                    'close': True,
                }
            )
        elif action['codename'] == 'action_then_waiting_answer':
            code, resp = schedule_asynchronous_job(
                ticket.id,
                action_id,
                ip_addr,
                user,
                seconds=1,
                method='action.apply_action',
                params={
                    'ticket_id': ticket.id,
                    'action_id': action_id,
                    'ip_addr': ip_addr,
                    'user_id': user.id,
                }
            )
            code, resp = update_status(
                ticket,
                'waitinganswer',
                {'snoozeDuration': action['params']['snoozeDuration']},
                user
            )
        elif action['codename'] == 'action_then_close':
            code, resp = schedule_asynchronous_job(
                ticket.id,
                action_id,
                ip_addr,
                user,
                seconds=1,
                method='action.apply_then_close',
                params={
                    'ticket_id': ticket.id,
                    'action_id': action_id,
                    'ip_addr': ip_addr,
                    'resolution_id': resolution_id,
                    'user_id': user.id,
                }
            )
    elif action['codename'] == 'waiting_answer':
        code, resp = update_status(
            ticket,
            'waitinganswer',
            {'snoozeDuration': action['params']['snoozeDuration']},
            user
        )
    elif action['codename'] == 'close_with_resolution':
        code, resp = update_status(
            ticket,
            'closed',
            {'resolution': resolution_id},
            user
        )
    elif action['codename'] == 'pause_ticket':
        code, resp = update_status(
            ticket,
            'paused',
            {'pauseDuration': action['params']['pauseDuration']},
            user)
    else:
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Action not found'}

    return code, resp


def __get_ip_for_action(ticket, action):
    """
        Extract and check IP address for action
    """
    # Get ticket IP(s)
    reports = ticket.reportTicket.all()
    ips_on_ticket = [itm.ip for rep in reports for itm in rep.reportItemRelatedReport.filter(~Q(ip=None), itemType='IP')]
    ips_on_ticket.extend([itm.fqdnResolved for rep in reports for itm in rep.reportItemRelatedReport.filter(~Q(fqdnResolved=None), itemType__in=['FQDN', 'URL'])])
    ips_on_ticket = list(set(ips_on_ticket))

    # Check IP
    ip_addr = None
    if action['params'].get('ip'):
        if action['params']['ip'] not in ips_on_ticket:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Specified IP address not attached to ticket'}
        else:
            ip_addr = action['params']['ip']
    else:
        if len(ips_on_ticket) == 1:
            ip_addr = ips_on_ticket[0]
        else:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Multiple or no IP on this ticket'}
    return 200, ip_addr


def get_actions_list(ticket_id, user):
    """
        List possible actions for ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        if not ticket.service or not ticket.defendant:
            return 200, []
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    try:
        perm = AbusePermission.objects.get(user=user, category=ticket.category)
        authorized = list(set(perm.profile.actions.all().values_list('id', flat=True)))
    except ObjectDoesNotExist:
        return 403, {'status': 'Forbidden', 'code': 403, 'message': 'You can not interact with this ticket'}

    try:
        actions = ImplementationFactory.instance.get_singleton_of('ActionServiceBase').list_actions_for_ticket(ticket)
    except ActionServiceException:
        return 500, {'status': 'Internal Server Error', 'code': 500, 'message': 'Unable to list actions for this ticket'}

    actions = [model_to_dict(action) for action in actions if action.id in authorized]
    return 200, actions


def cancel_aysnchronous_job(ticket_id, job_id, user):
    """ Cancel task on ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        job = ServiceActionJob.objects.get(id=job_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket or job not found'}

    action = 'cancel action: %s' % (ticket.action.name)
    utils.scheduler.cancel(job.asynchronousJobId)
    ServiceActionJob.objects.filter(asynchronousJobId=job.asynchronousJobId).update(status='cancelled')
    ticket.save()
    GeneralController.log_action(ticket, user, action)
    return 200, {'status': 'OK', 'code': 200, 'message': 'Task successfully canceled'}


def schedule_asynchronous_job(ticket_id, action_id, ip_addr, user, seconds=1, method='apply_action', params=None):
    """ Schedule task on ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        action = ServiceAction.objects.get(id=action_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket or action not found'}

    if not params:
        params = {}

    if not __check_action_rights(ticket, action.id, user):
        return 403, {'status': 'Forbidden', 'code': 403, 'message': 'Invalid permission for this action'}

    # Cancel previous pending jobs
    for job in ticket.jobs.all():
        if job.asynchronousJobId in utils.scheduler:
            utils.scheduler.cancel(job.asynchronousJobId)
            job.status = 'cancelled by new action'
            job.save()

    async_job = utils.scheduler.enqueue_in(timedelta(seconds=seconds), method, **params)
    job = ServiceActionJob.objects.create(ip=ip_addr, action=action, asynchronousJobId=async_job.id, creationDate=datetime.now())

    ticket.action = action
    delay = 'now' if seconds == 1 else 'in %s hour(s)' % (str(seconds / 3600))
    log_action = 'set action: %s, execution %s' % (action.name, delay)
    ticket.jobs.add(job)
    ticket.save()

    GeneralController.log_action(ticket, user, log_action)
    return 200, {'status': 'OK', 'code': 200, 'message': 'Task successfully created'}


def get_jobs_status(ticket_id):
    """
        Get actions todo status
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    resp = []
    jobs = ticket.jobs.all().order_by('creationDate')
    for job in jobs:
        info = model_to_dict(job)
        for key, val in info.iteritems():
            if isinstance(val, datetime):
                info[key] = int(time.mktime(val.timetuple()))
        if info.get('action'):
            info['action'] = model_to_dict(ServiceAction.objects.get(id=info['action']))
        resp.append(info)

    return 200, resp


def __check_action_rights(ticket, action_id, user):
    """
        Check if user can set action
    """
    try:
        perm = AbusePermission.objects.get(user=user, category=ticket.category)
        authorized = list(set(perm.profile.actions.all().values_list('id', flat=True)))
        if action_id not in authorized:
            return False
    except ObjectDoesNotExist:
        return False
    return True


def get_todo_tickets(**kwargs):
    """ Test
    """
    # Parse filters from request
    filters = {}
    if kwargs.get('filters'):
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}

    tickets, nb_record = __get_filtered_todo_tickets(filters, kwargs['user'])
    __format_ticket_response(tickets)
    return 200, {'tickets': [dict(ticket) for ticket in tickets], 'ticketsCount': nb_record}


def __get_filtered_todo_tickets(filters, user):
    """ Get tickets TODO with specifi ordering
    """
    try:
        limit = int(filters['paginate']['resultsPerPage'])
        offset = int(filters['paginate']['currentPage'])
    except KeyError:
        limit = 10
        offset = 1

    try:
        with_assigned = filters['withAssigned']
        if not isinstance(with_assigned, bool):
            with_assigned = True
    except KeyError:
        with_assigned = True

    try:
        with_alarm = filters['withFts']
        if not isinstance(with_alarm, bool):
            with_alarm = True
    except KeyError:
        with_alarm = True

    where = __get_user_filters(user)
    res = []
    order_by = ['modificationDate']
    ids = set()
    fields = [fld.name for fld in Ticket._meta.fields]

    if not with_assigned:
        where.append(Q(treatedBy=None))

    if not with_alarm:
        where.append(Q(alarm=False))

    # Aggregate all filters
    where = reduce(operator.and_, where)

    nb_record = Ticket.objects.filter(
        where,
        status__in=['ActionError', 'Answered', 'Alarm', 'Reopened', 'Open']
    ).distinct().count()

    for status in [['ActionError'], ['Answered'], ['Alarm', 'Reopened'], ['Open']]:

        if status == ['Open']:
            order_by.append('-reportTicket__tags__level')

        for priority in ['High', 'Normal', 'Low']:

            tickets = Ticket.objects.filter(
                where,
                ~Q(id__in=ids),
                priority=priority,
                status__in=status,
            ).values(
                *fields
            ).order_by(
                *order_by
            ).annotate(
                attachedReportsCount=Count('reportTicket')
            ).distinct()[:limit * offset]

            ids.update([t['id'] for t in tickets])
            res.extend(tickets)

            if len(res) > limit * offset:
                return res[(offset - 1) * limit:limit * offset], nb_record

    return res[(offset - 1) * limit:limit * offset], nb_record


def __get_user_filters(user):
    """ Filter allowed category for this user
    """
    where = [Q()]
    user_specific_where = []
    abuse_permissions = AbusePermission.objects.filter(user=user.id)

    for perm in abuse_permissions:
        if perm.profile.name == 'Expert':
            user_specific_where.append(Q(category=perm.category))
        elif perm.profile.name == 'Advanced':
            user_specific_where.append(Q(category=perm.category, confidential=False))
        elif perm.profile.name == 'Beginner':
            user_specific_where.append(Q(category=perm.category, confidential=False, escalated=False, moderation=False))

    if len(user_specific_where):
        user_specific_where = reduce(operator.or_, user_specific_where)
        where.append(user_specific_where)
    else:
        # If no category allowed
        where.append(Q(category=None))

    return where


def get_emails(ticket_id):
    """
        Get all emails for this tickets
    """
    ticket = None
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket not found'}

    try:
        emails = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').get_emails(ticket)
        emails = [{'body': e.body, 'created': e.created, 'from': e.sender, 'subject': e.subject, 'to': e.recipient} for e in emails]
        return 200, emails
    except MailerServiceException as ex:
        return 500, {'status': 'Internal Server Error', 'code': 500, 'message': str(ex)}
