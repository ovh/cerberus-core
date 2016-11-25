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

import base64
import hashlib
import json
import operator
import time
from copy import deepcopy
from datetime import datetime, timedelta
from urllib import unquote

from django.conf import settings
from django.contrib.auth.models import User
from django.core.exceptions import FieldError, MultipleObjectsReturned
from django.db import IntegrityError, transaction
from django.db.models import Count, FieldDoesNotExist, ObjectDoesNotExist, Q
from django.forms.models import model_to_dict
from django.utils import text
from netaddr import AddrConversionError, AddrFormatError, IPNetwork
from werkzeug.exceptions import (BadRequest, Forbidden, InternalServerError,
                                 NotFound)

from abuse.models import (AbusePermission, ContactedProvider, Defendant,
                          History, Proof, Report, Resolution, Service,
                          ServiceAction, ServiceActionJob, Tag, Ticket,
                          TicketComment, AttachedDocument)
from adapters.services.action.abstract import ActionServiceException
from adapters.services.mailer.abstract import EMAIL_VALID_CATEGORIES, MailerServiceException
from adapters.services.search.abstract import SearchServiceException
from adapters.services.storage.abstract import StorageServiceException
from api.constants import (IP_CIDR_RE, TICKET_FIELDS, TICKET_FILTER_MAPPING,
                           TICKET_UPDATE_VALID_FIELDS, TICKET_BULK_VALID_FIELDS,
                           TICKET_BULK_VALID_STATUS, TICKET_MODIFICATION_INVALID_FIELDS)
from api.controllers import (DefendantsController, GeneralController,
                             ProvidersController)
from factory.implementation import ImplementationFactory
from factory.ticketscheduling import TicketSchedulingAlgorithmFactory
from utils import utils
from worker import database


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
            raise BadRequest(str(ex.message))
    try:
        limit = int(filters['paginate']['resultsPerPage'])
        offset = int(filters['paginate']['currentPage'])
    except KeyError:
        limit = 10
        offset = 1

    # Generate Django filter based on parsed filters
    try:
        where = __generate_request_filters(filters, kwargs['user'], kwargs.get('treated_by'))
    except (AttributeError, KeyError, IndexError, FieldError,
            SyntaxError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))

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
    except (AttributeError, KeyError, IndexError, FieldError,
            SyntaxError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))

    __format_ticket_response(tickets)
    return list(tickets), nb_record_filtered


def __generate_request_filters(filters, user=None, treated_by=None):
    """
        Generates filters base on filter query string
    """
    where = [Q()]
    if treated_by:
        where.append(Q(treatedBy=treated_by))

    # Add SearchService results if fulltext search
    try:
        for field in filters['where']['like']:
            for key, value in field.iteritems():
                if key == 'fulltext':
                    if ImplementationFactory.instance.is_implemented('SearchServiceBase'):
                        _add_search_filters(filters, value[0])
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
                    field = reduce(lambda a, kv: a.replace(*kv), TICKET_FILTER_MAPPING, key)
                    where.append(reduce(operator.or_, [Q(**{field: i}) for i in val]))
        if 'like' in keys:
            like = []
            for param in filters['where']['like']:
                for key, val in param.iteritems():
                    field = reduce(lambda a, kv: a.replace(*kv), TICKET_FILTER_MAPPING, key)
                    field = field + '__icontains'
                    like.append(Q(**{field: val[0]}))
            if len(like):
                where.append(reduce(operator.or_, like))
    else:
        # All except closed
        where.append(~Q(status='Closed'))

    # Filter allowed category for this user
    user_specific_where = []
    abuse_permissions = AbusePermission.objects.filter(user=user.id)

    for perm in abuse_permissions:
        if perm.profile.name == 'Expert':
            user_specific_where.append(Q(category=perm.category))
        elif perm.profile.name in ('Advanced', 'Read-only', 'Beginner'):
            user_specific_where.append(Q(category=perm.category, confidential=False))

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
            defendant = Defendant.objects.get(id=ticket['defendant'])
            ticket['defendant'] = model_to_dict(defendant)
            ticket['defendant']['email'] = defendant.details.email
        if ticket.get('service'):
            ticket['service'] = model_to_dict(Service.objects.get(id=ticket['service']))
        if ticket.get('treatedBy'):
            ticket['treatedBy'] = User.objects.get(id=ticket['treatedBy']).username
        if ticket.get('tags'):
            tags = Ticket.objects.get(id=ticket['id']).tags.all()
            ticket['tags'] = [model_to_dict(tag) for tag in tags]
        ticket['commentsCount'] = TicketComment.objects.filter(ticket=ticket['id']).count()


def _add_search_filters(filters, query):
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
        reports = ImplementationFactory.instance.get_singleton_of(
            'SearchServiceBase'
        ).search_reports(search_query)
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
        ticket_dict = Ticket.objects.filter(id=ticket_id).values(*TICKET_FIELDS)[0]
    except (IndexError, ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

    # Convert dates
    for key, val in ticket_dict.iteritems():
        if isinstance(val, datetime):
            ticket_dict[key] = time.mktime(val.timetuple())

    # Add related infos
    if ticket.treatedBy:
        ticket_dict['treatedBy'] = ticket.treatedBy.username
    if ticket.defendant:
        ticket_dict['defendant'] = DefendantsController.show(ticket.defendant.id)
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

    ticket_reports_id = ticket.reportTicket.all().values_list('id', flat=True).distinct()

    ticket_dict['comments'] = __get_ticket_comments(ticket)
    ticket_dict['history'] = __get_ticket_history(ticket)
    ticket_dict['attachedReportsCount'] = ticket.reportTicket.count()
    ticket_dict['tags'] = __get_ticket_tags(ticket, ticket_reports_id)
    ticket_dict['attachments'] = __get_ticket_attachments(ticket, ticket_reports_id)
    ticket_dict['justAssigned'] = just_assigned

    return ticket_dict


def __get_ticket_comments(ticket):
    """
        Get ticket comments..
    """
    return [{
        'id': c.comment.id,
        'user': c.comment.user.username,
        'date': time.mktime(c.comment.date.timetuple()),
        'comment': c.comment.comment
    } for c in TicketComment.objects.filter(ticket=ticket.id).order_by('-comment__date')]


def __get_ticket_history(ticket):
    """
        Get ticket history..
    """
    history = History.objects.filter(
        ticket=ticket.id
    ).values_list(
        'user__username',
        'date',
        'action'
    ).order_by('-date')
    return [{
        'username': username,
        'date': time.mktime(date.timetuple()),
        'action': action
    } for username, date, action in history]


def __get_ticket_tags(ticket, ticket_reports_id):
    """
        Get ticket tags..
    """
    report_tags = Tag.objects.filter(
        report__id__in=ticket_reports_id
    ).distinct()
    tags = list(set(list(set(ticket.tags.all())) + list(set(report_tags))))
    return [model_to_dict(tag) for tag in tags]


def __get_ticket_attachments(ticket, ticket_reports_id):
    """
        Get ticket attachments..
    """
    attachments = AttachedDocument.objects.filter(report__id__in=ticket_reports_id).distinct()
    attachments = list(attachments)
    attachments.extend(ticket.attachments.all())
    attachments = list(set(attachments))
    return [model_to_dict(attach) for attach in attachments]


def assign_if_not(ticket, user):
    """
        If ticket is not assigned and user not just set ticket owner to nobody
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
    just_unassigned = ticket.ticketHistory.filter(
        date__gt=delta,
        action__icontains='to nobody'
    ).order_by('-date')[:1]
    if not ticket.treatedBy and not ticket.protected and not just_unassigned:
        ticket.treatedBy = user
        ticket.save()
        database.log_action_on_ticket(
            ticket=ticket,
            action='change_treatedby',
            user=user,
            new_value=user.username
        )
        assigned = True
    return assigned


def create(body, user):
    """ Create a ticket from a report or attach it
        if ticket with same defendant/category already exists
    """
    try:
        if body['status'].lower() not in ('new', 'attached'):
            raise BadRequest('Can not create a ticket with this status')
        report = Report.objects.get(id=body['id'])
    except (KeyError, ObjectDoesNotExist):
        raise BadRequest('Invalid or missing report id')

    GeneralController.check_perms(method='POST', user=user, report=report.id)

    # Retrieve foreign model from body
    defendant = None
    if report.defendant:
        try:
            defendant = DefendantsController.get_or_create(customer_id=report.defendant.customerId)
            if not defendant:
                raise BadRequest('Defendant not found')
        except KeyError:
            raise BadRequest('Missing id in defendant object')

    service = None
    if report.service:
        try:
            service = Service.objects.get(
                id=report.service.id,
                name=report.service.name,
            )
        except (KeyError, ObjectDoesNotExist):
            raise BadRequest('Invalid service or missing id in service object')

    new_ticket = False
    ticket = None
    # Try to attach to existing
    if all((defendant, service, report.category)):
        ticket = database.search_ticket(defendant, report.category, service)

    # Else creates ticket
    if not ticket:
        ticket = database.create_ticket(
            defendant,
            report.category,
            service,
            priority=report.provider.priority
        )
        new_ticket = True

    database.log_action_on_ticket(
        ticket=ticket,
        action='attach_report',
        user=user,
        report=report,
        new_ticket=new_ticket
    )

    report.status = 'Attached'
    report.ticket = ticket
    report.save()
    database.set_ticket_higher_priority(ticket)

    # If new report, try to attach existing reports with status "New" to this new created ticket
    if ticket:
        for rep in ticket.reportTicket.filter(~Q(id__in=[report.id])):
            database.log_action_on_ticket(
                ticket=ticket,
                action='attach_report',
                user=user,
                report=report,
                new_ticket=False
            )

    resp = show(ticket.id, user)
    return resp


def update(ticket, body, user, bulk=False):
    """
        Update a ticket
    """
    allowed, body = _precheck_user_fields_update_authorizations(user, body)
    if not allowed:
        raise Forbidden('You are not allowed to edit any fields')

    if not isinstance(ticket, Ticket):
        try:
            ticket = Ticket.objects.get(id=ticket)
        except (ObjectDoesNotExist, ValueError):
            raise NotFound('Not Found')

    if 'defendant' in body and body['defendant'] != ticket.defendant:
        body['defendant'] = update_ticket_defendant(ticket, body['defendant'])

    if 'category' in body and body['category'] != ticket.category:
        try:
            ticket.reportTicket.update(category=body['category'])
        except IntegrityError:
            raise BadRequest('Invalid category')

    # If the user is a Beginner, he does not have the rights to modify these infos
    if user.abusepermission_set.filter(category=ticket.category, profile__name='Beginner').count():
        body.pop('escalated', None)
        body.pop('moderation', None)

    if not ticket.escalated and body.get('escalated'):
        body['treatedBy'] = None

    if 'treatedBy' in body and ticket.treatedBy and \
       ticket.protected and ticket.treatedBy.username != body['treatedBy']:
        raise BadRequest('Ticket is protected')

    # remove invalid fields
    body = {k: v for k, v in body.iteritems() if k in TICKET_UPDATE_VALID_FIELDS}

    if body.get('treatedBy'):
        body['treatedBy'] = User.objects.get(username=body['treatedBy'])

    body['modificationDate'] = datetime.now()
    old = deepcopy(ticket)

    try:
        Ticket.objects.filter(pk=ticket.pk).update(**body)
        ticket = Ticket.objects.get(pk=ticket.pk)
        actions = _get_modifications(old, ticket, user)

        for action in actions:
            database.log_action_on_ticket(**action)

    except (KeyError, FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))

    if bulk:
        return None

    return show(ticket.id, user)


def _get_modifications(old, new, user):
    """ Track ticket changes
    """
    actions = []
    if getattr(old, 'category') != getattr(new, 'category'):
        old_value = getattr(old, 'category').name if getattr(old, 'category') is not None else 'nothing'
        new_value = getattr(new, 'category').name if getattr(new, 'category') is not None else 'nothing'
        actions.append({
            'ticket': new,
            'action': 'update_property',
            'user': user,
            'property': 'category',
            'previous_value': old_value,
            'new_value': new_value
        })
    if getattr(old, 'defendant') != getattr(new, 'defendant'):
        old_value = getattr(old, 'defendant').customerId if getattr(old, 'defendant') is not None else 'nobody'
        new_value = getattr(new, 'defendant').customerId if getattr(new, 'defendant') is not None else 'nobody'
        actions.append({
            'ticket': new,
            'action': 'update_property',
            'user': user,
            'property': 'defendant',
            'previous_value': old_value,
            'new_value': new_value
        })
    if getattr(old, 'treatedBy') != getattr(new, 'treatedBy'):
        old_value = getattr(old, 'treatedBy').username if getattr(old, 'treatedBy') is not None else 'nobody'
        new_value = getattr(new, 'treatedBy').username if getattr(new, 'treatedBy') is not None else 'nobody'
        actions.append({
            'ticket': new,
            'action': 'update_property',
            'user': user,
            'property': 'treatedBy',
            'previous_value': old_value,
            'new_value': new_value
        })

    for field in set(TICKET_FIELDS) - set(TICKET_MODIFICATION_INVALID_FIELDS):
        if getattr(old, field) != getattr(new, field):
            actions.append({
                'ticket': new,
                'action': 'update_property',
                'user': user,
                'property': field,
                'previous_value': getattr(old, field),
                'new_value': getattr(new, field)
            })
    return actions


def update_snooze_duration(ticket_id, body, user):
    """ Update ticket snooze duration
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Not Found')

    try:
        data = {'snoozeDuration': body['snoozeDuration']}

        if data['snoozeDuration'] == 0 and ticket.status == 'WaitingAnswer':
            ticket.previousStatus = ticket.status
            ticket.status = 'Alarm'
            ticket.save()

        if int(data['snoozeDuration']) > 10000000:
            raise BadRequest('Invalid duration')

        # Delay jobs
        new_duration = int(data['snoozeDuration'])
        if new_duration > ticket.snoozeDuration:
            delay = new_duration - ticket.snoozeDuration
            delay = timedelta(seconds=delay)
            utils.default_queue.enqueue(
                'ticket.delay_jobs',
                ticket=ticket.id,
                delay=delay,
                back=False
            )
        else:
            delay = ticket.snoozeDuration - new_duration
            delay = timedelta(seconds=delay)
            utils.default_queue.enqueue(
                'ticket.delay_jobs',
                ticket=ticket.id,
                delay=delay,
                back=True
            )
        return __update_duration(ticket, data, user)
    except (KeyError, ValueError) as ex:
        raise BadRequest(str(ex.message))


def update_pause_duration(ticket_id, body, user):
    """ Update ticket pause duration
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        if ticket.status != 'Paused':
            raise BadRequest('Ticket is not paused')
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Not Found')

    try:
        data = {'pauseDuration': body['pauseDuration']}
        if int(data['pauseDuration']) > 10000000:
            raise BadRequest('Invalid duration')

        # Delay jobs
        new_duration = int(data['pauseDuration'])
        if new_duration > ticket.pauseDuration:
            delay = new_duration - ticket.pauseDuration
            delay = timedelta(seconds=delay)
            utils.default_queue.enqueue(
                'ticket.delay_jobs',
                ticket=ticket.id,
                delay=delay,
                back=False
            )
        else:
            delay = ticket.pauseDuration - new_duration
            delay = timedelta(seconds=delay)
            utils.default_queue.enqueue(
                'ticket.delay_jobs',
                ticket=ticket.id,
                delay=delay,
                back=True
            )
        return __update_duration(ticket, data, user)
    except (KeyError, ValueError) as ex:
        raise BadRequest(str(ex.message))


def __update_duration(ticket, data, user):
    """ Generic update for duration
    """
    try:
        key = data.keys()[0]
        previous = getattr(ticket, key)
        data[key.replace('Duration', 'Start')] = datetime.now()

        Ticket.objects.filter(pk=ticket.pk).update(**data)
        ticket = Ticket.objects.get(pk=ticket.pk)

        database.log_action_on_ticket(
            ticket=ticket,
            action='update_property',
            user=user,
            property=key.replace('Duration', ''),
            previous_value=str(timedelta(seconds=previous)),
            new_value=str(timedelta(seconds=getattr(ticket, key)))
        )

    except (FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))

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
            defendant_obj = DefendantsController.get_or_create(customer_id=defendant['customerId'])
            if not defendant_obj:
                raise BadRequest('Defendant not found')
        except KeyError:
            raise BadRequest('Missing customerId or id in defendant body')

        # Cascade update
        if ticket.defendant != defendant:
            ticket.reportTicket.update(defendant=defendant_obj.id)

    return defendant_obj


def get_providers(ticket_id):
    """ Get ticket's providers
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

    emails = ticket.reportTicket.all().values_list('provider__pk', flat=True).distinct()
    providers = [ProvidersController.show(email) for email in emails]

    for prov in providers:
        prov['contacted'] = ContactedProvider.objects.filter(
            ticket=ticket,
            provider__email=prov['email']
        ).exists()

    return providers


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
        raise NotFound('Ticket not found')

    return [model_to_dict(p) for p in ticket.proof.all()]


def add_proof(ticket_id, body, user):
    """ Add proof to ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

    if isinstance(body, dict):
        body = [body]

    if not isinstance(body, list):
        raise BadRequest('Invalid body, expecting object or list')

    for param in body:
        try:
            ticket.proof.create(**param)
            ticket.save()
            database.log_action_on_ticket(
                ticket=ticket,
                action='add_proof',
                user=user
            )
        except (KeyError, FieldDoesNotExist, FieldError,
                IntegrityError, TypeError, ValueError) as ex:
            raise BadRequest(str(ex.message))

    return {'message': 'Proof successfully added to ticket'}


def update_proof(ticket_id, proof_id, body, user):
    """ Update proof
    """
    ticket = None
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        Proof.objects.get(id=proof_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Not Found')

    try:
        body.pop('id', None)
        body.pop('ticket', None)
        ticket.proof.update(**body)
        ticket.save()
        database.log_action_on_ticket(
            ticket=ticket,
            action='update_proof',
            user=user
        )
    except (KeyError, FieldDoesNotExist, FieldError, IntegrityError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))
    return {'message': 'Proof successfully updated'}


def delete_proof(ticket_id, proof_id, user):
    """ Delete proof
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

    try:
        proof = ticket.proof.get(id=proof_id)
        proof.delete()
        database.log_action_on_ticket(
            ticket=ticket,
            action='delete_proof',
            user=user
        )
    except (ObjectDoesNotExist, KeyError, FieldDoesNotExist,
            FieldError, IntegrityError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex.message))
    return {'message': 'Proof successfully deleted'}


def update_status(ticket, status, body, user):
    """
        Update ticket status
    """
    if not _precheck_user_status_update_authorizations(user, status):
        raise Forbidden('You are not allowed to set this status')

    try:
        status = status.lower()
    except AttributeError:
        raise BadRequest('Invalid status')

    if not isinstance(ticket, Ticket):
        try:
            ticket = Ticket.objects.get(id=ticket)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            raise NotFound('Ticket not found')

    if not status == 'waitinganswer' and status == ticket.status.lower():
        raise BadRequest('Ticket had already this status')

    resp = {}
    action = None
    if status == 'paused':
        try:
            resp = pause_ticket(ticket, body)
            new_value = '%s (for %s hour(s))' % (ticket.status, int(body['pauseDuration'] / 3600))
            action = {
                'ticket': ticket,
                'action': 'change_status',
                'user': user,
                'previous_value': ticket.previousStatus,
                'new_value': new_value
            }
        except (ValueError, TypeError, ObjectDoesNotExist):
            raise BadRequest('Invalid parameter')
        except KeyError as ex:
            raise BadRequest('Missing %s field' % (str(ex.message)))

    elif status == 'unpaused':
        try:
            resp = unpause_ticket(ticket)
            action = {
                'ticket': ticket,
                'action': 'change_status',
                'user': user,
                'previous_value': ticket.previousStatus,
                'new_value': ticket.status
            }
        except (ValueError, TypeError, ObjectDoesNotExist):
            raise BadRequest('Invalid parameter')
        except KeyError as ex:
            raise BadRequest('Missing %s field' % (str(ex.message)))

    elif status == 'waitinganswer':
        resp = {'message': 'Ticket waiting answer from customer'}
        try:
            if int(body['snoozeDuration']) > 10000000:
                raise BadRequest('Invalid snooze duration')
            ticket.snoozeDuration = int(body['snoozeDuration'])
            ticket.snoozeStart = datetime.now()
            ticket.previousStatus = ticket.status
            if ticket.snoozeDuration == 0:
                ticket.status = 'Alarm'
            else:
                ticket.status = 'WaitingAnswer'
            ticket.reportTicket.all().update(status='Attached')
            new_value = '%s (for %s hour(s))' % (ticket.status, int(body['snoozeDuration'] / 3600))
            action = {
                'ticket': ticket,
                'action': 'change_status',
                'user': user,
                'previous_value': ticket.previousStatus,
                'new_value': new_value
            }
        except (KeyError, ValueError):
            raise BadRequest('Missing or invalid snoozeDuration')

    elif status == 'closed':

        try:
            resolution = Resolution.objects.get(id=int(body['resolution']))
        except (AttributeError, KeyError, ValueError, ObjectDoesNotExist):
            raise BadRequest('Missing or invalid resolution id')

        resp = {'message': 'Ticket closed'}

        if ticket.mailerId:
            utils.default_queue.enqueue(
                'ticket.close_emails_thread',
                ticket_id=ticket.id,
            )

        resp = {'message': 'Ticket closed'}
        ticket.previousStatus = ticket.status
        ticket.status = 'Closed'
        ticket.reportTicket.all().update(status='Archived')
        ticket.resolution = resolution

        # Cancel pending jobs
        utils.default_queue.enqueue(
            'ticket.cancel_rq_scheduler_jobs',
            ticket_id=ticket.id,
            status=status
        )

        is_user_beginner = user.abusepermission_set.filter(
            category=ticket.category,
            profile__name='Beginner'
        ).count()
        if is_user_beginner:
            ticket.moderation = True

        action = {
            'ticket': ticket,
            'action': 'change_status',
            'user': user,
            'previous_value': ticket.previousStatus,
            'new_value': ticket.status,
            'close_reason': ticket.resolution.codename
        }

    elif status == 'reopened':
        resp = {'message': 'Ticket reopened'}
        ticket.previousStatus = ticket.status
        ticket.status = 'Reopened'
        ticket.reportTicket.all().update(status='Attached')
        action = {
            'ticket': ticket,
            'action': 'change_status',
            'user': user,
            'previous_value': ticket.previousStatus,
            'new_value': ticket.status
        }

    else:
        raise NotFound('Status not found')

    ticket.save()
    if action:
        database.log_action_on_ticket(**action)

    return resp


def pause_ticket(ticket, body):
    """ Pause ticket
    """
    if int(body['pauseDuration']) > 10000000:
        raise BadRequest('Invalid pause duration')

    ticket.pauseStart = datetime.now()
    ticket.pauseDuration = int(body['pauseDuration'])
    ticket.previousStatus = ticket.status
    ticket.status = 'Paused'

    # Delay jobs
    delay = timedelta(seconds=ticket.pauseDuration)
    utils.default_queue.enqueue('ticket.delay_jobs', ticket=ticket.id, delay=delay, back=False)

    return {'message': 'Ticket paused for %d hour(s)' % (ticket.pauseDuration)}


def unpause_ticket(ticket):
    """ Unpause ticket
    """
    # Delay jobs
    delay = timedelta(seconds=ticket.pauseDuration) - (datetime.now() - ticket.pauseStart)
    utils.default_queue.enqueue('ticket.delay_jobs', ticket=ticket.id, delay=delay, back=True)

    if ticket.previousStatus == 'WaitingAnswer' and ticket.snoozeDuration and ticket.snoozeStart:
        ticket.snoozeDuration = ticket.snoozeDuration + (datetime.now() - ticket.pauseStart).seconds
    ticket.pauseStart = None
    ticket.pauseDuration = None
    ticket.status = ticket.previousStatus
    ticket.previousStatus = 'Paused'

    return {'message': 'Ticket unpaused'}


@transaction.atomic
def bulk_update(body, user, method):
    """
        Add or update infos for multiple tickets
    """
    tickets = __check_bulk_conformance(body, user, method)

    for ticket in tickets:
        assign_if_not(ticket, user)

    # Update status
    if 'status' in body['properties']:
        if body['properties']['status'].lower() not in TICKET_BULK_VALID_STATUS:
            raise BadRequest('Status not supported')

        valid_fields = ('pauseDuration', 'resolution')
        properties = {k: v for k, v in body['properties'].iteritems() if k in valid_fields}

        for ticket in tickets:
            update_status(ticket, body['properties']['status'], properties, user)

    # Update general fields
    properties = {k: v for k, v in body['properties'].iteritems() if k in TICKET_BULK_VALID_FIELDS}

    if properties:
        for ticket in tickets:
            update(ticket, properties, user, bulk=True)

    return {'message': 'Ticket(s) successfully updated'}


@transaction.atomic
def bulk_delete(body, user, method):
    """
        Delete infos from multiple tickets
    """
    tickets = __check_bulk_conformance(body, user, method)

    # Update tags
    try:
        if 'tags' in body['properties'] and isinstance(body['properties']['tags'], list):
            for ticket in tickets:
                for tag in body['properties']['tags']:
                    remove_tag(ticket.id, tag['id'], user)
    except (KeyError, TypeError, ValueError):
        raise BadRequest('Invalid or missing tag(s) id')

    return {'message': 'Ticket(s) successfully updated'}


def __check_bulk_conformance(body, user, method):
    """
        Check request conformance for bulk
    """
    if not body.get('tickets') or not body.get('properties'):
        raise BadRequest('Missing tickets or properties in body')

    try:
        tickets = Ticket.objects.filter(id__in=list(body['tickets']))
    except (AttributeError, TypeError, ValueError, KeyError):
        raise BadRequest('Invalid ticket(s) id')

    for ticket in tickets:
        GeneralController.check_perms(method=method, user=user, ticket=ticket.id)

    return tickets


def add_tag(ticket_id, body, user):
    """ Add ticket tag
    """
    try:
        tag = Tag.objects.get(**body)
        ticket = Ticket.objects.get(id=ticket_id)

        if ticket.__class__.__name__ != tag.tagType:
            raise BadRequest('Invalid tag for ticket')

        ticket.tags.add(tag)
        ticket.save()
        database.log_action_on_ticket(
            ticket=ticket,
            action='add_tag',
            user=user,
            tag_name=tag.name
        )
    except MultipleObjectsReturned:
        raise BadRequest('Please use tag id')
    except (KeyError, FieldError, IntegrityError, ObjectDoesNotExist, ValueError):
        raise NotFound('Tag or ticket not found')
    return {'message': 'Tag successfully added'}


def remove_tag(ticket_id, tag_id, user):
    """ Remove ticket tag
    """
    try:
        tag = Tag.objects.get(id=tag_id)
        ticket = Ticket.objects.get(id=ticket_id)

        if ticket.__class__.__name__ != tag.tagType:
            raise BadRequest('Invalid tag for ticket')

        ticket.tags.remove(tag)
        ticket.save()
        database.log_action_on_ticket(
            ticket=ticket,
            action='remove_tag',
            user=user,
            tag_name=tag.name
        )

    except (ObjectDoesNotExist, FieldError, IntegrityError, ValueError):
        raise NotFound('Not Found')
    return {'message': 'Tag successfully removed'}


def interact(ticket_id, body, user):
    """
        Magic endpoint to save operator's time
    """
    if not _precheck_user_interact_authorizations(user, body):
        raise Forbidden('You are not allowed use this interact parameters')
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

    if not all(key in body for key in ('emails', 'action')):
        raise BadRequest('Missing param(s): need emails and action')

    for params in body['emails']:
        if not all(params.get(key) for key in ('to', 'subject', 'body')):
            raise BadRequest('Missing param(s): need subject and body in email')
        category = params['category'] if params.get('category') else 'Defendant'
        category = category.title()
        if category not in EMAIL_VALID_CATEGORIES:
            raise BadRequest('Invalid email category')

    action = body['action']

    try:
        __parse_interact_action(ticket, action, user)
    except (AttributeError, KeyError, ValueError, TypeError):
        raise BadRequest('Missing or invalid params in action')

    for params in body['emails']:

        attachments = None
        if params.get('attachments'):
            if len(params['attachments']) > 5:
                raise BadRequest('Too many attachments')
            try:
                attachments = _save_and_sanitize_attachments(ticket, params['attachments'])
            except StorageServiceException:
                raise InternalServerError('Error while uploading attachments')
            except KeyError:
                raise BadRequest('Missing or invalid params in attachments')

        category = params['category'] if params.get('category') else 'Defendant'
        for recipient in params['to']:
            try:
                ImplementationFactory.instance.get_singleton_of('MailerServiceBase').send_email(
                    ticket,
                    recipient,
                    params['subject'],
                    params['body'],
                    category,
                    attachments=attachments,
                )
                database.log_action_on_ticket(
                    ticket=ticket,
                    action='send_email',
                    user=user,
                    email=recipient
                )
            except MailerServiceException as ex:
                raise InternalServerError(str(ex))

    return {'message': 'Ticket successfully updated'}


def _save_and_sanitize_attachments(ticket, attachments):

    for attachment in attachments:
        attachment['filename'] = text.get_valid_filename(attachment['filename'])
        attachment['content_type'] = attachment.pop('contentType')

        content = base64.b64decode(attachment['content'])
        storage_filename = hashlib.sha256(attachment['content']).hexdigest()
        storage_filename = storage_filename + '-attach-'
        storage_filename = storage_filename.encode('utf-8')
        storage_filename = storage_filename + attachment['filename']

        storage = settings.GENERAL_CONFIG['email_storage_dir']
        with ImplementationFactory.instance.get_instance_of('StorageServiceBase', storage) as cnx:
            cnx.write(storage_filename, content)

        ticket.reportTicket.last().attachments.add(AttachedDocument.objects.create(
            filename=storage_filename,
            filetype=attachment['content_type'],
            name=attachment['filename']
        ))

    return attachments


def __parse_interact_action(ticket, action, user):
    """ Parse action of interact endpoint's body
    """
    resp = {'message': 'OK'}

    # Check resolution
    resolution_id = None
    if action.get('params') and action['params'].get('resolution'):
        resolution_id = int(action['params']['resolution'])
        if not Resolution.objects.filter(id=resolution_id).exists():
            raise NotFound('Ticket resolution not found')

    if 'action' in action['codename']:

        # Check action
        try:
            action_id = int(action['params']['action'])
        except ObjectDoesNotExist:
            raise NotFound('Action not found')

        # Check IP address
        ip_addr = __get_ip_for_action(ticket, action)
        if not ip_addr:
            raise BadRequest('No IP specified')

        if not __check_action_rights(ticket, action_id, user):
            raise Forbidden('Invalid permission for action')

        if action['codename'] == 'waiting_answer_then_action':
            resp = update_status(
                ticket,
                'waitinganswer',
                {'snoozeDuration': action['params']['snoozeDuration']},
                user,
            )
            resp = schedule_asynchronous_job(
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
            resp = update_status(
                ticket,
                'waitinganswer',
                {'snoozeDuration': action['params']['snoozeDuration']},
                user,
            )
            resp = schedule_asynchronous_job(
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
            resp = schedule_asynchronous_job(
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
            resp = update_status(
                ticket,
                'waitinganswer',
                {'snoozeDuration': action['params']['snoozeDuration']},
                user
            )
        elif action['codename'] == 'action_then_close':
            resp = schedule_asynchronous_job(
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
        resp = update_status(
            ticket,
            'waitinganswer',
            {'snoozeDuration': action['params']['snoozeDuration']},
            user
        )
    elif action['codename'] == 'close_with_resolution':
        resp = update_status(
            ticket,
            'closed',
            {'resolution': resolution_id},
            user
        )
    elif action['codename'] == 'pause_ticket':
        resp = update_status(
            ticket,
            'paused',
            {'pauseDuration': action['params']['pauseDuration']},
            user)
    else:
        raise NotFound('Action not found')

    return resp


def __get_ip_for_action(ticket, action):
    """
        Extract and check IP address for action
    """
    # Get ticket IP(s)
    ips_on_ticket = ticket.reportTicket.all().values_list(
        'reportItemRelatedReport__ip',
        'reportItemRelatedReport__fqdnResolved'
    ).distinct()
    ips_on_ticket = [item for sub in ips_on_ticket for item in sub if item]
    ips_on_ticket = list(set(ips_on_ticket))

    # Check IP
    ip_addr = None
    if action['params'].get('ip'):
        if action['params']['ip'] not in ips_on_ticket:
            raise BadRequest('Specified IP address not attached to ticket')
        else:
            ip_addr = action['params']['ip']
    else:
        if len(ips_on_ticket) == 1:
            ip_addr = ips_on_ticket[0]
        else:
            raise BadRequest('Multiple or no IP on this ticket')
    return ip_addr


def get_actions_list(ticket_id, user):
    """
        List possible actions for ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        if not ticket.service or not ticket.defendant:
            return []
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

    try:
        perm = AbusePermission.objects.get(user=user, category=ticket.category)
        authorized = list(set(perm.profile.actions.all().values_list('id', flat=True)))
    except ObjectDoesNotExist:
        raise Forbidden('You can not interact with this ticket')

    try:
        actions = ImplementationFactory.instance.get_singleton_of(
            'ActionServiceBase'
        ).list_actions_for_ticket(ticket)
    except ActionServiceException:
        raise InternalServerError('Unable to list actions for this ticket')

    actions = [model_to_dict(action) for action in actions if action.id in authorized]
    return actions


def cancel_asynchronous_job(ticket_id, job_id, user):
    """ Cancel task on ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        job = ServiceActionJob.objects.get(id=job_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket or job not found')

    if ticket.action:
        database.log_action_on_ticket(
            ticket=ticket,
            action='cancel_action',
            user=user,
            action_name=ticket.action.name
        )

    utils.scheduler.cancel(job.asynchronousJobId)
    ServiceActionJob.objects.filter(
        asynchronousJobId=job.asynchronousJobId
    ).update(status='cancelled')
    ticket.save()
    return {'message': 'Task successfully canceled'}


def schedule_asynchronous_job(ticket_id, action_id, ip_addr, user, seconds=1, method='apply_action', params=None):
    """
        Schedule task on ticket
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        action = ServiceAction.objects.get(id=action_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket or action not found')

    if not params:
        params = {}
    params['timeout'] = 3600

    if not __check_action_rights(ticket, action.id, user):
        raise Forbidden('Invalid permission for this action')

    # Cancel previous pending jobs
    for job in ticket.jobs.filter(ip=ip_addr):
        if job.asynchronousJobId in utils.scheduler:
            utils.scheduler.cancel(job.asynchronousJobId)
            job.status = 'cancelled by new action'
            job.save()

    async_job = utils.scheduler.enqueue_in(timedelta(seconds=seconds), method, **params)
    job = ServiceActionJob.objects.create(
        ip=ip_addr,
        action=action,
        asynchronousJobId=async_job.id,
        creationDate=datetime.now()
    )

    ticket.action = action
    delay = 'now' if seconds == 1 else 'in %s hour(s)' % (str(seconds / 3600))
    ticket.jobs.add(job)
    ticket.save()

    database.log_action_on_ticket(
        ticket=ticket,
        action='set_action',
        user=user,
        action_name=action.name,
        action_execution_date=delay
    )
    return {'message': 'Task successfully created'}


def get_jobs_status(ticket_id):
    """
        Get actions todo status
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

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

    return resp


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
    """
        Get TODO tickets
    """
    # Parse filters from request
    filters = {}
    if kwargs.get('filters'):
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex.message))

    user = kwargs['user']
    try:
        scheduling_algo = user.operator.role.modelsAuthorizations['ticket']['schedulingAlgorithm']
        tickets, nb_record = TicketSchedulingAlgorithmFactory.instance.get_singleton_of(
            scheduling_algo
        ).get_tickets(
            user=user,
            filters=filters
        )
        __format_ticket_response(tickets)
    except (ObjectDoesNotExist, KeyError):
        tickets = []
        nb_record = 0

    return {'tickets': list(tickets), 'ticketsCount': nb_record}


def get_emails(ticket_id):
    """
        Get all emails for this tickets
    """
    ticket = None
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

    try:
        emails = ImplementationFactory.instance.get_singleton_of(
            'MailerServiceBase'
        ).get_emails(ticket)
        response = []
        for email in emails:
            attachments = _get_email_attachments(email, ticket)
            response.append({
                'body': email.body,
                'created': email.created,
                'from': email.sender,
                'subject': email.subject,
                'to': email.recipient,
                'category': email.category,
                'attachments': attachments,
            })
        return response
    except (KeyError, MailerServiceException) as ex:
        raise InternalServerError(str(ex))


def _get_email_attachments(email, ticket):

    attachments = []
    if not email.attachments:
        return attachments

    filters = [{'name': a['filename'], 'filetype': a['content_type']} for a in email.attachments]
    filters.extend([{'name': a['name'].replace('_', ' '), 'filetype': a['filetype']} for a in filters])

    for attach in filters:
        for att in ticket.attachments.filter(**attach):
            desc = model_to_dict(att)
            if desc not in attachments:
                attachments.append(desc)

    return attachments


def _precheck_user_interact_authorizations(user, body):
    """
       Check if user's interact parameters are allowed
    """
    authorizations = user.operator.role.modelsAuthorizations
    if authorizations.get('ticket') and authorizations['ticket'].get('interact'):
        return body['action']['codename'] in authorizations['ticket']['interact']
    return False


def _precheck_user_fields_update_authorizations(user, body):
    """
       Check if user's update paramaters are allowed
    """
    authorizations = user.operator.role.modelsAuthorizations
    if authorizations.get('ticket') and authorizations['ticket'].get('fields'):
        body = {k: v for k, v in body.iteritems() if k in authorizations['ticket']['fields']}
        if not body:
            return False, body
        return True, body
    return False, body


def _precheck_user_status_update_authorizations(user, status):
    """
       Check if user's update paramaters are allowed
    """
    authorizations = user.operator.role.modelsAuthorizations
    if authorizations.get('ticket') and authorizations['ticket'].get('status'):
        return status.lower() in authorizations['ticket']['status']
    else:
        return False


def get_timeline(ticket_id, **kwargs):
    """
        Get ̀àbuse.models.Ticket` history and activities
    """
    try:
        ticket = Ticket.objects.get(id=ticket_id)
    except (IndexError, ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket not found')

    # Parse filters from request
    filters = {}
    if kwargs.get('filters'):
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex.message))
    try:
        limit = int(filters['paginate']['resultsPerPage'])
        offset = int(filters['paginate']['currentPage'])
    except KeyError:
        limit = 10
        offset = 1

    with_meta = False
    if filters.get('withMetadata'):
        with_meta = True

    order_by = 'date' if filters.get('reverse') else '-date'

    history = _get_timeline_history(ticket, with_meta, order_by, limit, offset)
    return history


def _get_timeline_history(ticket, with_meta, order_by, limit, offset):

    history = ticket.ticketHistory.all().values_list(
        'user__username',
        'date',
        'action',
        'actionType'
    ).order_by(order_by)[(offset - 1) * limit:limit * offset]

    history = [{
        'username': username,
        'date': date,
        'log': log,
        'actionType': action_type
    } for username, date, log, action_type in history]

    if not with_meta:
        return history

    for entry in history:
        entry['metadata'] = None
        if entry['actionType'] in ['AddComment', 'UpdateComment']:
            comment = ticket.comments.filter(
                comment__date__range=(
                    entry['date'] - timedelta(seconds=1),
                    entry['date'] + timedelta(seconds=1),
                )
            ).values_list(
                'comment__comment',
                flat=True
            ).last()
            entry['metadata'] = {
                'key': 'comment',
                'value': comment
            }
        elif entry['actionType'] in ['AddItem', 'UpdateItem']:
            item = ticket.reportTicket.filter(
                reportItemRelatedReport__date__range=(
                    entry['date'] - timedelta(seconds=1),
                    entry['date'] + timedelta(seconds=1),
                )
            ).values_list(
                'reportItemRelatedReport__rawItem',
                flat=True
            ).last()
            entry['metadata'] = {
                'key': 'item',
                'value': item
            }

    return history


def get_attachment(ticket_id, attachment_id):
    """
        Get given abuse.models.AttachedDocument`for given `abuse.models.Ticket`
    """
    try:
        Ticket.objects.filter(id=ticket_id)
        attachment = AttachedDocument.objects.get(id=attachment_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Ticket or attachment not found')

    resp = None
    try:
        with ImplementationFactory.instance.get_instance_of(
            'StorageServiceBase',
            settings.GENERAL_CONFIG['email_storage_dir']
        ) as cnx:
            raw = cnx.read(attachment.filename)
            resp = {
                'raw': base64.b64encode(raw),
                'filetype': str(attachment.filetype),
                'filename': attachment.name.encode('utf-8'),
            }
    except StorageServiceException:
        pass

    if not resp:
        raise NotFound('Raw attachment not found')

    return resp
