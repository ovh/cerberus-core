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
    Common API endpoints
"""

import json
import operator
import os
import re
from base64 import b64encode
from copy import deepcopy
from datetime import datetime, timedelta
from time import mktime
from urllib import unquote

import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.core.exceptions import (FieldError, ObjectDoesNotExist,
                                    ValidationError)
from django.core.validators import validate_ipv46_address
from django.db import IntegrityError
from django.db.models import Count, FieldDoesNotExist, Q
from django.forms.models import model_to_dict

from abuse.models import (AbusePermission, Category, MassContact,
                          MassContactResult, Profile, Report, ReportItem,
                          Resolution, Tag, Ticket, Operator, Role)
from factory.factory import TicketSchedulingAlgorithmFactory
from utils import logger, utils
from worker import database

Logger = logger.get_logger(__name__)
CRYPTO = utils.Crypto()

DASHBOARD_STATUS = {
    'idle': ('Open', 'Reopened'),
    'waiting': ('WaitingAnswer', 'Paused'),
    'pending': ('Answered', 'Alarm'),
}

CHECK_PERM_DEFENDANT_LEVEL = ('Beginner', 'Advanced', 'Expert')
MASS_CONTACT_REQUIRED = ('{{ service }}', '{{ publicId }}', '{% if lang ==')

SEARCH_EXTRA_FIELDS = ['defendantTag', 'providerTag', 'defendant', 'defendantCountry', 'providerEmail', 'item', 'fulltext']
SEARCH_REPORT_FIELDS = list(set([f.name for f in Report._meta.fields] + SEARCH_EXTRA_FIELDS + ['reportTag']))
SEARCH_TICKET_FIELDS = list(set([f.name for f in Ticket._meta.fields] + SEARCH_EXTRA_FIELDS + ['ticketTag', 'attachedReportsCount', 'ticketIds']))

SEARCH_MAPPING = {
    'defendant': ['defendantEmail', 'defendantCustomerId'],
    'item': ['itemFqdnResolved', 'itemIpReverse', 'itemRawItem'],
    'ticketIds': ['id', 'publicId'],
}

TOOLBAR_TODO_STATUS = ('ActionError', 'Alarm', 'Open', 'Reopened')
TOOLBAR_TODO_COUNT_STATUS = ('ActionError', 'Answered', 'Alarm', 'Reopened', 'Open')
TOOLBAR_SLEEPING_STATUS = ('Paused', 'WaitingAnswer')


def auth(body):
    """ Login/password based auth
        if success, generates HMAC512 based token
    """
    try:
        username = body['name']
        password = body['password']
    except (TypeError, KeyError):
        return False, 'Invalid fields in body'

    user = authenticate(username=username, password=password)
    if user is not None and user.is_active:
        user = User.objects.get_or_create(username=username)[0]
        user.last_login = datetime.now()
        user.save()
        data = {
            'id': user.id,
            'rand': b64encode(os.urandom(64)).decode('utf-8')
        }
        token = jwt.encode(
            {
                'data': CRYPTO.encrypt(json.dumps(data)),
                'exp': datetime.utcnow() + timedelta(days=1),
            },
            settings.SECRET_KEY,
            algorithm='HS512'
        )
        return True, {'token': token}

    return False, 'Invalid username or password'


def logout(request):
    """ Logout a user
    """
    try:
        token = request.environ['HTTP_X_API_TOKEN']
    except (KeyError, IndexError, TypeError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing HTTP X-Api-Token header'}

    try:
        data = jwt.decode(token, settings.SECRET_KEY)
        data = json.loads(CRYPTO.decrypt(str(data['data'])))
        user = User.objects.get(id=data['id'])
        user.last_login = datetime.fromtimestamp(0)
        user.save()
        return 200, {'status': 'OK', 'code': 200, 'message': 'OK'}
    except (utils.CryptoException, KeyError, jwt.DecodeError, jwt.ExpiredSignature, User.DoesNotExist):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid token'}


def check_perms(**kwargs):
    """ Check abuse permissions for a user
    """
    if 'user' not in kwargs:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing user or report'}

    user = kwargs['user']
    code = 200
    response = {'status': 'OK', 'code': 200}

    try:
        authorized_cats = AbusePermission.objects.filter(user=user.id).values_list('category', flat=True).distinct()
    except AttributeError:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Need User object'}

    if 'report' in kwargs:
        try:
            rep = Report.objects.get(id=kwargs['report'])
            if rep.category_id not in authorized_cats:
                code = 403
                response = {'status': 'Forbidden', 'message': 'Report category not in your authorized categories', 'code': 403}

            profile = AbusePermission.objects.get(user=user.id, category=rep.category_id).profile.name
            if str(kwargs['method']) != 'GET' and profile == 'Read-only':
                code = 403
                response = {'status': 'Forbidden', 'message': 'Read-only access for this report', 'code': 403}

        except ObjectDoesNotExist:
            code = 403
            response = {'status': 'Forbidden', 'code': 403, 'message': 'Forbidden'}
        except ValueError:
            code = 400
            response = {'status': 'Bad Request', 'code': 400, 'message': 'Report ID is integer'}
    if 'ticket' in kwargs:
        try:
            ticket = Ticket.objects.get(id=kwargs['ticket'])
            has_perm = AbusePermission.objects.filter(user=user.id, category=ticket.category_id, profile__name='Expert')
            if (ticket.confidential and not has_perm) or (ticket.category_id not in authorized_cats):
                code = 403
                response = {'status': 'Forbidden', 'code': 403, 'message': 'Forbidden'}

            profile = AbusePermission.objects.get(user=user.id, category=ticket.category_id).profile.name
            if str(kwargs['method']) != 'GET' and profile == 'Read-only':
                code = 403
                response = {'status': 'Forbidden', 'message': 'Read-only access for this ticket', 'code': 403}

        except ObjectDoesNotExist:
            code = 403
            response = {'status': 'Forbidden', 'code': 403, 'message': 'Forbidden'}
        except ValueError:
            code = 400
            response = {'status': 'Bad Request', 'code': 400, 'message': 'Report ID is integer'}
    if 'defendant' in kwargs and kwargs['method'] != 'GET' and not AbusePermission.objects.filter(user=user.id, profile__name__in=CHECK_PERM_DEFENDANT_LEVEL).count():
        code = 403
        response = {'status': 'Forbidden', 'code': 403, 'message': 'Forbidden'}
    return code, response


def get_users_infos(**kwargs):
    """ Get user(s) infos
    """
    users = []
    where = [Q()]
    if 'user' in kwargs:
        where.append(Q(id=kwargs['user']))

    where = reduce(operator.and_, where)
    try:
        users = User.objects.filter(where).values('id', 'username', 'email', 'operator')
    except (TypeError, ValueError):
        return 400, {'status': 'Bad request', 'code': 400, 'message': 'Bad request'}

    if not users:
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'User not found'}

    categories = Category.objects.all().values_list('name', flat=True)

    for user in users:
        profiles = []
        for category in categories:
            try:
                perm = AbusePermission.objects.get(user=user['id'], category=category)
                profile = perm.profile.name
                access = True
            except ObjectDoesNotExist:
                access = False
                profile = None

            profiles.append(
                {
                    'category': category,
                    'access': access,
                    'profile': profile
                }
            )
        user['profiles'] = profiles
        role = None
        if Operator.objects.filter(id=user['operator']).exists():
            role = Operator.objects.get(id=user['operator']).role.codename
        user.pop('operator', None)
        user['role'] = role

    if 'user' in kwargs:
        return 200, dict(users[0])
    else:
        return 200, list(users)


def update_user(user_id, body):
    """ Update user infos and permissions
    """
    try:
        user = User.objects.get(id=user_id)
    except ObjectDoesNotExist:
        return 404, {'status': 'Not Found', 'code': 404}

    if 'profiles' in body:
        try:
            _update_permissions(user, body['profiles'])
        except ObjectDoesNotExist:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid category or profile'}

        # Unassigned tickets no more allowed
        cats = AbusePermission.objects.filter(user=user).values_list('category', flat=True).distinct()
        for ticket in Ticket.objects.filter(treatedBy=user):
            if ticket.category_id not in cats:
                database.log_action_on_ticket(
                    ticket=ticket,
                    action='change_treatedby',
                    new_value=user.username
                )
                ticket.treatedBy = None
                ticket.save()
        body.pop('profiles', None)

    try:
        body.pop('id', None)
        if 'role' in body:
            if not Operator.objects.filter(user=user).exists():
                role = Role.objects.get(codename=body['role'])
                Operator.objects.create(user=user, role=role)
            elif body['role'] != user.operator.role.codename:
                user.operator.role = Role.objects.get(codename=body['role'])
                user.operator.save()
            body.pop('role')
        User.objects.filter(pk=user.pk).update(**body)
    except (KeyError, ValueError, FieldError, FieldDoesNotExist, IntegrityError, ObjectDoesNotExist):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid fields in body'}

    code, resp = get_users_infos(user=user_id)
    return code, resp


def _update_permissions(user, permissions):
    """ Update user permissions
    """

    AbusePermission.objects.filter(user=user).delete()

    for permission in permissions:
        if permission['access']:
            profile = Profile.objects.get(name=permission['profile'])
            category = Category.objects.get(name=permission['category'])
            AbusePermission.objects.get_or_create(
                user=user,
                category=category,
                profile=profile
            )


def get_ip_report_count(**kwargs):
    """ Count nb of reports for an ip
    """
    filters = {}
    if 'filters' in kwargs:
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError):
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Bad Request'}

    try:
        start = datetime.fromtimestamp(filters['start'])
        end = datetime.fromtimestamp(filters['end'])
    except (KeyError, TypeError, ValueError):
        start = datetime.now() - timedelta(weeks=1)
        end = datetime.now() + timedelta(weeks=1)

    ip_addr = kwargs['ip']
    try:
        validate_ipv46_address(ip_addr)
        count = ReportItem.objects.filter(
            itemType='IP',
            rawItem=ip_addr,
            report__receivedDate__gte=start,
            report__receivedDate__lte=end,
        ).values_list('report__id').distinct().count()
        return 200, {'reports': count}
    except ValidationError:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Not a valid IPV4'}


def get_profiles():
    """ List all Abuse profiles
    """
    return 200, [model_to_dict(p) for p in Profile.objects.all().order_by('id')]


def get_users_login():
    """ Get login for all users
    """
    return 200, list(User.objects.all().values('username'))


def get_ticket_resolutions():
    """ List all ticket resolutions
    """
    return [model_to_dict(p) for p in Resolution.objects.all()]


def add_ticket_resolution(body):
    """ Add a ticket resolution
    """
    try:
        _, created = Resolution.objects.get_or_create(codename=body['codename'])
        if not created:
            return 409, {'status': 'Conflict', 'code': 409, 'message': 'Ticket resolution already exists'}
    except (AttributeError, ValueError, KeyError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid or missing codename in body'}
    return 200, get_ticket_resolutions()


def update_ticket_resolution(resolution_id, body):
    """ Update a ticket resolution
    """
    try:
        resolution = Resolution.objects.get(id=int(resolution_id))
        codename = body['codename']
        if Resolution.objects.filter(codename=codename).count():
            return 409, {'status': 'Conflict', 'code': 409, 'message': 'Ticket resolution already exists'}
        resolution.codename = codename
        resolution.save()
        return 200, get_ticket_resolutions()
    except (AttributeError, ValueError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Expecting id, not string'}
    except ObjectDoesNotExist:
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket resolution not found'}
    except KeyError:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Missing codename in body'}


def delete_ticket_resolution(resolution_id):
    """ Delete given ticket resolution
    """
    try:
        resolution = Resolution.objects.get(id=int(resolution_id))
        if resolution.ticket_set.count():
            return 403, {'status': 'Bad Request', 'code': 403, 'message': 'This resolution is linked to at least one ticket'}
    except ValueError:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Expecting id, not string'}
    except ObjectDoesNotExist:
        return 404, {'status': 'Not Found', 'code': 404, 'message': 'Ticket resolution not found'}

    Resolution.objects.filter(id=resolution.id).delete()
    return 200, get_ticket_resolutions()


def search(**kwargs):
    """ Global Search
    """
    filters = {}
    user = kwargs['user']

    if 'filters' in kwargs:
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError):
            return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Unable to decode JSON'}

    custom_filters = {
        'ticket': {
            'fields': SEARCH_TICKET_FIELDS,
            'filters': deepcopy(filters),
        },
        'report': {
            'fields': SEARCH_REPORT_FIELDS,
            'filters': deepcopy(filters),
        },
    }

    try:
        for _, values in custom_filters.iteritems():
            for key, val in filters.iteritems():
                if key == 'queryFields':
                    values['filters'][key] = [q for q in val if q in values['fields']]
                if key == 'sortBy':
                    values['filters'][key] = {k: v for k, v in filters[key].iteritems() if k in values['fields']}
                if key == 'where':
                    for key2 in filters[key].keys():
                        values['filters'][key][key2] = [a for a in filters[key][key2] if a.keys()[0] in values['fields']]
    except AttributeError:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid fields in body'}

    for _, values in custom_filters.iteritems():
        if 'where' in values['filters']:
            new_where = deepcopy(values['filters']['where'])
            for key, val in values['filters']['where'].iteritems():
                for field in values['filters']['where'][key]:
                    if field.keys()[0] in SEARCH_MAPPING:
                        for new_field in SEARCH_MAPPING[field.keys()[0]]:
                            new_where[key].append({new_field: field[field.keys()[0]]})
                        new_where[key].remove(field)
                    elif 'ticketTag' in field:
                        if Tag.objects.filter(name__in=field['ticketTag'], tagType='Report').count():
                            new_where[key].append({'reportsTag': field['ticketTag']})
                        else:
                            new_where[key].append({'ticketsTag': field['ticketTag']})
                        new_where[key].remove(field)
            values['filters']['where'] = new_where

    from api.controllers import ReportsController, TicketsController
    code1, reps, nb_reps = ReportsController.index(filters=json.dumps(custom_filters['report']['filters']), user=user)
    code2, ticks, nb_ticks = TicketsController.index(filters=json.dumps(custom_filters['ticket']['filters']), user=user)

    code = code1 if code1 > code2 else code2
    return code, {'tickets': ticks, 'reports': reps, 'ticketsCount': nb_ticks, 'reportsCount': nb_reps}


def toolbar(**kwargs):
    """ Get reports/tickets stats
    """
    user = kwargs['user']
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

    # Aggregate all filters
    where = reduce(operator.and_, where)

    if not len(abuse_permissions):
        return 403, {'status': 'Forbidden', 'code': 403, 'message': 'You are not allowed to see any category'}

    resp = {}
    res = Ticket.objects.filter(where, treatedBy=user).values('status').annotate(count=Count('status'))
    resp['myTicketsCount'] = reduce(operator.add, [t['count'] if t['status'] != 'Closed' else 0 for t in res]) if res else 0
    resp['myTicketsAnsweredCount'] = reduce(operator.add, [t['count'] if t['status'] == 'Answered' else 0 for t in res]) if res else 0
    resp['myTicketsTodoCount'] = reduce(operator.add, [t['count'] if t['status'] in TOOLBAR_TODO_STATUS else 0 for t in res]) if res else 0
    resp['myTicketsSleepingCount'] = reduce(operator.add, [t['count'] if t['status'] in TOOLBAR_SLEEPING_STATUS else 0 for t in res]) if res else 0
    resp['escalatedCount'] = Ticket.objects.filter(where, escalated=True).order_by('id').distinct().count()
    resp['toValidateCount'] = Report.objects.filter(status='ToValidate').count()

    # Get count of scheduling algorithm
    try:
        scheduling_algorithm = user.operator.role.modelsAuthorizations['ticket']['schedulingAlgorithm']
        todo_count = TicketSchedulingAlgorithmFactory.instance.get_singleton_of(scheduling_algorithm).count(where=where)
    except (TypeError, AttributeError, ObjectDoesNotExist, KeyError):
        todo_count = 0

    resp['todoCount'] = todo_count
    return 200, resp


def dashboard(**kwargs):
    """ Get dashboard stats
    """
    user = kwargs['user']
    authorized_categories = AbusePermission.objects.filter(user=user.id).values_list('category', flat=True).distinct().order_by('category')
    where = [Q(category=c) for c in authorized_categories]

    if not len(where):
        return 403, {'status': 'Forbidden', 'code': 403, 'message': 'You are not allowed to see any category'}

    where = reduce(operator.or_, where)

    resp = {}
    res = Report.objects.filter(where, ~Q(status='Archived')).values('category').annotate(count=Count('category'))
    resp['reportsByCategory'] = {k['category']: k['count'] for k in res}
    res = Report.objects.filter(where, ~Q(status='Archived')).values('status').annotate(count=Count('status'))
    resp['reportsByStatus'] = {k['status']: k['count'] for k in res}
    res = Ticket.objects.filter(where, ~Q(status='Closed')).values('status').annotate(count=Count('status'))
    resp['ticketsByStatus'] = {k['status']: k['count'] for k in res}
    resp['ticketsByCategory'] = {}

    for name, sts in DASHBOARD_STATUS.iteritems():
        request = Ticket.objects.filter(
            category__in=authorized_categories,
            status__in=sts
        ).values(
            'category'
        ).annotate(
            count=Count('category')
        ).order_by(
            'category'
        )
        request = {r['category']: r['count'] for r in request}
        resp['ticketsByCategory'].update({name: [request[cat] if cat in request else 0 for cat in authorized_categories]})

    resp['categories'] = list(authorized_categories)
    return 200, resp


def status(**kwargs):
    """ Get status available for tickets and/or reports
    """
    if 'model' in kwargs:
        model = kwargs['model']
        if str(model).lower() == 'ticket':
            return [{'label': v} for _, v in Ticket.TICKET_STATUS]
        if str(model).lower() == 'report':
            return [{'label': v} for _, v in Report.REPORT_STATUS]
    return [{'label': v} for _, v in Ticket.TICKET_STATUS] + [{'label': v} for _, v in Report.REPORT_STATUS]


def get_mass_contact(filters=None):
    """
        List all created mass-contact campaigns
    """
    # Parse filters from request
    query_filters = {}
    if filters:
        try:
            query_filters = json.loads(unquote(unquote(filters)))
        except (ValueError, SyntaxError, TypeError) as ex:
            return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}
    try:
        limit = int(query_filters['paginate']['resultsPerPage'])
        offset = int(query_filters['paginate']['currentPage'])
    except KeyError:
        limit = 10
        offset = 1

    sort = []
    try:
        sort += ['-' + k if v < 0 else k for k, v in query_filters['sortBy'].iteritems()]
    except KeyError:
        sort += ['id']

    campaigns = []
    try:
        for campaign in MassContact.objects.all().order_by(*sort)[(offset - 1) * limit:limit * offset]:
            campaigns.append({
                'campaignName': campaign.campaignName,
                'category': campaign.category.name,
                'user': campaign.user.username,
                'ipsCount': campaign.ipsCount,
                'date': int(mktime(campaign.date.timetuple())),
                'result': model_to_dict(campaign.masscontactresult_set.all()[0]),
            })
    except (AttributeError, KeyError, FieldError, SyntaxError, TypeError, ValueError) as ex:
        return 400, {'status': 'Bad Request', 'code': 400, 'message': str(ex.message)}
    return 200, campaigns


def post_mass_contact(body, user):
    """
       Create a worker task for mass contact
    """
    try:
        ips = list(set(body['ips']))
        for ip_address in ips:
            validate_ipv46_address(ip_address)
    except (TypeError, ValidationError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid value(s) in fields ips'}

    try:
        category = Category.objects.get(name=body['category'].title())
    except (AttributeError, ObjectDoesNotExist, TypeError):
        return 400, {'status': 'Bad Request', 'code': 400, 'message': 'Invalid category'}

    # Generates unified campaignName
    campaign_name = body['campaignName']
    campaign_name = re.sub(r'(\s+){2,}', ' ', campaign_name).replace(' ', '_').lower()
    campaign_name = re.sub('[^A-Za-z0-9_]+', '', campaign_name)
    campaign_name = u'mass_contact_' + campaign_name + u'_' + datetime.now().strftime('%D')

    # Check mustache (required for worker)
    for key, val in body['email'].iteritems():
        if not all([mustache in val for mustache in MASS_CONTACT_REQUIRED]):
            message = '%s templating elements required in %s' % (str(MASS_CONTACT_REQUIRED), key)
            return 400, {'status': 'Bad Request', 'code': 400, 'message': message}

    __create_jobs(campaign_name, ips, category, body, user)
    return 200, {'status': 'OK', 'code': 200, 'message': 'Campaign successfully created'}


def __create_jobs(campaign_name, ips, category, body, user):
    """
        Creates RQ jobs for each IP
    """
    # Save related infos
    campaign = MassContact.objects.create(
        campaignName=campaign_name,
        category=category,
        user=user,
        ipsCount=len(ips),
    )

    result = MassContactResult.objects.create(
        campaign=campaign,
    )

    # For each IP, create a worker job
    jobs = []
    for ip_address in ips:
        job = utils.queue.enqueue(
            'ticket.mass_contact',
            ip_address=ip_address,
            category=category.name,
            campaign_name=campaign_name,
            email_subject=body['email']['subject'],
            email_body=body['email']['body'],
            user_id=user.id,
            timeout=360,
        )
        jobs.append(job.id)

    utils.queue.enqueue(
        'ticket.check_mass_contact_result',
        result_campaign_id=result.id,
        jobs=jobs,
        timeout=3600,
    )


def get_notifications(user):
    """
        Get notifications for given user

        :param `abuse.models.User` user: An instance of `abuse.models.User`
        :rtype: tuple
        :returns: The status code and the notifications
    """
    response = utils.get_user_notifications(user.username)
    return 200, response


def get_roles():
    """
        Get Cerberus `abuse.models.Role`
    """
    return 200, list(Role.objects.all().values('id', 'codename', 'name'))


def monitor():
    """
        Endpoint to monitor API
    """
    Category.objects.count()
