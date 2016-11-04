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


""" Cerberus report items manager
"""

import json
import operator
import re
import time
from Queue import Queue
from threading import Thread
from urllib import unquote

from django.core.exceptions import FieldError, ValidationError
from django.core.validators import URLValidator, validate_ipv46_address
from django.db import IntegrityError, close_old_connections
from django.db.models import ObjectDoesNotExist, Q
from django.forms.models import model_to_dict
from werkzeug.exceptions import BadRequest, InternalServerError, NotFound

from abuse.models import (ItemScreenshotFeedback, Report, ReportItem,
                          Service, Ticket)
from adapters.dao.customer.abstract import CustomerDaoException
from adapters.services.phishing.abstract import PhishingServiceException
from api.controllers import DefendantsController, TicketsController
from factory.implementation import ImplementationFactory
from utils import schema, utils
from worker import database

ITEM_FIELDS = [f.name for f in ReportItem._meta.fields]

DNS_ERROR = {
    '-2': 'NXDOMAIN'
}


def get_items_infos(**kwargs):
    """ Get items informations
    """
    filters = {}
    if kwargs.get('filters'):
        try:
            filters = json.loads(unquote(unquote(kwargs['filters'])))
        except (ValueError, SyntaxError, TypeError) as ex:
            raise BadRequest(str(ex))

    try:
        limit = int(filters['paginate']['resultsPerPage'])
        offset = int(filters['paginate']['currentPage'])
    except KeyError:
        limit = 10
        offset = 1

    where = [Q()]
    if 'where' in filters and len(filters['where']):
        try:
            keys = set(k for k in filters['where'])
            if 'in' in keys:
                for i in filters['where']['in']:
                    for key, val in i.iteritems():
                        where.append(reduce(operator.or_, [Q(**{key: i}) for i in val]))
            if 'like' in keys:
                for i in filters['where']['like']:
                    for key, val in i.iteritems():
                        field = key + '__icontains'
                        where.append(reduce(operator.or_, [Q(**{field: val[0]})]))
        except (AttributeError, KeyError, IndexError, FieldError,
                SyntaxError, TypeError, ValueError) as ex:
            raise BadRequest(str(ex))

    where = reduce(operator.and_, where)

    # If backend is PostgreSQL, a simple distinct('rawItem') do the job
    try:
        count = ReportItem.objects.filter(
            where,
            report__in=kwargs['reps']
        ).values_list(
            'rawItem',
            flat=True
        ).distinct().count()
        raw_items = ReportItem.objects.filter(
            where,
            report__in=kwargs['reps']
        ).values_list(
            'rawItem',
            flat=True
        ).distinct()
        raw_items = raw_items[(offset - 1) * limit:limit * offset]
        items = []
        for raw in raw_items:
            items.append(ReportItem.objects.filter(
                where,
                report__in=kwargs['reps'],
                rawItem=raw
            ).last())
    except (AttributeError, KeyError, IndexError, FieldError,
            SyntaxError, TypeError, ValueError) as ex:
        raise BadRequest(str(ex))

    items = [{f.name: f.value_from_object(i) for f in ReportItem._meta.fields} for i in items]
    queue = Queue()
    threads = []
    now = int(time.time())

    for item in items:
        thread = Thread(target=__format_item_response, args=(item, now, queue))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    resp = {'items': [queue.get() for _ in xrange(len(items))]}
    resp['itemsCount'] = count

    return resp


def __format_item_response(item, now, queue):
    """ Add usefull information to items for UX
    """
    # Add ip network, diff if resolved IP changed etc ...
    history = []
    item['date'] = int(time.mktime(item['date'].timetuple()))

    if item.get('itemType') == 'URL' and not item.get('fqdnResolved'):
        item['fqdnResolved'] = DNS_ERROR['-2']

    history.append(item)

    # History == diff parsing/now
    current_item_infos = __check_item_status(item)
    for key, val in current_item_infos.iteritems():

        diff = False
        if isinstance(val, list):
            if item.get(key) and item[key] not in val:
                current_item_infos[key] = [v for v in val if v != item[key]][0]
                diff = True
        else:
            if item.get(key) and item[key] != val:
                diff = True
        if diff:
            current_item_infos['date'] = now
            history.append(current_item_infos)
            break

    for row in history:
        if row['itemType'] in ['FQDN', 'URL']:
            ip_addr = row['fqdnResolved']
        else:
            ip_addr = row['ip']
        row['ipCategory'] = utils.get_ip_network(ip_addr)

    res = {
        'rawItem': item['rawItem'],
        'report': item['report'],
        'id': item['id'],
        'itemType': item['itemType'],
        'history': history,
        'screenshotDetails': None
    }

    # Add screenshot feedback if available
    if ItemScreenshotFeedback.objects.filter(item_id=item['id']).exists():
        try:
            feedback = ItemScreenshotFeedback.objects.filter(item_id=item['id'])[0]
            details = ImplementationFactory.instance.get_instance_of(
                'PhishingServiceBase'
            ).is_screenshot_viewed(feedback.token)
            schema.valid_adapter_response('PhishingServiceBase', 'is_screenshot_viewed', details)
            res['screenshotDetails'] = {
                'screenshotId': feedback.token,
                'viewed': details['viewed'],
                'views': details['views'],
            }
            res['viewed'] = details['viewed']  # For compatiblity with UX
        except (PhishingServiceException, schema.InvalidFormatError, schema.SchemaNotFound):
            pass

    queue.put(res)
    close_old_connections()


def __check_item_status(item):
    """ Check current item status
    """
    current_item_infos = {
        'itemType': item['itemType'],
        'rawItem': item['rawItem'],
    }

    current_item_infos.update(utils.get_reverses_for_item(
        item['rawItem'],
        nature=item['itemType'],
        replace_exception=True,
    ))

    return current_item_infos


def get_items_report(**kwargs):
    """ Get report items
    """
    rep = kwargs['rep']
    return get_items_infos(reps=[rep], filters=kwargs.get('filters'))


def get_items_ticket(**kwargs):
    """ Get all items for a ticket
    """
    ticket = kwargs['ticket']
    reps = Report.objects.filter(ticket=ticket).values_list('id', flat=True)
    return get_items_infos(reps=reps, filters=kwargs.get('filters'))


def show(item_id):
    """ Get an item
    """
    try:
        item = ReportItem.objects.get(id=item_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Item not found')
    return model_to_dict(item)


def create(body, user):
    """
        Create a new report item
    """
    try:
        resp = __get_item_infos(body, user)
        item, created = ReportItem.objects.get_or_create(**resp)
        if resp['report'].ticket:
            database.log_action_on_ticket(
                ticket=resp['report'].ticket,
                action='add_item',
                user=user
            )
    except (AttributeError, FieldError, IntegrityError, KeyError, ObjectDoesNotExist) as ex:
        raise BadRequest(str(ex.message))
    if not created:
        raise BadRequest('Report items already exists')
    return show(item.id)


def update(item_id, body, user):
    """
        Update a report item
    """
    try:
        item = ReportItem.objects.get(id=item_id)
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Item not found')

    try:
        resp = __get_item_infos(body, user)
        ReportItem.objects.filter(pk=item.pk).update(**resp)
        item = ReportItem.objects.get(pk=item.pk)
        if resp['report'].ticket:
            database.log_action_on_ticket(
                ticket=resp['report'].ticket,
                action='update_item',
                user=user
            )
    except (AttributeError, FieldError, IntegrityError, KeyError, ObjectDoesNotExist):
        raise BadRequest('Invalid fields in body')
    return show(item_id)


def __get_item_infos(body, user):

    item_infos = body

    for key in item_infos.keys():
        if key not in ITEM_FIELDS:
            item_infos.pop(key, None)
    item_infos.pop('date', None)

    item_infos['report'] = Report.objects.get(id=item_infos['report'])
    resp = get_defendant_from_item(item_infos)

    item_infos.update(utils.get_reverses_for_item(
        item_infos['rawItem'],
        nature=item_infos['itemType']
    ))

    update_item_report_and_ticket(item_infos, resp['customerId'], resp['service'], user)

    return item_infos


def delete_from_report(item_id, rep, user):
    """ Delete an item
    """
    try:
        item = ReportItem.objects.get(id=item_id)
        ReportItem.objects.filter(report=rep, rawItem=item.rawItem).delete()
        report = Report.objects.get(id=rep)
        if report.ticket:
            database.log_action_on_ticket(
                ticket=report.ticket,
                action='delete_item',
                user=user
            )
        return {'message': 'Item successfully removed'}
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Item not found')


def delete_from_ticket(item_id, ticket):
    """ Cascade delete item
    """
    try:
        reps = Report.objects.filter(ticket=ticket)
        item = ReportItem.objects.get(id=item_id)
        ReportItem.objects.filter(report__in=reps, rawItem=item.rawItem).delete()
        return {'message': 'Item successfully removed'}
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Item not found')


def get_defendant_from_item(item):
    """
        Get defendant/service for given item
    """
    customer_id = None
    item['rawItem'] = _get_deobfuscate_item(item['rawItem'])

    try:
        ip_addr, hostname, url = _get_item_ip_hostname_url(item)
        if not ip_addr and not hostname:
            raise BadRequest('Unable to get infos for this item')
    except ValidationError:
        raise BadRequest('Invalid item')

    for param in {'urls': [url]}, {'ips': [ip_addr], 'fqdn': [hostname]}:
        try:
            services = ImplementationFactory.instance.get_singleton_of(
                'CustomerDaoBase'
            ).get_services_from_items(**param)
            schema.valid_adapter_response('CustomerDaoBase', 'get_services_from_items', services)
            if services:
                break
        except (CustomerDaoException, schema.InvalidFormatError, schema.SchemaNotFound):
            raise InternalServerError('Unknown exception while identifying defendant')

    if services:
        try:
            customer_id = services[0]['defendant']['customerId']
            service = services[0]['service']
        except (IndexError, KeyError):
            raise InternalServerError('Unable to parse CustomerDaoBase response')

    if not customer_id:
        raise NotFound('No defendant found for this item')

    return {'customerId': customer_id, 'service': service}


def _get_item_ip_hostname_url(item):
    """ Get item infos
    """
    ip_addr = hostname = url = None
    try:
        validate = URLValidator()
        validate(item['rawItem'])
        item['itemType'] = 'URL'
        url = item['rawItem']
    except ValidationError:
        try:
            validate_ipv46_address(item['rawItem'])
            item['itemType'] = 'IP'
        except ValidationError:
            item['itemType'] = 'FQDN'

    if item['itemType'] == 'URL':
        hostname = utils.get_url_hostname(item['rawItem'])
        ips = utils.get_ips_from_url(item['rawItem'])
        if ips:
            ip_addr = ips[0]
    elif item['itemType'] == 'IP':
        item['itemType'] = 'IP'
        ip_addr = item['rawItem']
    elif item['itemType'] == 'FQDN':
        hostname = item['rawItem']
        ips = utils.get_ips_from_fqdn(item['rawItem'])
        if ips:
            ip_addr = ips[0]

    return ip_addr, hostname, url


def update_item_report_and_ticket(item, customer_id, service, user):
    """ Eventually update report and ticket with item infos
    """
    if item['report'].defendant and customer_id != item['report'].defendant.customerId:
        message = 'Resolved customerId for this item (%s) does not ' \
                  'match report customerId' % (customer_id)
        raise BadRequest(message)

    if item['report'].service and service['name'] != item['report'].service.name:
        message = 'Resolved service for this item (%s) does not ' \
                  'match report service' % (customer_id)
        raise BadRequest(message)

    if not item['report'].defendant:
        defendant = DefendantsController.get_or_create(customer_id=customer_id)
        service_obj, _ = Service.objects.get_or_create(**service)
        if all((defendant, service_obj)):
            item['report'].defendant = defendant
            item['report'].service = service_obj
            item['report'].save()

            if item['report'].ticket and not item['report'].ticket.defendant:
                TicketsController.update(
                    item['report'].ticket.id,
                    {'defendant': {'customerId': customer_id}},
                    user
                )
                item['report'].ticket.service = service_obj
                item['report'].ticket.defendant = defendant
                item['report'].ticket.save()
                item['report'].ticket.reportTicket.all().update(
                    service=service_obj,
                    defendant=defendant
                )
        else:
            raise BadRequest('Please retry later')

    return {'message' 'Item successfully updated'}


def get_screenshot(item_id, report_id):
    """
        Get screenshot for item
    """
    try:
        item = ReportItem.objects.get(id=item_id, report__id=report_id)
        if item.itemType != 'URL':
            raise BadRequest('Item is not an URL')
    except (ObjectDoesNotExist, ValueError):
        raise NotFound('Item not found')

    try:
        screenshots = ImplementationFactory.instance.get_singleton_of(
            'PhishingServiceBase'
        ).get_screenshots(item.rawItem)
        schema.valid_adapter_response('PhishingServiceBase', 'get_screenshots', screenshots)
        results = {
            'rawItem': item.rawItem,
            'screenshots': screenshots,
        }
        return results
    except (PhishingServiceException, schema.InvalidFormatError, schema.SchemaNotFound):
        raise InternalServerError('Error while loading screenshots')


def get_http_headers(url):
    """
        Get HTTP headers for given url
    """
    if not url:
        raise BadRequest('Missing url')

    url = _get_deobfuscate_item(url)
    try:
        validate = URLValidator()
        validate(url)
    except ValidationError:
        raise BadRequest('Not a valid URL')

    try:
        response = ImplementationFactory.instance.get_singleton_of(
            'PhishingServiceBase'
        ).get_http_headers(url)
        schema.valid_adapter_response('PhishingServiceBase', 'get_http_headers', response)
        return response
    except (PhishingServiceException, schema.InvalidFormatError, schema.SchemaNotFound) as ex:
        raise InternalServerError(str(ex))


def _get_deobfuscate_item(item):

    item = item.strip()
    item = item.replace(' ', '')
    reg = re.compile(re.escape('hxxpx'), re.IGNORECASE)
    item = reg.sub('https', item)
    reg = re.compile(re.escape('hxxp'), re.IGNORECASE)
    item = reg.sub('http', item)
    item = item.replace('[.]', '.')
    return item


def get_whois(item):
    """
        Whois-like services based on utils/ips.py
    """
    try:
        item = {'rawItem': _get_deobfuscate_item(item)}
    except AttributeError:
        raise BadRequest('Invalid item')

    try:
        ip_addr, _, _ = _get_item_ip_hostname_url(item)
        if not ip_addr:
            raise BadRequest('Unable to get infos for this item')
    except ValidationError:
        raise BadRequest('Invalid item')

    return {'ipCategory': utils.get_ip_network(ip_addr)}


def unblock_item(item_id, report_id=None, ticket_id=None):
    """
        Unblock given `abuse.models.ReportItem`
    """
    try:
        item = ReportItem.objects.get(id=item_id)
        if report_id:
            report = Report.objects.get(id=report_id)
            if item.report.id != report.id:
                raise BadRequest('Given item not attached to given report')
        if ticket_id:
            ticket = Ticket.objects.get(id=ticket_id)
            if item.report.id not in ticket.reportTicket.all().values_list('id', flat=True):
                raise BadRequest('Given item not attached to given ticket')
    except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
        raise NotFound('Item not found')

    utils.default_queue.enqueue(
        'phishing.unblock_url',
        url=item.rawItem,
    )
    return {'message': 'Unblocking job successfully scheduled'}
