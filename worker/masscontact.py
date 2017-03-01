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
    MassContact functions for worker
"""

import hashlib
import inspect

from collections import Counter
from datetime import datetime
from time import sleep

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.validators import validate_ipv46_address
from django.db import transaction
from django.db.models import ObjectDoesNotExist
from django.template import Context, loader

import common
import database

from abuse.models import (Category, MassContactResult, Report,
                          ReportItem, Resolution, Tag, User)
from adapters.dao.customer.abstract import CustomerDaoException
from factory.implementation import ImplementationFactory as implementations
from utils import pglocks, schema, utils
from worker import Logger


# XXX: rewrite, use workflows engine
def mass_contact(ip_address=None, category=None, campaign_name=None,
                 email_subject=None, email_body=None, user_id=None):
    """
        Try to identify customer based on `ip_address`, creates Cerberus ticket
        then send email to customer and finally close ticket.

        The use case is: a trusted provider sent you
        a list of vulnerable DNS servers (DrDOS amp) for example.

        To prevent abuse on your network, you notify customer of this vulnerability.

        :param str ip_address: The IP address
        :param str category: The category of the abuse
        :param str campaign_name: The name if the "mass-conctact" campaign
        :param str email_subject: The subject of the email to send to defendant
        :param str email_body: The body of the email to send to defendant
        :param int user_id: The id of the Cerberus `abuse.models.User` who created the campaign
    """
    # Check params
    _, _, _, values = inspect.getargvalues(inspect.currentframe())
    if not all(values.values()):
        Logger.error(unicode('invalid parameters submitted %s' % str(values)))
        return

    try:
        validate_ipv46_address(ip_address)
    except (TypeError, ValidationError):
        Logger.error(unicode('invalid ip addresses submitted'))
        return

    # Get Django model objects
    try:
        category = Category.objects.get(name=category)
        user = User.objects.get(id=user_id)
    except (AttributeError, ObjectDoesNotExist, TypeError):
        Logger.error(unicode('invalid user or category'))
        return

    # Identify service for ip_address
    try:
        services = implementations.instance.get_singleton_of(
            'CustomerDaoBase'
        ).get_services_from_items(ips=[ip_address])
        schema.valid_adapter_response('CustomerDaoBase', 'get_services_from_items', services)
    except CustomerDaoException as ex:
        Logger.error(unicode(
            'Exception while identifying defendants for ip %s -> %s ' % (ip_address, str(ex))
        ))
        raise CustomerDaoException(ex)

    # Create report/ticket
    if services:
        Logger.debug(unicode('creating report/ticket for ip address %s' % (ip_address)))
        with pglocks.advisory_lock('cerberus_lock'):
            _create_contact_tickets(
                services,
                campaign_name,
                ip_address,
                category,
                email_subject,
                email_body,
                user
            )
        return True
    else:
        Logger.debug(unicode('no service found for ip address %s' % (ip_address)))
        return False


# XXX: rewrite
@transaction.atomic
def _create_contact_tickets(services, campaign_name, ip_address, category,
                            email_subject, email_body, user):

    # Create fake report
    report_subject = 'Campaign %s for ip %s' % (campaign_name, ip_address)
    report_body = 'Campaign: %s\nIP Address: %s\n' % (campaign_name, ip_address)
    filename = hashlib.sha256(report_body.encode('utf-8')).hexdigest()
    _save_email(filename, report_body)

    for data in services:  # For identified (service, defendant, items) tuple

        actions = []

        # Create report
        report = Report.objects.create(**{
            'provider': database.get_or_create_provider('mass_contact'),
            'receivedDate': datetime.now(),
            'subject': report_subject,
            'body': report_body,
            'category': category,
            'filename': filename,
            'status': 'Archived',
            'defendant': database.get_or_create_defendant(data['defendant']),
            'service': database.get_or_create_service(data['service']),
        })
        database.log_new_report(report)

        # Create item
        item_dict = {'itemType': 'IP', 'report_id': report.id, 'rawItem': ip_address}
        item_dict.update(utils.get_reverses_for_item(ip_address, nature='IP'))
        ReportItem.objects.create(**item_dict)

        # Create ticket
        ticket = database.create_ticket(
            report.defendant,
            report.category,
            report.service,
            priority=report.provider.priority,
            attach_new=False,
        )
        database.add_mass_contact_tag(ticket, campaign_name)
        actions.append({'ticket': ticket, 'action': 'create_masscontact', 'campaign_name': campaign_name})
        actions.append({'ticket': ticket, 'action': 'change_treatedby', 'new_value': user.username})
        report.ticket = ticket
        report.save()
        Logger.debug(unicode(
            'ticket %d successfully created for (%s, %s)' % (ticket.id, report.defendant.customerId, report.service.name)
        ))

        # Send email to defendant
        _send_mass_contact_email(ticket, email_subject, email_body)
        actions.append({'ticket': ticket, 'action': 'send_email', 'email': report.defendant.details.email})

        # Close ticket/report
        ticket.resolution = Resolution.objects.get(codename=settings.CODENAMES['fixed_customer'])
        ticket.previousStatus = ticket.status
        ticket.status = 'Closed'
        ticket.save()
        actions.append({
            'ticket': ticket,
            'action': 'change_status',
            'previous_value': ticket.previousStatus,
            'new_value': ticket.status,
            'close_reason': ticket.resolution.codename
        })

        for action in actions:
            database.log_action_on_ticket(**action)


def _send_mass_contact_email(ticket, email_subject, email_body):

    template = loader.get_template_from_string(email_subject)
    context = Context({
        'publicId': ticket.publicId,
        'service': ticket.service.name.replace('.', '[.]'),
        'lang': ticket.defendant.details.lang,
    })
    subject = template.render(context)

    template = loader.get_template_from_string(email_body)
    context = Context({
        'publicId': ticket.publicId,
        'service': ticket.service.name.replace('.', '[.]'),
        'lang': ticket.defendant.details.lang,
    })
    body = template.render(context)

    implementations.instance.get_singleton_of('MailerServiceBase').send_email(
        ticket,
        ticket.defendant.details.email,
        subject,
        body,
        'MassContact',
    )


def check_mass_contact_result(result_campaign_id=None, jobs=None):
    """
        Check "mass-contact" campaign jobs's result

        :param int result_campaign_id: The id of the `abuse.models.MassContactResult`
        :param list jobs: The list of associated Python-Rq jobs id
    """
    # Check params
    _, _, _, values = inspect.getargvalues(inspect.currentframe())
    if not all(values.values()) or not isinstance(jobs, list):
        Logger.error(unicode('invalid parameters submitted %s' % str(values)))
        return

    if not isinstance(result_campaign_id, MassContactResult):
        try:
            campaign_result = MassContactResult.objects.get(id=result_campaign_id)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            Logger.error(unicode('MassContactResult {} cannot be found in DB. Skipping...'.format(
                result_campaign_id
            )))
            return

    result = []
    for job_id in jobs:
        job = utils.default_queue.fetch_job(job_id)
        if not job:
            continue
        while job.status.lower() == 'queued':
            sleep(0.5)
        result.append(job.result)

    count = Counter(result)
    campaign_result.state = 'Done'
    campaign_result.matchingCount = count[True]
    campaign_result.notMatchingCount = count[False]
    campaign_result.failedCount = count[None]
    campaign_result.save()
    Logger.info(unicode('MassContact campaign %d finished' % (campaign_result.campaign.id)))


def _save_email(filename, email):
    """
        Push email storage service

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    with implementations.instance.get_instance_of('StorageServiceBase', common.STORAGE_DIR) as cnx:
        cnx.write(filename, email.encode('utf-8'))
        Logger.info(unicode('Email %s pushed to Storage Service' % (filename)))


def _add_mass_contact_tag(ticket, campaign_name):
    """
        Add mass contact tag to report
    """
    try:
        tag, _ = Tag.objects.get_or_create(tagType='Ticket', name=campaign_name)
        ticket.tags.add(tag)
        ticket.save()
    except ObjectDoesNotExist:
        pass
