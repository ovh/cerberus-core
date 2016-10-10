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
    Action functions for worker
"""

from datetime import datetime

from django.conf import settings
from django.db.models import ObjectDoesNotExist
from rq import get_current_job

import common
import database
from abuse.models import (ServiceActionJob, ContactedProvider, Resolution, Ticket,
                          User)
from adapters.services.action.abstract import ActionServiceException
from factory.implementation import ImplementationFactory
from worker import Logger


def apply_if_no_reply(ticket_id=None, action_id=None, ip_addr=None, resolution_id=None, user_id=None, close=False):
    """
        Action if no reply from customer

        :param int ticket_id: The id of the Cerberus `Ticket`
        :param int action_id: The id of the Cerberus `ServiceAction`
        :param str ip_addr: The ip address
        :param int resolution_id: The id of the Cerberus `Resolution`
        :param int user_id: The id of the Cerberus `User`
        :param bool close: If the ticket has to be closed after action
    """
    # Checking conformance
    if not all((ticket_id, action_id, user_id)):
        Logger.error(unicode(
            'Invalid parameters [ticket_id=%s, action_id=%s, user_id=%s]' % (ticket_id, action_id, user_id)
        ))
        return

    if close and not resolution_id:
        Logger.error(unicode('Close requested but no resolution submitted'))
        return

    if resolution_id and not Resolution.objects.filter(id=resolution_id).exists():
        Logger.error(unicode('Ticket resolution %d not found, Skipping...' % (resolution_id)))
        return

    # Apply action
    applied = apply_action(ticket_id, action_id, ip_addr, user_id)
    if not applied:
        return

    # Updating ticket info
    ticket = Ticket.objects.get(id=ticket_id)
    user = User.objects.get(id=user_id)
    ticket.previousStatus = ticket.status
    ticket.snoozeDuration = None
    ticket.snoozeStart = None

    close_reason = None
    if close and resolution_id:
        __close_ticket(ticket, resolution_id)
        close_reason = ticket.resolution.codename
    else:
        ticket.status = 'Alarm'

    ticket.save()
    database.log_action_on_ticket(
        ticket=ticket,
        action='change_status',
        user=user,
        previous_value=ticket.previousStatus,
        new_value=ticket.status,
        close_reason=close_reason
    )
    Logger.info(unicode('Ticket %d processed. Next !' % (ticket_id)))


def apply_then_close(ticket_id=None, action_id=None, ip_addr=None, resolution_id=None, user_id=None):
    """
        Action on service then close

        :param int ticket_id: The id of the Cerberus `Ticket`
        :param int action_id: The id of the Cerberus `ServiceAction`
        :param str ip_addr: The ip address
        :param int resolution_id: The id of the Cerberus `Resolution`
        :param int user_id: The id of the Cerberus `User`
    """
    # Checking conformance
    if not all((ticket_id, action_id, resolution_id, user_id)):
        msg = 'Invalid parameters submitted [ticket_id=%d, action_id=%s, resolution_id=%s, user_id=%s]'
        Logger.error(unicode(msg % (ticket_id, action_id, resolution_id, user_id)))
        return

    # Apply action
    applied = apply_action(ticket_id, action_id, ip_addr, user_id)
    if not applied:
        return

    # Closing ticket and updating ticket info
    ticket = Ticket.objects.get(id=ticket_id)
    user = User.objects.get(id=user_id)
    __close_ticket(ticket, resolution_id)
    database.log_action_on_ticket(
        ticket=ticket,
        action='change_status',
        user=user,
        previous_value=ticket.previousStatus,
        new_value=ticket.status,
        close_reason=ticket.resolution.codename
    )
    ticket.resolution_id = resolution_id
    ticket.save()

    Logger.info(unicode('Ticket %d processed. Next !' % (ticket_id)))


def apply_action(ticket_id=None, action_id=None, ip_addr=None, user_id=None):
    """
        Apply given action on customer service

        :param int ticket_id: The id of the Cerberus `Ticket`
        :param int action_id: The id of the Cerberus `ServiceAction`
        :param int user_id: The id of the Cerberus `User`
        :rtype: bool
        :returns: if action has been applied
    """
    current_job = get_current_job()

    # Checking conformance
    if not all((ticket_id, action_id, user_id)):
        msg = 'Invalid parameters submitted [ticket_id=%d, action_id=%s, user_id=%s]'
        Logger.error(unicode(msg % (ticket_id, action_id, user_id)))
        return False

    # Fetching Django model object
    Logger.info(unicode('Starting process ticket %d with params [%d]' % (ticket_id, action_id)))
    try:
        ticket = Ticket.objects.get(id=ticket_id)
        user = User.objects.get(id=user_id)
    except (ObjectDoesNotExist, ValueError):
        Logger.error(unicode('Ticket %d or user %d cannot be found in DB. Skipping...' % (ticket_id, user_id)))
        return False

    if ticket.status in ['Closed', 'Answered']:
        __cancel_by_status(ticket)
        ticket.previousStatus = ticket.status
        ticket.status = 'ActionError'
        ticket.save()
        database.log_action_on_ticket(
            ticket=ticket,
            action='change_status',
            user=user,
            previous_value=ticket.previousStatus,
            new_value=ticket.status,
        )
        return False

    # Call action service
    try:
        result = ImplementationFactory.instance.get_singleton_of(
            'ActionServiceBase'
        ).apply_action_on_service(
            ticket_id,
            action_id,
            ip_addr,
            user.id
        )
        _update_job(current_job.id, todo_id=result.todo_id, status=result.status, comment=result.comment)
        return True
    except ActionServiceException as ex:
        Logger.info(unicode('Service Action not apply for ticket %d' % (ticket_id)))
        _update_job(current_job.id, status='actionError', comment=str(ex))
        ticket.previousStatus = ticket.status
        ticket.status = 'ActionError'
        ticket.save()
        database.log_action_on_ticket(
            ticket=ticket,
            action='change_status',
            user=user,
            previous_value=ticket.previousStatus,
            new_value=ticket.status,
        )
        return False


def __close_ticket(ticket, resolution_id):
    """
        Close ticket

        :param `Ticket` ticket : A Cerberus `Ticket` instance
        :param int resolution_id: The id of the Cerberus `Resolution`

    """
    # Send mail to providers and defendant
    providers_emails = ContactedProvider.objects.filter(ticket_id=ticket.id).values_list('provider__email', flat=True).distinct()
    providers_emails = list(set(providers_emails))

    common.send_email(
        ticket,
        providers_emails,
        settings.CODENAMES['case_closed']
    )

    # Close ticket
    if ticket.mailerId:
        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').close_thread(ticket)

    ticket.previousStatus = ticket.status
    ticket.status = 'Closed'
    ticket.resolution_id = resolution_id


def __cancel_by_status(ticket):
    """
        Action cancelled because of ticket status
    """
    current_job = get_current_job()
    Logger.error(unicode('Ticket %d is %s, Skipping...' % (ticket.id, ticket.status)))
    ServiceActionJob.objects.filter(
        asynchronousJobId=current_job.id
    ).update(
        status='cancelled',
        comment='ticket is %s' % (ticket.status)
    )


def _update_job(job_id, todo_id=None, status=None, comment=None):
    """
        Update job status
    """
    ServiceActionJob.objects.filter(
        asynchronousJobId=job_id
    ).update(
        actionTodoId=todo_id,
        status=status,
        comment=comment,
        executionDate=datetime.now(),
    )
