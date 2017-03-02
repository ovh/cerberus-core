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
    Service Action functions for worker
"""

from datetime import datetime

from django.conf import settings
from rq import get_current_job

import common
from abuse.models import (ServiceActionJob, ContactedProvider, Resolution, Ticket,
                          User)
from adapters.services.action.abstract import ActionServiceException
from factory.implementation import ImplementationFactory as implementations
from worker import Logger


def apply_if_no_reply(ticket_id=None, action_id=None, ip_addr=None,
                      resolution_id=None, user_id=None, close=False):
    """
        Action if no reply from customer

        :param int ticket_id: The id of the Cerberus `Ticket`
        :param int action_id: The id of the Cerberus `ServiceAction`
        :param str ip_addr: The ip address
        :param int resolution_id: The id of the Cerberus `Resolution`
        :param int user_id: The id of the Cerberus `User`
        :param bool close: If the ticket has to be closed after action
    """
    ticket = Ticket.objects.get(id=ticket_id)
    user = User.objects.get(id=user_id)

    resolution = None
    if close and resolution_id:
        resolution = Resolution.objects.get(id=resolution_id)

    # Apply action
    applied = apply_action(ticket_id, action_id, ip_addr, user_id)
    if not applied:
        return

    if close and resolution_id:
        _close_ticket(ticket, resolution.codename, user)
    else:
        common.set_ticket_status(
            ticket,
            'Alarm',
            user=user,
            reset_snooze=True
        )


def apply_then_close(ticket_id=None, action_id=None, ip_addr=None,
                     resolution_id=None, user_id=None):
    """
        Action on service then close

        :param int ticket_id: The id of the Cerberus `Ticket`
        :param int action_id: The id of the Cerberus `ServiceAction`
        :param str ip_addr: The ip address
        :param int resolution_id: The id of the Cerberus `Resolution`
        :param int user_id: The id of the Cerberus `User`
    """
    ticket = Ticket.objects.get(id=ticket_id)
    resolution = Resolution.objects.get(id=resolution_id)
    user = User.objects.get(id=user_id)

    # Apply action
    applied = apply_action(ticket_id, action_id, ip_addr, user_id)
    if not applied:
        return

    # Closing ticket
    _close_ticket(ticket, resolution.codename, user)


def apply_action(ticket_id=None, action_id=None, ip_addr=None, user_id=None):
    """
        Apply given action on customer service

        :param int ticket_id: The id of the Cerberus `Ticket`
        :param int action_id: The id of the Cerberus `ServiceAction`
        :param int user_id: The id of the Cerberus `User`
        :rtype: bool
        :return: if action has been applied
    """
    current_job = get_current_job()

    ticket = Ticket.objects.get(id=ticket_id)
    user = User.objects.get(id=user_id)

    if ticket.status in ('Closed', 'Answered'):
        _cancel_by_status(ticket)
        common.set_ticket_status(
            ticket,
            'ActionError',
            user=user
        )
        return False

    # Call action service
    try:
        result = implementations.instance.get_singleton_of(
            'ActionServiceBase'
        ).apply_action_on_service(
            ticket_id,
            action_id,
            ip_addr,
            user.id
        )
        _update_job(
            current_job.id,
            todo_id=result.todo_id,
            status=result.status,
            comment=result.comment
        )
        return True
    except ActionServiceException as ex:
        _update_job(current_job.id, status='actionError', comment=str(ex))
        common.set_ticket_status(
            ticket,
            'ActionError',
            user=user
        )
        return False


def _close_ticket(ticket, resolution_codename, user):

    # Send mail to providers and defendant
    providers_emails = ContactedProvider.objects.filter(
        ticket_id=ticket.id
    ).values_list(
        'provider__email',
        flat=True
    ).distinct()
    providers_emails = list(set(providers_emails))

    common.send_email(
        ticket,
        providers_emails,
        settings.CODENAMES['case_closed']
    )
    common.close_ticket(
        ticket,
        user=user,
        resolution_codename=resolution_codename
    )


def _cancel_by_status(ticket):
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
