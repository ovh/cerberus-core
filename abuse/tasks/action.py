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
    Service Action tasks
"""

import logging

from datetime import datetime, timedelta

from rq import get_current_job

from . import enqueue, enqueue_in
from . import helpers
from ..logs import TaskLoggerAdapter
from ..models import History, ServiceActionJob, Resolution, Ticket, User, ServiceAction
from ..services.action import ActionServiceException, ActionService

logger = TaskLoggerAdapter(logging.getLogger("rq.worker"), dict())


# Hack for easy mocking in tests
def get_job_object():

    return get_current_job()


def apply_action(
    ticket_id=None,
    action_id=None,
    ip_addr=None,
    user_id=None,
    close_ticket=True,
    resolution_id=None,
    status="Alarm",
    bypass_status=False,
    customer_notify=True,
):
    """
        Apply given action on customer service

        :param int ticket_id: The id of the Cerberus `Ticket`
        :param int action_id: The id of the Cerberus `ServiceAction`
        :param str ip_addr: The ip address
        :param int user_id: The id of the Cerberus `User`
        :param bool close_ticket: If the ticket has to be closed after action
        :param int resolution_id: The id of the Cerberus `Resolution`
        :param str status: The new ticket status
        :param bool bypass_status: check ticket status or not
        :param bool customer_notify: send notification to customer
        :rtype: bool
        :return: if action has been applied
    """
    ticket = ticket_id
    if not isinstance(ticket_id, Ticket):
        ticket = Ticket.get(id=ticket_id)

    current_job = get_job_object()

    user = User.objects.filter(id=user_id).last()
    if not user:
        user = User.objects.get(username="abuse.robot")

    if not bypass_status and ticket.status in ("Closed", "Answered"):
        _cancel_by_status(ticket)
        ticket.set_status("ActionError", user=user)
        return False

    # Call action service
    try:
        result = ActionService.apply_action_on_service(
            ticket_id, action_id, ip_addr, user.id
        )
        _update_job(
            current_job.id,
            todo_id=result.todo_id,
            status=result.status,
            comment=result.comment,
        )
    except ActionServiceException as ex:
        _update_job(current_job.id, status="actionError", comment=str(ex))
        ticket.set_status("ActionError")
        return False

    # send service action notification to defendant
    if ticket.has_defendant_email_requests() and customer_notify:
        helpers.send_email(
            ticket,
            [ticket.defendant.details.email],
            "service_blocked",
            lang=ticket.defendant.details.lang.upper(),
        )

    if close_ticket:
        resolution = Resolution.filter(id=resolution_id).last()
        if not resolution:
            resolution = Resolution.get(codename="fixed_by_isp")
        _close_ticket(ticket, resolution.codename, user)
    else:
        ticket.set_status(status, user=user)

    ticket.action = None
    ticket.save(update_fields=["action"])

    enqueue(
        "ticket.cancel_pending_jobs", ticket_id=ticket.id, status="action execution"
    )
    return True


def _close_ticket(ticket, resolution_codename, user):

    # Send mail to providers
    emails = ticket.get_emailed_providers()

    helpers.send_email(ticket, emails, "case_closed")

    helpers.close_ticket(ticket, user=user, resolution_codename=resolution_codename)


def _cancel_by_status(ticket):
    """
        Action cancelled because of ticket status
    """
    current_job = get_job_object()
    logger.error(unicode("Ticket %d is %s, Skipping..." % (ticket.id, ticket.status)))
    ServiceActionJob.filter(asynchronousJobId=current_job.id).update(
        status="cancelled", comment="ticket is %s" % (ticket.status)
    )


def _update_job(job_id, todo_id=None, status=None, comment=None):
    """
        Update job status
    """
    ServiceActionJob.filter(asynchronousJobId=job_id).update(
        actionTodoId=todo_id,
        status=status,
        comment=comment,
        executionDate=datetime.now(),
    )


def schedule_action(
    ticket=None,
    action=None,
    seconds=5,
    ip_addr=None,
    force=False,
    snooze_duration=None,
    **kwargs
):
    """
        Schedule service action on ticket
    """
    if not isinstance(ticket, Ticket):
        ticket = Ticket.get(id=ticket)

    if not isinstance(action, ServiceAction):
        action = ServiceAction.get(id=action)

    if ip_addr:
        ticket.verify_service_action_ipaddr(ip_addr)
    else:
        ip_addr = ticket.get_service_action_ipaddr()

    params = {
        "ticket_id": ticket.id,
        "action_id": action.id,
        "ip_addr": ip_addr,
        "timeout": 3600,
    }
    params.update(**kwargs)

    if force:  # mainly used by API
        ticket.cancel_pending_jobs(reason="new action")
        _create_job(ticket, action, ip_addr, snooze_duration, seconds, params)
        return

    # first or more imminent action
    if (
        not any((ticket.snoozeStart, ticket.snoozeDuration))
        or seconds < ticket.get_action_remaining_time()
    ):
        _create_job(ticket, action, ip_addr, snooze_duration, seconds, params)


def _create_job(ticket, action, ip_addr, snooze_duration, seconds, params):

    ticket.action = action
    ticket.snoozeDuration = snooze_duration or seconds
    ticket.snoozeStart = datetime.now()
    ticket.save()

    async_job = enqueue_in(timedelta(seconds=seconds), "action.apply_action", **params)

    job = ServiceActionJob.create(
        ip=ip_addr,
        action=action,
        asynchronousJobId=async_job.id,
        creationDate=datetime.now(),
    )
    ticket.jobs.add(job)

    user = User.objects.filter(id=params.get("user_id")).last()
    delay = "now" if seconds < 3600 else "in {} hour(s)".format(seconds / 3600)
    History.log_ticket_action(
        ticket=ticket,
        user=user,
        action="set_action",
        action_name=action.name,
        action_execution_date=delay,
    )

    if seconds >= 129600:
        enqueue_in(timedelta(seconds=86400), "action.reminder", ticket_id=ticket.id)


def reminder(ticket_id=None, template="second_alert_with_action"):

    if not isinstance(ticket_id, Ticket):
        ticket = Ticket.get(id=ticket_id)

    if ticket.status != "WaitingAnswer":
        return

    lang = ticket.defendant.details.lang.upper()

    recipients = [ticket.defendant.details.email, ticket.defendant.details.spareEmail]

    helpers.send_email(ticket, recipients, template, lang=lang)
