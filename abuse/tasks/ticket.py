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
    Ticket async tasks
"""

from datetime import timedelta

from django.db.models import ObjectDoesNotExist

from . import Queues, cancel_ticket_tasks
from ..models import History, Report, Ticket, User, BusinessRules
from ..rules.actions import ReportActions
from ..rules.engine import run
from ..rules.variables import ReportVariables
from ..services import EmailService


def delay_jobs(ticket=None, delay=None, back=True):
    """
        Delay pending jobs for given `abuse.models.Ticket`

        :param `abuse.models.Ticket` ticket: The Cerberus ticket
        :param int delay: Postpone duration
        :param bool back: In case of unpause, reschedule jobs
                          with effectively elapsed time
    """
    if not delay:
        raise AssertionError("Missing delay")

    if not isinstance(ticket, Ticket):
        try:
            ticket = Ticket.get(id=ticket)
        except (AttributeError, ObjectDoesNotExist, TypeError, ValueError):
            raise AssertionError("Ticket {} not found".format(ticket))

    # a job is here a tuple (Job instance, datetime instance)
    pending_jobs = Queues.scheduler.get_jobs(until=timedelta(days=7), with_times=True)

    pending_jobs = {job[0].id: job for job in pending_jobs}

    for job in ticket.jobs.all():
        if pending_jobs.get(job.asynchronousJobId):
            current_date = pending_jobs[job.asynchronousJobId][1]
            new_date = current_date - delay if back else current_date + delay
            Queues.scheduler.change_execution_time(
                pending_jobs[job.asynchronousJobId][0], new_date
            )


def create_ticket_from_phishtocheck(report=None, user=None):
    """
        Re-apply "phishing_up" rules for validated PhishToCheck report

        :param int report: The id of the `abuse.models.Report`
        :param int user: The id of the `abuse.models.User`
    """
    report = Report.get(id=report)
    user = User.objects.get(id=user)
    ticket = Ticket.search(report.defendant, report.category, report.service)

    rule_config = _get_phishtocheck_rule_config()
    variables = ReportVariables(None, report, ticket, is_trusted=True)
    actions = ReportActions(report, ticket, "EN")

    rule_applied = run(
        rule_config, defined_variables=variables, defined_actions=actions
    )

    if not rule_applied:
        raise AssertionError("Rule 'phishing_up' not applied")

    History.log_ticket_action(
        ticket=report.ticket, action="validate_phishtocheck", user=user, report=report
    )


def _get_phishtocheck_rule_config():

    rule = BusinessRules.get(name="phishing_up")
    config = rule.config

    conditions = []
    for cond in config["conditions"]["all"]:
        if cond["name"] not in ("all_items_phishing", "urls_down"):
            conditions.append(cond)

    config["conditions"]["all"] = conditions
    return config


def cancel_pending_jobs(ticket_id=None, status="answered"):
    """
        Cancel all rq scheduler jobs for given `abuse.models.Ticket`

        :param int ticket_id: The id of the `abuse.models.Ticket`
        :param str status: The `abuse.models.Ticket.TICKET_STATUS' reason
    """
    ticket = Ticket.get(id=ticket_id)

    ticket.cancel_pending_jobs(reason=status)

    cancel_ticket_tasks(ticket_id)


def close_emails_thread(ticket_id=None):
    """
        Close emails thread for given `abuse.models.Ticket`

        :param int ticket_id: The id of the `abuse.models.Ticket`
    """
    ticket = Ticket.get(id=ticket_id)

    EmailService.close_thread(ticket)
