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
    Defined Customer Answer workflow
"""

from factory.factory import ImplementationFactory
from utils import utils
from worker import database
from worker.workflows.ticket.abstract import TicketAnswerWorkflowBase

ASYNC_JOB_TO_CANCEL = (
    'action.apply_if_no_reply',
    'action.apply_then_close',
    'action.apply_action',
    'ticket.timeout',
)


class CustomerAnswerWorkflow(TicketAnswerWorkflowBase):
    """
        Customer Answer workflow implementation
    """
    def identify(self, ticket, abuse_report, recipient, category):
        """
            identify if the `abuse.models.Report` match this workflow.

            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` abuse_report: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
            :return: If the workflow match
            :rtype: bool
        """
        if category == 'Defendant':
            return True
        return False

    def apply(self, ticket, abuse_report, recipient, category):
        """
            Apply specific answer workflow on given `abuse.models.Ticket`

            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param `worker.parsing.parsed.ParsedEmail` abuse_report: the email
            :param str recipient: The recipient of the answer
            :param str category: defendant, plaintiff or other
            :return: If the workflow is applied
            :rtype: bool
        """
        ticket.previousStatus = ticket.status
        ticket.status = 'Answered'
        ticket.snoozeStart = None
        ticket.snoozeDuration = None
        ticket.save()

        # Cancel pending jobs
        utils.queue.enqueue(
            'ticket.cancel_rq_scheduler_jobs',
            ticket_id=ticket.id,
            status='answered'
        )

        database.log_action_on_ticket(
            ticket=ticket,
            action='change_status',
            previous_value=ticket.previousStatus,
            new_value=ticket.status,
        )

        # Attach answer to ticket
        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').attach_external_answer(
            ticket,
            abuse_report.provider,
            recipient,
            abuse_report.subject,
            abuse_report.body,
            category
        )
        return True
