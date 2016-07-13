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
    Defined PhishingWorkflow hook
"""

from datetime import datetime, timedelta

from django.conf import settings

from abuse.models import Ticket
from utils import utils
from worker.hooks.abstract import WorkflowHookBase


class PhishingWorkflowHook(WorkflowHookBase):
    """
        Abstract class defining hook in report processing workflow
    """
    def identify(self, report, ticket, is_trusted=False):
        """
            identify if the `abuse.models.Report` match this workflow.

            :param `abuse.models.Report` report: A Cerberus report instance
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param bool is_trusted: If the report is trusted
            :return: If the workflow match
            :rtype: bool
        """
        is_there_some_urls = report.reportItemRelatedReport.filter(itemType='URL').exists()

        # Phishing specific workflow
        if report.category.name.lower() == 'phishing' and is_there_some_urls:
            return True
        return False

    def apply(self, report, ticket, is_trusted=False, no_phishtocheck=False):
        """
            Apply specific workflow on given `abuse.models.Report`

            :param `abuse.models.Report` report: A Cerberus report instance
            :param `abuse.models.Ticket` ticket: A Cerberus ticket instance
            :param bool is_trusted: If the report is trusted
            :param bool no_phishtocheckstr: if the report does not need PhishToCheck
            :return: If the workflow is applied
            :rtype: bool
        """
        from worker import database, phishing

        is_there_some_urls = report.reportItemRelatedReport.filter(itemType='URL').exists()
        all_down = phishing.check_if_all_down(report=report)

        # Archived report immediatly
        if all_down:
            phishing.close_because_all_down(report=report)
            return True

        if no_phishtocheck:
            # Just pass
            return True

        # Report has to be manually checked
        if not report.provider.apiKey:  # Means it is not a trusted phishing provider
            report.status = 'PhishToCheck'
            report.save()
            utils.push_notification({
                'type': 'new phishToCheck',
                'id': report.id,
                'message': 'New PhishToCheck report %d' % (report.id),
            })
        else:
            if not ticket and is_trusted:  # Create ticket
                ticket = database.create_ticket(report.defendant, report.category, report.service, priority=report.provider.priority)
                action = 'create this ticket with report %d from %s (%s ...)'
                database.log_action_on_ticket(ticket, action % (report.id, report.provider.email, report.subject[:30]))
                utils.scheduler.enqueue_in(
                    timedelta(seconds=settings.GENERAL_CONFIG['phishing']['wait']),
                    'ticket.timeout',
                    ticket_id=ticket.id
                )
                ticket_snooze = settings.GENERAL_CONFIG['phishing']['wait']
                ticket.previousStatus = ticket.status
                ticket.status = 'WaitingAnswer'
                ticket.snoozeDuration = ticket_snooze
                ticket.snoozeStart = datetime.now()
                ticket.save()

            if is_there_some_urls:  # Block urls
                phishing.block_url_and_mail(ticket_id=ticket.id, report_id=report.id)

        if ticket:
            report.ticket = Ticket.objects.get(id=ticket.id)
            report.status = 'Attached'
            report.save()
            database.set_ticket_higher_priority(report.ticket)

        return True
