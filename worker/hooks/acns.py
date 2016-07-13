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
    Defined AcnsWorkflow hook
"""

from django.conf import settings

from abuse.models import Proof, Resolution, Ticket

from factory.factory import ImplementationFactory
from worker.hooks.abstract import WorkflowHookBase
from worker.parsing import regexp


class AcnsWorkflowHook(WorkflowHookBase):
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
        if all((is_trusted,
                report.category.name.lower() == 'copyright',
                any([pattern in report.body for pattern in settings.GENERAL_CONFIG['copyright']['acns_patterns']]))):
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
        from worker import common, database

        ticket = database.create_ticket(
            report.defendant,
            report.category,
            report.service,
            attach_new=False
        )
        action = 'create this ticket with report %d from %s (%s ...)'
        database.log_action_on_ticket(ticket, action % (report.id, report.provider.email, report.subject[:30]))

        # Add proof
        content = regexp.ACNS_PROOF.search(report.body).group()
        Proof.objects.create(
            content=content,
            ticket=ticket,
        )

        # Send emails to provider/defendant (template, email, lang)
        templates = [
            (settings.CODENAMES['ack_received'], report.provider.email, 'EN'),
            (settings.CODENAMES['first_alert'], report.defendant.details.email, report.defendant.details.lang),
        ]
        for codename, email, lang in templates:
            common.send_email(
                ticket,
                [email],
                codename,
                lang=lang,
                acknowledged_report_id=report.id,
            )

        # Close ticket
        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').close_thread(ticket)
        resolution = Resolution.objects.get(codename=settings.CODENAMES['forward_acns'])
        ticket.resolution = resolution
        ticket.previousStatus = ticket.status
        ticket.status = 'Closed'
        ticket.update = False
        ticket.save()
        database.log_action_on_ticket(
            ticket,
            'change status from %s to %s, reason : %s' % (ticket.previousStatus, ticket.status, resolution.codename)
        )
        report.ticket = Ticket.objects.get(id=ticket.id)
        report.status = 'Archived'
        report.save()
        database.set_ticket_higher_priority(report.ticket)
        return True
