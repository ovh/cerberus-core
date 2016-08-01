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
    Common functions for worker
"""

from django.core.exceptions import ValidationError
from django.core.validators import validate_email

import database
from abuse.models import Proof, Resolution, User
from factory.factory import ImplementationFactory
from utils import utils


def send_email(ticket, emails, template_codename, lang='EN', acknowledged_report_id=None):
    """
        Wrapper to send email
    """
    prefetched_email = ImplementationFactory.instance.get_singleton_of('MailerServiceBase').prefetch_email_from_template(
        ticket,
        template_codename,
        lang=lang,
        acknowledged_report=acknowledged_report_id,
    )

    for email in emails:
        try:
            validate_email(email)
        except ValidationError:
            continue

        ImplementationFactory.instance.get_singleton_of('MailerServiceBase').send_email(
            ticket,
            email,
            prefetched_email.subject,
            prefetched_email.body
        )
        database.log_action_on_ticket(
            ticket=ticket,
            action='send_email',
            email=email
        )


def create_ticket(report, denied_by=None, attach_new=False):
    """
        Create a `abuse.models.Ticket`
    """
    ticket = database.create_ticket(report.defendant, report.category, report.service, priority=report.provider.priority, attach_new=attach_new)
    database.log_action_on_ticket(
        ticket=ticket,
        action='attach_report',
        new_ticket=True,
        report=report
    )

    if denied_by:
        user = User.objects.get(id=denied_by)
        database.log_action_on_ticket(
            ticket=ticket,
            action='deny_phishtocheck',
            user=user,
            report=report
        )

    return ticket


def close_ticket(report, resolution_codename=None, user=None):
    """
        Close a `abuse.models.Ticket`
    """
    resolution = Resolution.objects.get(codename=resolution_codename)
    report.ticket.resolution = resolution
    report.ticket.previousStatus = report.ticket.status
    report.ticket.status = 'Closed'
    report.status = 'Archived'

    database.log_action_on_ticket(
        ticket=report.ticket,
        action='change_status',
        user=user,
        previous_value=report.ticket.previousStatus,
        new_value=report.ticket.status,
        close_reason=report.ticket.resolution.codename
    )

    report.ticket.save()
    report.save()


def get_temp_proofs(ticket):
    """
        Get report's ticket content
    """
    temp_proofs = []
    for report in ticket.reportTicket.all():
        content = 'From: %s\nDate: %s\nSubject: %s\n\n%s\n'
        temp_proofs.append(
            Proof.objects.create(
                content=content % (
                    report.provider.email,
                    report.receivedDate.strftime("%d/%m/%y %H:%M"),
                    report.subject,
                    utils.dehtmlify(report.body)
                ),
                ticket=report.ticket,
            )
        )
    return temp_proofs
