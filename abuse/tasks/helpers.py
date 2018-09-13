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
    Common functions for tasks
"""

import re

from django.core.exceptions import ValidationError
from django.core.validators import validate_email

from ..models import History, Proof, Resolution, Ticket, User
from ..parsers import Parser
from ..services import EmailService, StorageService
from ..tasks import enqueue
from ..utils import text


def send_email(ticket, emails, template_codename, lang='EN',
               acknowledged_report_id=None, inject_proof=False):
    """
        Wrapper to send email
    """
    temp_proofs = []
    if inject_proof:
        temp_proofs = _get_temp_proofs(ticket)

    prefetched_email = _get_prefetched_email(
        ticket,
        template_codename,
        lang,
        acknowledged_report_id
    )

    for email in emails:
        try:
            _email = email.strip()
            validate_email(_email)
        except (AttributeError, ValidationError):
            continue

        EmailService.send_email(
            ticket,
            _email,
            prefetched_email.subject,
            prefetched_email.body,
            prefetched_email.category
        )
        History.log_ticket_action(
            ticket=ticket,
            action='send_email',
            email=_email
        )

    if inject_proof and temp_proofs:
        for proof in temp_proofs:
            Proof.filter(id=proof.id).delete()


def _get_prefetched_email(ticket, template_codename, lang,
                          acknowledged_report_id=None):

    return EmailService.prefetch_email_from_template(
        ticket,
        template_codename,
        lang=lang,
        acknowledged_report=acknowledged_report_id,
    )


def create_ticket(report, denied_by=None, attach_new=False):
    """
        Create a `abuse.models.Ticket`
    """
    ticket = Ticket.create_ticket(
        report.defendant,
        report.category,
        report.service,
        priority=report.provider.priority,
        attach_new=attach_new
    )

    History.log_ticket_action(
        ticket=ticket,
        action='attach_report',
        new_ticket=True,
        report=report
    )

    report.ticket = ticket
    report.status = 'Attached'
    report.save()

    ticket.set_higher_priority()

    if denied_by:
        user = User.objects.get(id=denied_by)
        History.log_ticket_action(
            ticket=ticket,
            action='deny_phishtocheck',
            user=user,
            report=report
        )

    return ticket


def close_ticket(ticket, resolution_codename=None, user=None):
    """
        Close a `abuse.models.Ticket`
    """
    resolution = Resolution.get(codename=resolution_codename)
    ticket.resolution = resolution
    ticket.save()

    ticket.set_status(
        'Closed',
        user=user,
        resolution_codename=resolution_codename
    )

    ticket.reportTicket.all().update(
        status='Archived'
    )

    if ticket.mailerId:
        EmailService.close_thread(ticket)

    enqueue(
        'ticket.cancel_pending_jobs',
        ticket_id=ticket.id,
        status='closed'
    )


def _get_temp_proofs(ticket, only_urls=False):
    """
        Get report's ticket content
    """
    temp_proofs = []
    for report in ticket.reportTicket.all():
        if only_urls:
            items = report.reportItemRelatedReport.filter(itemType='URL')
            content = '\n'.join([item.rawItem for item in items])
        else:
            content = 'From: %s\nDate: %s\nSubject: %s\n\n%s\n'
            content = content % (
                report.provider.email,
                report.receivedDate.strftime("%d/%m/%y %H:%M"),
                report.subject,
                text.dehtmlify(report.body)
            )
        # Remove potentially sensitive email addresses
        for email in re.findall(Parser.email_re, content):
            content = content.replace(email, 'email-removed@provider.com')
        temp_proofs.append(
            Proof.create(
                content=content,
                ticket=report.ticket,
            )
        )
    return temp_proofs


def save_email(filename, email):
    """
        Push email storage service

        :param str filename: The filename of the email
        :param str email: The content of the email
    """
    StorageService.write(filename, email)
