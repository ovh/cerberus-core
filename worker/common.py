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

import re

from django.core.exceptions import ValidationError
from django.core.validators import validate_email

import database
from abuse.models import Proof, Resolution, User
from django.conf import settings
from parsing import regexp
from factory.implementation import ImplementationFactory as implementations
from utils import utils

BOT_USER = User.objects.get(username=settings.GENERAL_CONFIG['bot_user'])
CDN_REQUEST_CACHE_EXPIRATION_DAYS = 15
CDN_REQUEST_REDIS_QUEUE = 'cdnrequest:%s:request'
CDN_REQUEST_LOCK = 'cdnrequest:lock'
STORAGE_DIR = settings.GENERAL_CONFIG['email_storage_dir']


def send_email(ticket, emails, template_codename, lang='EN', acknowledged_report_id=None):
    """
        Wrapper to send email
    """
    prefetched_email = implementations.instance.get_singleton_of(
        'MailerServiceBase'
    ).prefetch_email_from_template(
        ticket,
        template_codename,
        lang=lang,
        acknowledged_report=acknowledged_report_id,
    )

    for email in emails:
        _email = email.strip()
        try:
            validate_email(_email)
        except ValidationError:
            continue

        implementations.instance.get_singleton_of('MailerServiceBase').send_email(
            ticket,
            _email,
            prefetched_email.subject,
            prefetched_email.body,
            prefetched_email.category
        )
        database.log_action_on_ticket(
            ticket=ticket,
            action='send_email',
            email=_email
        )


def create_ticket(report, denied_by=None, attach_new=False):
    """
        Create a `abuse.models.Ticket`
    """
    ticket = database.create_ticket(
        report.defendant,
        report.category,
        report.service,
        priority=report.provider.priority,
        attach_new=attach_new
    )
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


def close_ticket(ticket, resolution_codename=None, user=None):
    """
        Close a `abuse.models.Ticket`
    """
    resolution = Resolution.objects.get(codename=resolution_codename)
    ticket.resolution = resolution
    ticket.previousStatus = ticket.status

    set_ticket_status(
        ticket,
        'Closed',
        reset_snooze=True,
        user=user,
        resolution_codename=resolution_codename
    )

    ticket.reportTicket.all().update(
        status='Archived'
    )

    if ticket.mailerId:
        implementations.instance.get_singleton_of('MailerServiceBase').close_thread(ticket)

    ticket.save()


def get_temp_proofs(ticket, only_urls=False):
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
                utils.dehtmlify(report.body)
            )
        for email in re.findall(regexp.EMAIL, content):  # Remove potentially sensitive emails
            content = content.replace(email, 'email-removed@provider.com')
        temp_proofs.append(
            Proof.objects.create(
                content=content,
                ticket=report.ticket,
            )
        )
    return temp_proofs


def set_ticket_status(ticket, status, resolution_codename=None,
                      reset_snooze=False, user=None):
    """
        Update `abuse.models.Ticket` and log action
    """
    ticket.previousStatus = ticket.status
    ticket.status = status

    if reset_snooze:
        ticket.snoozeStart = None
        ticket.snoozeDuration = None

    ticket.save()

    database.log_action_on_ticket(
        ticket=ticket,
        action='change_status',
        user=user,
        previous_value=ticket.previousStatus,
        new_value=ticket.status,
        close_reason=resolution_codename
    )
